import boto3
import logging
import os
import json

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Secrets Manager Rotation Template
    Rotates a IAM access key in a secretsmanager secret
    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)
        context (LambdaContext): The Lambda runtime information
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not properly configured for rotation
        KeyError: If the event parameters do not contain the expected keys
    """
    
    logger.info(f"event: {event}")
    
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the client
    service_client = boto3.client('secretsmanager')

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error(f"Secret {arn} is not enabled for rotation")
        raise ValueError(f"Secret {arn} is not enabled for rotation")
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error(f"Secret version {token} has no stage for rotation of secret {arn}.")
        raise ValueError(f"Secret version {token} has no stage for rotation of secret {arn}.")
    if "AWSCURRENT" in versions[token]:
        logger.info(f"Secret version {token} already set as AWSCURRENT for secret {arn}.")
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error(f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}.")
        raise ValueError(f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}.")

    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")

def create_secret(service_client, arn, token):
    """Create the secret
    Calls IAM to create a new access key and updates the secret wit the new secret key in a pending state.
    Adds the access key to the pending key tag on the secret.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    secret_dict = get_secret_dict(service_client, arn, token, "AWSCURRENT", required_fields=['User'])
    
    iam_client = boto3.client('iam')
    username = secret_dict['User']
    
    # we need to check if there are 2 keys, if so we need to delete one before we can create the new key due to the resource limit.
    existing_access_keys = sorted(iam_client.list_access_keys(UserName=username)['AccessKeyMetadata'], key=lambda x: x['CreateDate'])
    if len(existing_access_keys) >= 2:
        logger.info("at least 2 access keys already exist. deleting the oldest version: %s" % existing_access_keys[0]['AccessKeyId'])
        iam_client.delete_access_key(UserName=username, AccessKeyId=existing_access_keys[0]['AccessKeyId'])
    
    # make a copy of the secret_dict to update the secret
    new_secret_dict = secret_dict.copy()
    # create the new key
    new_key = iam_client.create_access_key(UserName=username)
    new_secret_dict['AccessKeyId'] = new_key['AccessKey']['AccessKeyId']
    new_secret_dict['SecretAccessKey'] = new_key['AccessKey']['SecretAccessKey']
    
    # Update the secret key id in the secret and set it to a pending state
    service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(new_secret_dict), VersionStages=['AWSPENDING'])

def set_secret(service_client, arn, token):
    """Set the secret
    The IAM service sets the secret in the user so there is nothing to do here
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    logging.info("Nothing to do here")


def test_secret(service_client, arn, token):
    """Test the secret
    Tests the new IAM access key
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    
    secret_dict = get_secret_dict(service_client, arn, token, "AWSPENDING", required_fields=['User','AccessKeyId','SecretAccessKey'])
    test_client = boto3.client('iam', aws_access_key_id=secret_dict['AccessKeyId'], aws_secret_access_key=secret_dict['SecretAccessKey'])
    
    try:
        test_client.get_account_authorization_details()
    except test_client.exceptions.ClientError as e:
        # the test fails if and only if Authentication fails. Authorization failures are acceptable.
        if e.response['Error']['Code'] == 'AuthFailure':
            raise ValueError(f"Pending IAM secret {arn} in rotation {secret_dict['User']} failed the test to authenticate. exception: {e}")

def finish_secret(service_client, arn, token):
    """Finish the secret
    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.
    Tags the secret with the new access key and removes the pending key tag.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    # First describe the secret to get the current version
    secret = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in secret["VersionIdsToStages"]:
        if "AWSCURRENT" in secret["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info(f"finishSecret: Version {version} already marked as AWSCURRENT for {arn}")
                return
            current_version = version
            break
    
    # get the user and the current access key so we can clean up the old one
    try:
        secret_dict = get_secret_dict(service_client, arn, token, "AWSCURRENT", required_fields=['User','AccessKeyId'])
    except:
        # If we do not yet have any AccessKey for the newly created USER.
        secret_dict = get_secret_dict(service_client, arn, token, "AWSCURRENT", required_fields=['User'])
    
    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)

    try:
        logger.info(f"Cleanup the AccessKeyId: {secret_dict['AccessKeyId']}.")
    except:
        logger.info("There are no any AccessKey yet.")

    try:
        logger.info("Cleanup the old access key now....")
        iam_client.delete_access_key(UserName=secret_dict['User'], AccessKeyId=secret_dict['AccessKeyId'])
    except:
        pass

    logger.info(f"finishSecret: Successfully set AWSCURRENT stage to version {token} for secret {arn}.")
    
def get_secret_dict(service_client, arn, token, stage, required_fields=[]):
    """
    Gets the secret dictionary corresponding for the secret arn, stage, and token
    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string
    Args:
        secretsmanager_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired
        stage (string): The stage identifying the secret version
    Returns:
        SecretDictionary: Secret dictionary
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not valid JSON
        KeyError: If the secret json does not contain the expected keys
    """

    try:
        secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    except:
        # If we do not yet have any AccessKey for the newly created USER.
        secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)

    plaintext = secret['SecretString']
    secret_dict = json.loads(plaintext)
    # Run validations against the secret
    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)
    # Parse and return the secret JSON string
    return secret_dict
