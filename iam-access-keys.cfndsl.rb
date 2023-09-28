CloudFormation do
  
  iam_policies = external_parameters.fetch(:iam_policies, [])
  IAM_Role(:LambdaRoleKeyRotator) {
    AssumeRolePolicyDocument service_assume_role_policy('lambda')
    Policies iam_role_policies(iam_policies)
  }

  base_tags = []
  base_tags.push({ Key: 'EnvironmentName', Value: Ref(:EnvironmentName) })
  base_tags.push({ Key: 'EnvironmentType', Value: Ref(:EnvironmentType) })
  
  users = external_parameters.fetch(:users, [])
  
  users.each do |user|
    
    resource_name = user['name'].capitalize.gsub(/[^a-zA-Z0-9]/, '')
    rotation = user.has_key?('rotation') ? user['rotation'] : 7
    
    user_tags = base_tags.clone()
    user_tags.push({ Key: 'Name', Value: "automated-key-rotation-user-#{user['name']}" })
    user_tags.push({ Key: 'RotationScheduleInDays', Value: rotation.to_s })
    
    IAM_User("#{resource_name}User") {
      UserName user['name']
      Path FnSub '/${EnvironmentName}/keyrotator/'
      
      if user.has_key?('policy')
        Policies iam_role_policies(user['policy'])
      end
      
      Tags user_tags
    }
    
    secret_tags = base_tags.clone()  
    secret_json = {
      User: Ref("#{resource_name}User")
    }
    
    SecretsManager_Secret("#{resource_name}Secret") {
      Name FnSub("/${EnvironmentName}/iamuser/keyrotated/#{user['name']}")
      Description "IAM user access key for #{user['name']}"
      SecretString secret_json.to_json
      Tags secret_tags
    }
    
    SecretsManager_RotationSchedule("#{resource_name}SecretRotationSchedule") {
      SecretId Ref("#{resource_name}Secret")
      RotationLambdaARN FnGetAtt(:CiinaboxKeyRotator, :Arn)
      RotationRules({
        AutomaticallyAfterDays: rotation.to_i
      })
    }
    
  end

end
