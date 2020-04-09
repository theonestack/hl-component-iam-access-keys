# iam-access-keys CfHighlander component

This component creates a IAM users with a AWS SecretsManager secret to hold static IAM Access Keys. The secrets have a rotation schedule defaulting to 7 days.

## Requirements

## Parameters

| Name | Use | Default | Global | Type | Allowed Values |
| ---- | --- | ------- | ------ | ---- | -------------- |
| EnvironmentName | Tagging | dev | true | string
| EnvironmentType | Tagging | development | true | string | ['development','production']

## Configuration

### Users

List of users

```yaml
users:
  # IAM User Name (required)
  - name: test-user
  # IAM Policy to apply to the user (optional)
    policy:
      assume-role:
        action: sts:AssumeRole
        resource:
          - arn:aws:iam:012345678912::role/mfa
          - arn:aws:iam:987654321098::role/mfa
    # rotation schedule in days (optional, defaults to 7 days)
    rotate: 30
```

## Outputs/Exports

| Name | Value | Exported |
| ---- | ----- | -------- |
