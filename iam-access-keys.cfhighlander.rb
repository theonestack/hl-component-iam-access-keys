CfhighlanderTemplate do
  Name 'iam-access-keys'
  Description "iam-access-keys - #{component_version}"
  
  DependsOn 'lib-iam@0.1.0'
  
  Parameters do
    ComponentParam 'EnvironmentName', 'dev', isGlobal: true
    ComponentParam 'EnvironmentType', 'development', allowedValues: ['development','production'], isGlobal: true
  end

  LambdaFunctions 'key_rotator'
  
end
