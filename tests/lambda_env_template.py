import os

control_id_default = "S3.2, S3.3, S3.8, EC2.1, EC2.18, EC2.9, EC2.3, EC2.7, RDS.1, RDS.2, RDS.4, RDS.3, DMS.1, IAM.1, IAM.8, Lambda.1"
os.environ["SECURITY_CONTROLS"] = control_id_default
os.environ["ACCOUNT_ALIAS"] = "unit-test-account"
os.environ["ACCOUNT_ID"] = "unit-test-account-number"
os.environ["METRICS_NAMESPACE"] = "unit-test"
os.environ["PUBLISH_OK_MESSAGE_TO_SLACK"] = "False"
os.environ["SNS_TOPIC_ARN"] = "unit-test-topic-arn"
os.environ["PS_ROOT_PATH"] = "unit-test-ps-path"
os.environ["PS_KEY_CONTROLS_IDS_API_HOST"] = "unit-test-api-host"
os.environ["PS_KEY_CONTROLS_IDS_API_KEY"] = "unit-test-ps-api-key"
os.environ["PS_KEY_CONTROLS_IDS_API_RESOURCE_PATH"] = "unit-test-ps-resource-path"