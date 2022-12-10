import unittest
import os, sys

test_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(test_dir + "/../src")
sys.path.append(test_dir + "/../test")
# before reporter, env variables need to be set
import tests.lambda_env_template
import src.security_hub_reporter as reporter


def create_one_unique_finding():
    return [{'SchemaVersion': '2018-10-08', 'Id': 'arn:aws:securityhub:eu-west-1:account-number:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.8/finding/e7969016-e854-410b-8330-8b8cfd8a5c68', 'ProductArn': 'arn:aws:securityhub:eu-west-1::product/aws/securityhub', 'ProductName': 'Security Hub', 'CompanyName': 'AWS', 'Region': 'eu-west-1', 'GeneratorId': 'aws-foundational-security-best-practices/v/1.0.0/S3.8', 'AwsAccountId': 'account-number', 'Types': ['Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices'], 'FirstObservedAt': '2022-06-28T10:36:00.661Z', 'LastObservedAt': '2022-06-28T10:36:04.197Z', 'CreatedAt': '2022-06-28T10:36:00.661Z', 'UpdatedAt': '2022-06-28T10:36:00.661Z', 'Severity': {'Product': 70, 'Label': 'HIGH', 'Normalized': 70, 'Original': 'HIGH'}, 'Title': 'S3.8 S3 Block Public Access setting should be enabled at the bucket-level', 'Description': 'This control checks if Amazon S3 buckets have bucket level public access blocks applied. This control fails if any of the bucket level settings are set to "false" public: ignorePublicAcls, blockPublicPolicy, blockPublicAcls, restrictPublicBuckets.', 'Remediation': {'Recommendation': {'Text': 'For directions on how to fix this issue, consult the AWS Security Hub Foundational Security Best Practices documentation.', 'Url': 'https://docs.aws.amazon.com/console/securityhub/S3.8/remediation'}}, 'ProductFields': {'StandardsArn': 'arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0', 'StandardsSubscriptionArn': 'arn:aws:securityhub:eu-west-1:account-number:subscription/aws-foundational-security-best-practices/v/1.0.0', 'ControlId': 'S3.8', 'RecommendationUrl': 'https://docs.aws.amazon.com/console/securityhub/S3.8/remediation', 'RelatedAWSResources:0/name': 'securityhub-s3-bucket-level-public-access-prohibited-7bed22bb', 'RelatedAWSResources:0/type': 'AWS::Config::ConfigRule', 'StandardsControlArn': 'arn:aws:securityhub:eu-west-1:account-number:control/aws-foundational-security-best-practices/v/1.0.0/S3.8', 'aws/securityhub/ProductName': 'Security Hub', 'aws/securityhub/CompanyName': 'AWS', 'aws/securityhub/annotation': 'PublicAccessBlockConfiguration block is missing', 'Resources:0/Id': 'arn:aws:s3:::just-for-tests-python-unit', 'aws/securityhub/FindingId': 'arn:aws:securityhub:eu-west-1::product/aws/securityhub/arn:aws:securityhub:eu-west-1:account-number:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.8/finding/e7969016-e854-410b-8330-8b8cfd8a5c68'}, 'Resources': [{'Type': 'AwsS3Bucket', 'Id': 'arn:aws:s3:::just-for-tests-python-unit', 'Partition': 'aws', 'Region': 'eu-west-1', 'Details': {'AwsS3Bucket': {'OwnerId': 'ownerId', 'CreatedAt': '2022-06-28T10:33:29.000Z'}}}], 'Compliance': {'Status': 'FAILED'}, 'WorkflowState': 'NEW', 'Workflow': {'Status': 'NEW'}, 'RecordState': 'ACTIVE', 'FindingProviderFields': {'Severity': {'Label': 'HIGH', 'Original': 'HIGH'}, 'Types': ['Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices']}}]


class SecurityHubReporterTest(unittest.TestCase):

    def test_group_findings_by_control_id(self):
        findings = create_one_unique_finding()
        by_ctrl_id = reporter.group_findings_by_control_id(findings, os.environ["SECURITY_CONTROLS"])
        self.assertEqual(len(by_ctrl_id.keys()), len(findings), 'Incorrect number of keys')

    def test_build_metric_data(self):
        findings = create_one_unique_finding()
        by_ctrl_id = reporter.group_findings_by_control_id(findings, os.environ["SECURITY_CONTROLS"])
        metric_data = reporter.build_metric_data(by_ctrl_id, os.environ["SECURITY_CONTROLS"])['metric_data']
        metrics = list(filter(lambda data: {'Name': 'ControlId', 'Value': 'S3.8'} in data['Dimensions'], metric_data))
        self.assertEqual(len(metrics), 1, 'Incorrect count of metrics')
        self.assertEqual(metrics[0]['Value'], 1, "Incorrect value for the S3.8 metric finding")

    def test_build_findings_report(self):
        findings = create_one_unique_finding()
        by_ctrl_id = reporter.group_findings_by_control_id(findings, os.environ["SECURITY_CONTROLS"])
        report, findings_count = reporter.build_findings_report(by_ctrl_id, os.environ.get('ACCOUNT_ALIAS'),
                                                                 os.environ.get('ACCOUNT_ID'))
        self.assertEqual(findings_count, 1, 'Incorrect number of findings in report')
        self.assertRegex(report, r'.*S3.8.*', 'S3.8 finding not in report')


if __name__ == '__main__':
    unittest.main()