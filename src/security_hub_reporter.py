import boto3, os, json, logging
from control_ids_resolver import ControlIdsResolver


sns = boto3.client('sns')
securityhub = boto3.client('securityhub')
cloudwatch = boto3.client('cloudwatch')

GENERATOR_ID = 'aws-foundational-security-best-practices/v/1.0.0'
SECURITY_CONTROLS = os.environ.get('SECURITY_CONTROLS')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ACCOUNT_ID = os.environ.get('ACCOUNT_ID')
ACCOUNT_ALIAS = os.environ.get('ACCOUNT_ALIAS')
METRICS_NAMESPACE = os.environ.get('METRICS_NAMESPACE')
PUBLISH_OK_MESSAGE_TO_SLACK = os.environ.get('PUBLISH_OK_MESSAGE_TO_SLACK')
""" variables below are used to connect to the backend service providing set of control-ids to be reported. """
PS_ROOT_PATH = os.environ.get('PS_ROOT_PATH')
PS_KEY_CONTROLS_IDS_API_HOST = os.environ.get('PS_KEY_CONTROLS_IDS_API_HOST')
PS_KEY_CONTROLS_IDS_API_KEY = os.environ.get('PS_KEY_CONTROLS_IDS_API_KEY')
PS_KEY_CONTROLS_IDS_API_RESOURCE_PATH = os.environ.get('PS_KEY_CONTROLS_IDS_API_RESOURCE_PATH')


control_ids_resolver = ControlIdsResolver(SECURITY_CONTROLS, PS_ROOT_PATH, PS_KEY_CONTROLS_IDS_API_HOST, PS_KEY_CONTROLS_IDS_API_KEY, PS_KEY_CONTROLS_IDS_API_RESOURCE_PATH)

def lambda_handler(event, context):
    findings = get_findings()
    findings_by_control_id = group_findings_by_control_id(findings, control_ids_resolver.get_security_controls())
    report, findings_count = build_findings_report(findings_by_control_id, ACCOUNT_ALIAS, ACCOUNT_ID)

    if SNS_TOPIC_ARN != 'DUMMY' and (findings_count > 0 or (findings_count == 0 and PUBLISH_OK_MESSAGE_TO_SLACK == 'true')):
        send_report_to_sns(SNS_TOPIC_ARN, report)

    metric_data = build_metric_data(findings_by_control_id)
    try:
        cloudwatch.put_metric_data(
            Namespace=metric_data['namespace'],
            MetricData=metric_data['metric_data']
        )
    except Exception as e:
        logging.exception(f"Failed to push metric data: {json.dumps(metric_data)}")
        raise e


def send_report_to_sns(topic_arn, report):
    try:
        sns.publish(
            Subject="AWS accounts security compliance check",
            TopicArn=topic_arn,
            Message=report
        )
    except Exception as e:
        logging.exception(f"Problem to send report to SNS: {topic_arn}")
        raise e


def build_findings_report(by_control_id, account_alias, account_id):
    findings_count = 0

    if len(by_control_id) == 0:
        report = "Everything alright for {}".format(account_alias)
    else:
        report = ""
        report += "-" * 80
        report += f"\nFindings for {account_alias} - {account_id}\n"
        report += "-" * 80
        for control_id in by_control_id.keys():
            report += f"\n{control_id} findings:"
            for finding in by_control_id[control_id]:
                report += f"\n{finding['Id']} - {finding['Region']} - {finding['LastObservedAt']}"
                findings_count += 1

    return [report, findings_count]


def group_findings_by_control_id(findings, control_ids):
    filtered = list(filter(lambda item: item["ProductFields"]["ControlId"] in control_ids, findings))
    by_control_id = {item["ProductFields"]["ControlId"]: [] for item in filtered}
    for finding in filtered:
        by_control_id[finding["ProductFields"]["ControlId"]].append(finding)
    return by_control_id


def get_findings():
    findings = []
    try:
        _filter = {
            'GeneratorId': [
                {
                    'Value': GENERATOR_ID,
                    'Comparison': 'PREFIX'
                }
            ],
            'ComplianceStatus': [
                {
                    'Value': 'FAILED',
                    'Comparison': 'EQUALS'
                }
            ],
            'RecordState': [
                {
                    'Value': 'ACTIVE',
                    'Comparison': 'EQUALS'
                }
            ]
        }
        response = securityhub.get_findings(Filters=_filter)
        findings.extend(response["Findings"])

        while 'NextToken' in response:
            response = securityhub.get_findings(
                Filters=_filter, NextToken=response['NextToken'])
            findings.extend(response["Findings"])
    except Exception as e:
        logging.exception(f"Failed to get security hub findings")
        raise e

    return findings


def build_metric_data(by_control_id):
    compliant_control_ids = list(set(control_ids_resolver.get_security_controls()) - set(by_control_id.keys() if bool(by_control_id) else []))

    by_control_id.update({ctrl_id: [] for ctrl_id in compliant_control_ids})
    metric_data = []

    for ctrl_id, findings in by_control_id.items():
        metric_data.extend(
            [
                {
                    'MetricName': 'Findings',
                    'Dimensions': [
                        {
                            'Name': 'ControlId',
                            'Value': ctrl_id
                        }
                    ],
                    'Unit': 'None',
                    'Value': len(findings)
                }
            ]
        )

    namespace = METRICS_NAMESPACE

    return {
        'metric_data': metric_data,
        'namespace': namespace
    }
