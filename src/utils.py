import boto3
import logging
logger = logging.getLogger()
logger.setLevel("INFO")

def get_securityhub_client() -> boto3.client:
    """returns client connected to correct region. Either finding aggregator region or region in which lambda resides"""
    tmp_hub_client = boto3.client('securityhub')
    res = tmp_hub_client.list_finding_aggregators()
    if res is not None and "FindingAggregators" in res:
        agg_arn = res["FindingAggregators"][0]["FindingAggregatorArn"]
        res = tmp_hub_client.get_finding_aggregator(FindingAggregatorArn=agg_arn)
        target_region = res[
            'FindingAggregationRegion'] if res is not None and "FindingAggregationRegion" in res else None
        logger.info(f"this security hub region will be uses {target_region}")
        return boto3.client("securityhub", region_name=target_region)
    else:
        logger.info(f"default region will be used for security hub client")
        return boto3.client("securityhub")
