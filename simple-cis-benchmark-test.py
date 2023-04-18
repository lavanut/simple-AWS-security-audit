import boto3
import prettytable

def check_iam_root_account():
    client = boto3.client('iam')
    response = client.get_account_summary()
    root_account = response['SummaryMap']['AccountMFAEnabled']
    return 'Compliant' if root_account == 1 else 'Non-Compliant'

def check_aws_config():
    client = boto3.client('config')
    response = client.describe_configuration_recorder_status()
    status = response['ConfigurationRecordersStatus'][0]['recording']
    return 'Compliant' if status else 'Non-Compliant'

def check_cloudtrail():
    client = boto3.client('cloudtrail')
    response = client.describe_trails()
    trails = response['trailList']
    for trail in trails:
        if trail['IsMultiRegionTrail']:
            return 'Compliant'
    return 'Non-Compliant'

def main():
    table = prettytable.PrettyTable()
    table.field_names = ['CIS Benchmark', 'Result']
    table.add_row(['1.1 Ensure IAM Root Account MFA is enabled', check_iam_root_account()])
    table.add_row(['2.1 Ensure AWS Config is enabled', check_aws_config()])
    table.add_row(['2.2 Ensure CloudTrail is enabled in all regions', check_cloudtrail()])

    print(table)

if __name__ == '__main__':
    main()
