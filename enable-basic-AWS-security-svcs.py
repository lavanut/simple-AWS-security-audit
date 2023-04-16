import boto3

# Initialize AWS clients
securityhub_client = boto3.client("securityhub")
guardduty_client = boto3.client("guardduty")
cloudtrail_client = boto3.client("cloudtrail")
inspector_client = boto3.client("inspector")
sts_client = boto3.client("sts")
ec2_client = boto3.client("ec2")

# Enable AWS Security Hub
try:
    securityhub_client.get_enabled_standards()
    print("Security Hub is already enabled.")
except securityhub_client.exceptions.ResourceNotFoundException:
    print("Enabling Security Hub...")
    securityhub_client.enable_security_hub()
    print("Security Hub enabled.")

# Enable CIS and PCI DSS benchmarks in Security Hub
print("Enabling CIS and PCI DSS benchmarks in Security Hub...")
cis_standard = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
pci_standard = "arn:aws:securityhub:::ruleset/pci-dss/v/3.2.1"
standards_to_enable = [cis_standard, pci_standard]
for standard_arn in standards_to_enable:
    securityhub_client.batch_enable_standards(StandardsSubscriptionRequests=[{"StandardsArn": standard_arn}])
print("CIS and PCI DSS benchmarks enabled in Security Hub.")

# Enable GuardDuty
detector = guardduty_client.list_detectors()
if not detector["DetectorIds"]:
    print("Enabling GuardDuty...")
    guardduty_client.create_detector(Enable=True)
    print("GuardDuty enabled.")
else:
    print("GuardDuty is already enabled.")

# Enable CloudTrail in all regions
print("Enabling CloudTrail in all regions...")
regions = [region["RegionName"] for region in ec2_client.describe_regions()["Regions"]]
for region in regions:
    regional_cloudtrail_client = boto3.client("cloudtrail", region_name=region)
    trails = regional_cloudtrail_client.describe_trails()
    if not trails["trailList"]:
        regional_cloudtrail_client.create_trail(Name="DefaultTrail", S3BucketName="your-bucket-name")
        regional_cloudtrail_client.start_logging(Name="DefaultTrail")
    else:
        for trail in trails["trailList"]:
            trail_status = regional_cloudtrail_client.get_trail_status(Name=trail["Name"])
            if not trail_status["IsLogging"]:
                regional_cloudtrail_client.start_logging(Name=trail["Name"])
print("CloudTrail enabled in all regions.")

# Set up Amazon Inspector
print("Setting up Amazon Inspector...")
inspector_assessment_targets = inspector_client.list_assessment_targets()
assessment_target_exists = False
for target in inspector_assessment_targets["assessmentTargetArns"]:
    target_details = inspector_client.describe_assessment_targets(assessmentTargetArns=[target])
    if target_details["assessmentTargets"][0]["name"] == "Default":
        assessment_target_exists = True
        break

if not assessment_target_exists:
    account_id = sts_client.get_caller_identity()["Account"]
    resource_group_arn = f"arn:aws:inspector:us-west-2:{account_id}:resourcegroup/0-abcdef1234567890"
    inspector_client.create_assessment_target(assessmentTargetName="Default", resourceGroupArn=resource_group_arn)
    print("Created Amazon Inspector assessment target
