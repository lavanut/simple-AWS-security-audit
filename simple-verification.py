# Verify the status of common AWS security services, AWS CloudTrail, Amazon GuardDuty, and AWS Security Hub.
# Simple script for verification "on or off" in a pretty table.

import boto3
from prettytable import PrettyTable

# Initialize AWS clients
cloudtrail_client = boto3.client("cloudtrail")
guardduty_client = boto3.client("guardduty")
securityhub_client = boto3.client("securityhub")

# Check if CloudTrail is enabled
cloudtrails = cloudtrail_client.describe_trails()
cloudtrail_status = "No"
for trail in cloudtrails["trailList"]:
    status = cloudtrail_client.get_trail_status(Name=trail["Name"])
    if status["IsLogging"]:
        cloudtrail_status = "Yes"
        break

# Check if GuardDuty is enabled
detector = guardduty_client.list_detectors()
guardduty_status = "Yes" if detector["DetectorIds"] else "No"

# Check if Security Hub is enabled
try:
    securityhub_client.get_enabled_standards()
    securityhub_status = "Yes"
except securityhub_client.exceptions.ResourceNotFoundException:
    securityhub_status = "No"

# Display the results in a pretty table
table = PrettyTable()
table.field_names = ["Service", "Enabled"]
table.add_row(["AWS CloudTrail", cloudtrail_status])
table.add_row(["Amazon GuardDuty", guardduty_status])
table.add_row(["AWS Security Hub", securityhub_status])

print(table)
