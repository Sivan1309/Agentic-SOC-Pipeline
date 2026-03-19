package terraform.aws.cloudtrail

# Policy 4 — CloudTrail must be enabled in all regions
# SOX IT Controls — Complete audit trail requirement

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.after.is_multi_region_trail == false
    msg := sprintf("CloudTrail '%v' must be enabled in all regions. SOX audit trail requirement", [resource.name])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.after.enable_log_file_validation == false
    msg := sprintf("CloudTrail '%v' must have log file validation enabled. SOX audit trail requirement", [resource.name])
}
