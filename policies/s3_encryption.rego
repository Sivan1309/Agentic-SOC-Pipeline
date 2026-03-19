package terraform.aws.s3

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not has_encryption(resource.name)
    msg := sprintf("S3 bucket '%v' must have encryption enabled. PCI DSS Req 3.5", [resource.name])
}

has_encryption(bucket_name) if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.after.bucket == bucket_name
}

has_encryption(bucket_name) if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    contains(resource.name, bucket_name)
}
