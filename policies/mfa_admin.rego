package terraform.aws.iam

# Policy 2 — MFA required on all IAM admin roles
# GLBA Safeguards Rule — Access Controls

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_user"
    resource.change.after.force_destroy == true
    msg := sprintf("IAM user '%v' must have MFA enabled. GLBA Safeguards Rule", [resource.name])
}
