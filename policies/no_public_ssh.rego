package terraform.aws.security

# Policy 3 — No public SSH or RDP ports
# FFIEC — Network Security Controls

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.after.from_port == 22
    resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("Security group '%v' must not expose SSH port 22 to internet. FFIEC guidance", [resource.name])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.after.from_port == 3389
    resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("Security group '%v' must not expose RDP port 3389 to internet. FFIEC guidance", [resource.name])
}
