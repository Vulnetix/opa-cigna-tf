# Intent: EKS clusters must use private API endpoints.
# Reference: Cigna/confectionery EKS public endpoint rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_eks_02

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-EKS-02",
	"name": "EKS clusters must use private endpoints",
	"description": "aws_eks_cluster.vpc_config must set endpoint_private_access = true and endpoint_public_access = false.",
	"help_uri": "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "eks", "network"],
}

findings contains finding if {
	some r in helpers.resources("aws_eks_cluster")
	not _private_only(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EKS cluster %q exposes a public API endpoint.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_private_only(block) if {
	some sb in helpers.sub_blocks(block, "vpc_config")
	helpers.bool_attr(sb, "endpoint_private_access") == true
	helpers.bool_attr(sb, "endpoint_public_access") == false
}
