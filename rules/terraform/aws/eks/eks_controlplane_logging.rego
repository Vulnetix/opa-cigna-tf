# Intent: EKS clusters must enable control plane logging.
# Reference: Cigna/confectionery EKS logging rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_eks_01

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-EKS-01",
	"name": "EKS clusters must enable control plane logging",
	"description": "aws_eks_cluster must set enabled_cluster_log_types with at least one log type.",
	"help_uri": "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logging.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [778],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "eks", "logging"],
}

findings contains finding if {
	some r in helpers.resources("aws_eks_cluster")
	not _has_log_types(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EKS cluster %q does not enable enabled_cluster_log_types.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_log_types(block) if {
	vals := helpers.string_list_attr(block, "enabled_cluster_log_types")
	count(vals) > 0
}
