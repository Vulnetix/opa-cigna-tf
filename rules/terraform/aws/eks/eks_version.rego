# Intent: EKS clusters must run a minimum Kubernetes version.
# Reference: Cigna/confectionery EKS version rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_eks_03

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-EKS-03",
	"name": "EKS clusters must run Kubernetes 1.15 or newer",
	"description": "aws_eks_cluster must set version to at least 1.15.",
	"help_uri": "https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [1104],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "eks", "version"],
}

findings contains finding if {
	some r in helpers.resources("aws_eks_cluster")
	v := helpers.string_attr(r.block, "version")
	not _meets_min_version(v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EKS cluster %q version %q is below 1.15.", [r.name, v]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_meets_min_version(v) if {
	parts := split(v, ".")
	count(parts) >= 2
	major := to_number(parts[0])
	minor := to_number(parts[1])
	major >= 1
	minor >= 15
}
