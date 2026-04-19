# Intent: Elasticsearch domains must be deployed inside a VPC.
# Reference: Cigna/confectionery Elasticsearch VPC rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_es_01

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-ES-01",
	"name": "Elasticsearch domains must deploy into a VPC",
	"description": "aws_elasticsearch_domain must declare a vpc_options block.",
	"help_uri": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/vpc.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "elasticsearch", "network"],
}

findings contains finding if {
	some r in helpers.resources("aws_elasticsearch_domain")
	not helpers.has_sub_block(r.block, "vpc_options")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Elasticsearch domain %q is not deployed inside a VPC.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
