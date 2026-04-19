# Intent: NAT Gateways must not be created.
# Reference: Cigna/confectionery NAT Gateway rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_nat_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-NAT-01",
	"name": "NAT Gateways must not be created",
	"description": "azurerm_nat_gateway is disallowed by policy.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/nat-gateway/nat-overview",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "nat-gateway"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_nat_gateway")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("NAT Gateway %q is disallowed by policy.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
