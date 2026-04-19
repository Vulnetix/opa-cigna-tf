# Intent: Public IPs must not be created.
# Reference: Cigna/confectionery Public IP rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_pip_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-PIP-01",
	"name": "Public IPs must not be created",
	"description": "azurerm_public_ip is disallowed by policy.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "public-ip"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_public_ip")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Public IP %q is disallowed by policy.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
