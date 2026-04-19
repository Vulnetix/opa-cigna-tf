# Intent: Application Gateway must have an attached WAF policy.
# Reference: Cigna/confectionery Azure Application Gateway rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_agw_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-AGW-01",
	"name": "Application Gateway must have an attached WAF policy",
	"description": "azurerm_application_gateway must set firewall_policy_id.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/application-gateway/waf-overview",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "app-gateway"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_application_gateway")
	not helpers.has_key(r.block, "firewall_policy_id")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Application Gateway %q does not set firewall_policy_id.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
