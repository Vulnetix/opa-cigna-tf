# Intent: Front Door frontend endpoints must attach a WAF policy.
# Reference: Cigna/confectionery Front Door WAF rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_fd_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-FD-02",
	"name": "Front Door frontend endpoints must attach a WAF policy",
	"description": "azurerm_frontdoor frontend_endpoint must set web_application_firewall_policy_link_id.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/frontdoor/waf-overview",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "front-door"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_frontdoor")
	some sb in helpers.sub_blocks(r.block, "frontend_endpoint")
	not helpers.has_key(sb, "web_application_firewall_policy_link_id")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Front Door %q has a frontend endpoint without WAF policy link.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
