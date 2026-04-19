# Intent: Front Door must require HTTPS or redirect HTTP to HTTPS.
# Reference: Cigna/confectionery Front Door HTTPS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_fd_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-FD-01",
	"name": "Front Door must require HTTPS or redirect HTTP to HTTPS",
	"description": "azurerm_frontdoor routing_rule must enforce HTTPS only or redirect HTTP to HTTPS.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/frontdoor/end-to-end-tls",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [319],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "front-door"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_frontdoor")
	some sb in helpers.sub_blocks(r.block, "routing_rule")
	not _enforces_https(sb)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Front Door %q has a routing rule that does not enforce HTTPS.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_enforces_https(block) if {
	some fwd in helpers.sub_blocks(block, "forwarding_configuration")
	helpers.string_attr(fwd, "forwarding_protocol") == "HttpsOnly"
}

_enforces_https(block) if {
	some redir in helpers.sub_blocks(block, "redirect_configuration")
	helpers.string_attr(redir, "redirect_protocol") == "HttpsOnly"
}
