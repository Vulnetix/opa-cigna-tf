# Intent: Web Apps must use TLS 1.2 or higher.
# Reference: Cigna/confectionery Web App TLS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_wa_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-WA-02",
	"name": "Web Apps must use TLS 1.2 or higher",
	"description": "azurerm_app_service site_config.min_tls_version must be >= 1.2.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [326],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "web-app", "tls"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_app_service")
	not _tls_ok(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Web App %q does not require TLS 1.2+.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_tls_ok(block) if {
	some sb in helpers.sub_blocks(block, "site_config")
	v := helpers.string_attr(sb, "min_tls_version")
	to_number(v) >= 1.2
}
