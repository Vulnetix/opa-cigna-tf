# Intent: Web Apps must require HTTPS.
# Reference: Cigna/confectionery Web App HTTPS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_wa_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-WA-01",
	"name": "Web Apps must require HTTPS",
	"description": "azurerm_app_service must set https_only = true.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [319],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "web-app"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_app_service")
	helpers.is_not_true(r.block, "https_only")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Web App %q does not require HTTPS.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
