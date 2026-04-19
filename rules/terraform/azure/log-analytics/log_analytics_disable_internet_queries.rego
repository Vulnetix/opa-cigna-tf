# Intent: Log Analytics Workspaces must disable internet queries.
# Reference: Cigna/confectionery Log Analytics internet queries rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_la_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-LA-01",
	"name": "Log Analytics Workspaces must disable internet queries",
	"description": "azurerm_log_analytics_workspace must set internet_query_enabled = false.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-workspace-overview",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "log-analytics"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_log_analytics_workspace")
	helpers.is_not_true(r.block, "internet_query_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Log Analytics workspace %q does not disable internet queries.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
