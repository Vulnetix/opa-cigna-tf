# Intent: SQL servers must be part of a geo-redundant failover group.
# Reference: Cigna/confectionery SQL geo-redundancy rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_db_04

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-DB-04",
	"name": "SQL servers must be part of a geo-redundant failover group",
	"description": "Each azurerm_sql_server must be referenced by an azurerm_sql_failover_group.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/azure-sql/database/auto-failover-group-overview",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "database"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_sql_server")
	not _in_failover_group(r.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL server %q is not part of a failover group.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_in_failover_group(name) if {
	some fg in helpers.resources("azurerm_sql_failover_group")
	servers := helpers.string_list_attr(fg.block, "server_names")
	some s in servers
	contains(s, name)
}
