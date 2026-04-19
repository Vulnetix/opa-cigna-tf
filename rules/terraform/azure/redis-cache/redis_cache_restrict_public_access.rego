# Intent: Redis Cache must disable public network access.
# Reference: Cigna/confectionery Redis public access rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_redis_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-REDIS-02",
	"name": "Redis Cache must disable public network access",
	"description": "azurerm_redis_cache must set public_network_access_enabled = false.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-network-isolation",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "redis-cache"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_redis_cache")
	helpers.is_not_true(r.block, "public_network_access_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redis cache %q does not disable public network access.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
