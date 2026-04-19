# Intent: Redis Cache must disable the non-SSL port.
# Reference: Cigna/confectionery Redis SSL port rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_redis_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-REDIS-01",
	"name": "Redis Cache must disable the non-SSL port",
	"description": "azurerm_redis_cache must set enable_non_ssl_port = false.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-configure#access-ports",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [319],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "redis-cache"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_redis_cache")
	helpers.bool_attr(r.block, "enable_non_ssl_port") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redis cache %q enables the non-SSL port.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
