# Intent: Redis Cache must use TLS 1.2 or higher.
# Reference: Cigna/confectionery Redis TLS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_redis_03

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-REDIS-03",
	"name": "Redis Cache must use TLS 1.2 or higher",
	"description": "azurerm_redis_cache minimum_tls_version must be >= 1.2.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-configure#access-ports",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [326],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "redis-cache", "tls"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_redis_cache")
	v := helpers.string_attr(r.block, "minimum_tls_version")
	to_number(v) < 1.2
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redis cache %q uses TLS version below 1.2.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in helpers.resources("azurerm_redis_cache")
	not helpers.has_key(r.block, "minimum_tls_version")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redis cache %q does not set minimum_tls_version.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
