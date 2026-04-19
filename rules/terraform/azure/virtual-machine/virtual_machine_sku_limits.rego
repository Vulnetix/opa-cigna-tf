# Intent: VMs must use an approved SKU (size).
# Reference: Cigna/confectionery VM SKU rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_vm_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-VM-02",
	"name": "VMs must use an approved SKU (size)",
	"description": "Windows/Linux VMs must set size to an approved SKU from the allowlist.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/virtual-machines/sizes",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "virtual-machine"],
}

_approved := {
	"Standard_B2s",
	"Standard_B2ms",
	"Standard_D2s_v3",
	"Standard_D2s_v4",
	"Standard_D4s_v3",
	"Standard_D4s_v4",
	"Standard_D8s_v3",
	"Standard_D8s_v4",
	"Standard_E2s_v3",
	"Standard_E4s_v3",
	"Standard_F2s_v2",
	"Standard_F4s_v2",
}

_vm_types := {"azurerm_windows_virtual_machine", "azurerm_linux_virtual_machine"}

findings contains finding if {
	some t in _vm_types
	some r in helpers.resources(t)
	size := helpers.string_attr(r.block, "size")
	not _is_approved(size)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM %q uses unapproved SKU %q.", [r.name, size]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_approved(size) if {
	some s in _approved
	size == s
}
