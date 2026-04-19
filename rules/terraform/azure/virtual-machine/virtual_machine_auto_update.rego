# Intent: VMs must enable automatic updates.
# Reference: Cigna/confectionery VM auto-update rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_vm_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-VM-01",
	"name": "VMs must enable automatic updates",
	"description": "Windows VMs must set patch_mode = \"AutomaticByPlatform\" or enable_automatic_updates = true; Linux VMs must set patch_mode = \"AutomaticByPlatform\".",
	"help_uri": "https://learn.microsoft.com/en-us/azure/virtual-machines/automatic-vm-guest-patching",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "virtual-machine"],
}

_vm_types := {"azurerm_windows_virtual_machine", "azurerm_linux_virtual_machine"}

findings contains finding if {
	some t in _vm_types
	some r in helpers.resources(t)
	not _auto_update_ok(r.block, t)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM %q does not enable automatic updates.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_auto_update_ok(block, t) if {
	t == "azurerm_windows_virtual_machine"
	helpers.bool_attr(block, "enable_automatic_updates") == true
}

_auto_update_ok(block, _t) if {
	some sb in helpers.sub_blocks(block, "os_disk")
	helpers.string_attr(sb, "patch_mode") == "AutomaticByPlatform"
}
