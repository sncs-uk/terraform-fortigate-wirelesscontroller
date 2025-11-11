<!-- BEGIN_TF_DOCS -->
# Fortigate Wireless Controller configuration module

This terraform module configures some base wireless controller configuration on a FortiGate firewall

## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_fortios"></a> [fortios](#provider\_fortios) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [fortios_wirelesscontroller_setting.settings](https://registry.terraform.io/providers/fortinetdev/fortios/latest/docs/resources/wirelesscontroller_setting) | resource |
| [fortios_wirelesscontroller_snmp.snmp](https://registry.terraform.io/providers/fortinetdev/fortios/latest/docs/resources/wirelesscontroller_snmp) | resource |
| [fortios_wirelesscontroller_vap.vaps](https://registry.terraform.io/providers/fortinetdev/fortios/latest/docs/resources/wirelesscontroller_vap) | resource |
| [fortios_wirelesscontroller_vapgroup.vapgroups](https://registry.terraform.io/providers/fortinetdev/fortios/latest/docs/resources/wirelesscontroller_vapgroup) | resource |
| [fortios_wirelesscontroller_wtpprofile.profiles](https://registry.terraform.io/providers/fortinetdev/fortios/latest/docs/resources/wirelesscontroller_wtpprofile) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_config_path"></a> [config\_path](#input\_config\_path) | Path to base configuration directory | `string` | n/a | yes |

## Outputs

No outputs.
<!-- END_TF_DOCS -->