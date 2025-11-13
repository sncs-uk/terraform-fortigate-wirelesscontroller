/**
 * # Fortigate Wireless Controller configuration module
 *
 * This terraform module configures some base wireless controller configuration on a FortiGate firewall
 */
terraform {
  required_providers {
    fortios = {
      source  = "fortinetdev/fortios"
    }
  }
}
locals {
  wireless_yaml  = fileexists("${var.config_path}/managed-wireless.yaml") ? yamldecode(file("${var.config_path}/managed-wireless.yaml")) : object({})
}

resource fortios_wirelesscontroller_setting settings {
  account_id                            = try(local.wireless_yaml.settings.account_id, null)
  country                               = try(local.wireless_yaml.settings.country, null)
  duplicate_ssid                        = try(local.wireless_yaml.settings.duplicate_ssid, null)
  fapc_compatibility                    = try(local.wireless_yaml.settings.fapc_compatibility, null)
  wfa_compatibility                     = try(local.wireless_yaml.settings.wfa_compatibility, null)
  phishing_ssid_detect                  = try(local.wireless_yaml.settings.phishing_ssid_detect, null)
  fake_ssid_action                      = try(local.wireless_yaml.settings.fake_ssid_action, null)
  device_weight                         = try(local.wireless_yaml.settings.device_weight, null)
  device_holdoff                        = try(local.wireless_yaml.settings.device_holdoff, null)
  device_idle                           = try(local.wireless_yaml.settings.device_idle, null)
  firmware_provision_on_authorization   = try(local.wireless_yaml.settings.firmware_provision_on_authorization, null)
  rolling_wtp_upgrade                   = try(local.wireless_yaml.settings.rolling_wtp_upgrade, null)
}

resource fortios_wirelesscontroller_snmp snmp {
  count                     = try(local.wireless_yaml.snmp, []) == [] ? 0 : 1
  engine_id                 = try(local.wireless_yaml.snmp.engine_id, null)
  contact_info              = try(local.wireless_yaml.snmp.contact_info, null)
  trap_high_cpu_threshold   = try(local.wireless_yaml.snmp.trap_high_cpu_threshold, null)
  trap_high_mem_threshold   = try(local.wireless_yaml.snmp.trap_high_mem_threshold, null)

  dynamic community {
    for_each          = { for name, community in try(local.wireless_yaml.snmp.communities, {}) : name => community}
    content {
      name                = community.key
      status              = try(community.value.status, null)
      query_v1_status     = try(community.value.query_v1_status, null)
      query_v2c_status    = try(community.value.query_v2c_status, null)
      trap_v1_status      = try(community.value.trap_v1_status, null)
      trap_v2c_status     = try(community.value.trap_v2c_status, null)
      dynamic hosts {
        for_each          = { for host in try(community.value.hosts, []) : host => host}
        content {
          id        = index(community.value.hosts, hosts.value)
          ip        = hosts.value
        }
      }
    }
  }

  dynamic user {
    for_each        = try(local.wireless_yaml.snmp.users, {})
    content {
      name              = try(user.value.name, null)
      status            = try(user.value.status, null)
      queries           = try(user.value.queries, null)
      trap_status       = try(user.value.trap_status, null)
      security_level    = try(user.value.security_level, null)
      auth_proto        = try(user.value.auth_proto, null)
      auth_pwd          = try(user.value.auth_pwd, null)
      priv_proto        = try(user.value.priv_proto, null)
      priv_pwd          = try(user.value.priv_pwd, null)
      notify_hosts      = try(user.value.notify_hosts, null)
    }
  }
}

resource fortios_wirelesscontroller_wtpprofile profiles {
  depends_on                            = [fortios_wirelesscontroller_vap.vaps, fortios_wirelesscontroller_vapgroup.vapgroups]
  for_each                              = { for name, profile in try(local.wireless_yaml.ap_profiles, []) : name => profile}
  name                                  = each.key
  comment                               = try(each.value.comment, null)
  control_message_offload               = try(each.value.control_message_offload, null)
  bonjour_profile                       = try(each.value.bonjour_profile, null)
  apcfg_profile                         = try(each.value.apcfg_profile, null)
  apcfg_mesh                            = try(each.value.apcfg_mesh, null)
  apcfg_mesh_ap_type                    = try(each.value.apcfg_mesh_ap_type, null)
  apcfg_mesh_ssid                       = try(each.value.apcfg_mesh_ssid, null)
  apcfg_mesh_eth_bridge                 = try(each.value.apcfg_mesh_eth_bridge, null)
  ble_profile                           = try(each.value.ble_profile, null)
  syslog_profile                        = try(each.value.syslog_profile, null)
  wan_port_mode                         = try(each.value.wan_port_mode, null)
  energy_efficient_ethernet             = try(each.value.energy_efficient_ethernet, null)
  led_state                             = try(each.value.led_state, null)
  dtls_policy                           = try(each.value.dtls_policy, null)
  dtls_in_kernel                        = try(each.value.dtls_in_kernel, null)
  max_clients                           = try(each.value.max_clients, null)
  handoff_rssi                          = try(each.value.handoff_rssi, null)
  handoff_sta_thresh                    = try(each.value.handoff_sta_thresh, null)
  handoff_roaming                       = try(each.value.handoff_roaming, null)
  ap_country                            = try(each.value.ap_country, null)
  ip_fragment_preventing                = try(each.value.ip_fragment_preventing, null)
  tun_mtu_uplink                        = try(each.value.tun_mtu_uplink, null)
  tun_mtu_downlink                      = try(each.value.tun_mtu_downlink, null)
  split_tunneling_acl_path              = try(each.value.split_tunneling_acl_path, null)
  split_tunneling_acl_local_ap_subnet   = try(each.value.split_tunneling_acl_local_ap_subnet, null)
  allowaccess                           = try(each.value.allowaccess, null)
  login_passwd_change                   = try(each.value.login_passwd_change, null)
  login_passwd                          = try(each.value.login_passwd, null)
  lldp                                  = try(each.value.lldp, null)
  poe_mode                              = try(each.value.poe_mode, null)
  usb_port                              = try(each.value.usb_port, null)
  frequency_handoff                     = try(each.value.frequency_handoff, null)
  ap_handoff                            = try(each.value.ap_handoff, null)
  default_mesh_root                     = try(each.value.default_mesh_root, null)
  ext_info_enable                       = try(each.value.ext_info_enable, null)
  indoor_outdoor_deployment             = try(each.value.indoor_outdoor_deployment, null)
  console_login                         = try(each.value.console_login, null)
  wan_port_auth                         = try(each.value.wan_port_auth, null)
  wan_port_auth_usrname                 = try(each.value.wan_port_auth_usrname, null)
  wan_port_auth_password                = try(each.value.wan_port_auth_password, null)
  wan_port_auth_methods                 = try(each.value.wan_port_auth_methods, null)
  wan_port_auth_macsec                  = try(each.value.wan_port_auth_macsec, null)
  unii_4_5ghz_band                      = try(each.value.unii_4_5ghz_band, null)
  admin_auth_tacacs                     = try(each.value.admin_auth_tacacs, null)
  admin_restrict_local                  = try(each.value.admin_restrict_local, null)

  dynamic platform {
    for_each = { for type, platform in each.value.platforms : type => platform }
    content {
      type      = platform.key
      mode      = try(platform.value.mode, null)
      ddscan    = try(platform.value.ddscan, null)
    }
  }

  lan {
    port_mode       = try(each.value.lan.port_mode, null)
    port_ssid       = try(each.value.lan.port_ssid, null)
    port1_mode      = try(each.value.lan.port1_mode, null)
    port1_ssid      = try(each.value.lan.port1_ssid, null)
    port2_mode      = try(each.value.lan.port2_mode, null)
    port2_ssid      = try(each.value.lan.port2_ssid, null)
    port3_mode      = try(each.value.lan.port3_mode, null)
    port3_ssid      = try(each.value.lan.port3_ssid, null)
    port4_mode      = try(each.value.lan.port4_mode, null)
    port4_ssid      = try(each.value.lan.port4_ssid, null)
    port5_mode      = try(each.value.lan.port5_mode, null)
    port5_ssid      = try(each.value.lan.port5_ssid, null)
    port6_mode      = try(each.value.lan.port6_mode, null)
    port6_ssid      = try(each.value.lan.port6_ssid, null)
    port7_mode      = try(each.value.lan.port7_mode, null)
    port7_ssid      = try(each.value.lan.port7_ssid, null)
    port8_mode      = try(each.value.lan.port8_mode, null)
    port8_ssid      = try(each.value.lan.port8_ssid, null)
    port_esl_mode   = try(each.value.lan.port_esl_mode, null)
    port_esl_ssid   = try(each.value.lan.port_esl_ssid, null)
  }

  dynamic led_schedules {
    for_each  = { for schedule in try(each.value.led_schedules, []) : schedule => schedule }
    content {
      name    = led_schedules.value
    }
  }

  dynamic deny_mac_list {
    for_each  = { for mac in try(each.value.deny_mac_list, []) : mac => mac}
    content {
      id      = index(each.value.deny_mac_list, deny_mac_list.value)
      mac     = deny_mac_list.value
    }
  }

  dynamic split_tunneling_acl {
    for_each    = { for ip in try(each.value.split_tunneling_acl, []) : ip => ip}
    content {
      id        = index(each.value.split_tunneling_acl, split_tunneling_acl.value)
      dest_ip   = split_tunneling_acl.value
    }
  }

  dynamic radio_1 {
    for_each                        = { for a in (try(each.value.radios.1, []) == [] ? [] : ["1"]) : a => a}
    content {
      radio_id                      = try(each.value.radios.1.radio_id, null)
      mode                          = try(each.value.radios.1.mode, null)
      band                          = try(each.value.radios.1.band, null)
      band_5g_type                  = try(each.value.radios.1.band_5g_type, null)
      drma                          = try(each.value.radios.1.drma, null)
      drma_sensitivity              = try(each.value.radios.1.drma_sensitivity, null)
      airtime_fairness              = try(each.value.radios.1.airtime_fairness, null)
      protection_mode               = try(each.value.radios.1.protection_mode, null)
      powersave_optimize            = try(each.value.radios.1.powersave_optimize, null)
      transmit_optimize             = try(each.value.radios.1.transmit_optimize, null)
      amsdu                         = try(each.value.radios.1.amsdu, null)
      coexistence                   = try(each.value.radios.1.coexistence, null)
      zero_wait_dfs                 = try(each.value.radios.1.zero_wait_dfs, null)
      bss_color                     = try(each.value.radios.1.bss_color, null)
      bss_color_mode                = try(each.value.radios.1.bss_color_mode, null)
      short_guard_interval          = try(each.value.radios.1.short_guard_interval, null)
      mimo_mode                     = try(each.value.radios.1.mimo_mode, null)
      channel_bonding               = try(each.value.radios.1.channel_bonding, null)
      channel_bonding_ext           = try(each.value.radios.1.channel_bonding_ext, null)
      optional_antenna              = try(each.value.radios.1.optional_antenna, null)
      optional_antenna_gain         = try(each.value.radios.1.optional_antenna_gain, null)
      auto_power_level              = try(each.value.radios.1.auto_power_level, null)
      auto_power_high               = try(each.value.radios.1.auto_power_high, null)
      auto_power_low                = try(each.value.radios.1.auto_power_low, null)
      auto_power_target             = try(each.value.radios.1.auto_power_target, null)
      power_mode                    = try(each.value.radios.1.power_mode, null)
      power_level                   = try(each.value.radios.1.power_level, null)
      power_value                   = try(each.value.radios.1.power_value, null)
      dtim                          = try(each.value.radios.1.dtim, null)
      beacon_interval               = try(each.value.radios.1.beacon_interval, null)
      n80211d                       = try(each.value.radios.1.n80211d, null)
      n80211mc                      = try(each.value.radios.1.n80211mc, null)
      rts_threshold                 = try(each.value.radios.1.rts_threshold, null)
      frag_threshold                = try(each.value.radios.1.frag_threshold, null)
      ap_sniffer_bufsize            = try(each.value.radios.1.ap_sniffer_bufsize, null)
      ap_sniffer_chan               = try(each.value.radios.1.ap_sniffer_chan, null)
      ap_sniffer_chan_width         = try(each.value.radios.1.ap_sniffer_chan_width, null)
      ap_sniffer_addr               = try(each.value.radios.1.ap_sniffer_addr, null)
      ap_sniffer_mgmt_beacon        = try(each.value.radios.1.ap_sniffer_mgmt_beacon, null)
      ap_sniffer_mgmt_probe         = try(each.value.radios.1.ap_sniffer_mgmt_probe, null)
      ap_sniffer_mgmt_other         = try(each.value.radios.1.ap_sniffer_mgmt_other, null)
      ap_sniffer_ctl                = try(each.value.radios.1.ap_sniffer_ctl, null)
      ap_sniffer_data               = try(each.value.radios.1.ap_sniffer_data, null)
      sam_ssid                      = try(each.value.radios.1.sam_ssid, null)
      sam_bssid                     = try(each.value.radios.1.sam_bssid, null)
      sam_security_type             = try(each.value.radios.1.sam_security_type, null)
      sam_captive_portal            = try(each.value.radios.1.sam_captive_portal, null)
      sam_cwp_username              = try(each.value.radios.1.sam_cwp_username, null)
      sam_cwp_password              = try(each.value.radios.1.sam_cwp_password, null)
      sam_cwp_test_url              = try(each.value.radios.1.sam_cwp_test_url, null)
      sam_cwp_match_string          = try(each.value.radios.1.sam_cwp_match_string, null)
      sam_cwp_success_string        = try(each.value.radios.1.sam_cwp_success_string, null)
      sam_cwp_failure_string        = try(each.value.radios.1.sam_cwp_failure_string, null)
      sam_eap_method                = try(each.value.radios.1.sam_eap_method, null)
      sam_client_certificate        = try(each.value.radios.1.sam_client_certificate, null)
      sam_private_key               = try(each.value.radios.1.sam_private_key, null)
      sam_private_key_password      = try(each.value.radios.1.sam_private_key_password, null)
      sam_ca_certificate            = try(each.value.radios.1.sam_ca_certificate, null)
      sam_username                  = try(each.value.radios.1.sam_username, null)
      sam_password                  = try(each.value.radios.1.sam_password, null)
      sam_test                      = try(each.value.radios.1.sam_test, null)
      sam_server_type               = try(each.value.radios.1.sam_server_type, null)
      sam_server_ip                 = try(each.value.radios.1.sam_server_ip, null)
      sam_server_fqdn               = try(each.value.radios.1.sam_server_fqdn, null)
      iperf_server_port             = try(each.value.radios.1.iperf_server_port, null)
      iperf_protocol                = try(each.value.radios.1.iperf_protocol, null)
      sam_report_intv               = try(each.value.radios.1.sam_report_intv, null)
      channel_utilization           = try(each.value.radios.1.channel_utilization, null)
      spectrum_analysis             = try(each.value.radios.1.spectrum_analysis, null)
      wids_profile                  = try(each.value.radios.1.wids_profile, null)
      darrp                         = try(each.value.radios.1.darrp, null)
      arrp_profile                  = try(each.value.radios.1.arrp_profile, null)
      max_clients                   = try(each.value.radios.1.max_clients, null)
      max_distance                  = try(each.value.radios.1.max_distance, null)
      frequency_handoff             = try(each.value.radios.1.frequency_handoff, null)
      ap_handoff                    = try(each.value.radios.1.ap_handoff, null)
      vap_all                       = try(each.value.radios.1.vap_all, null)
      call_admission_control        = try(each.value.radios.1.call_admission_control, null)
      call_capacity                 = try(each.value.radios.1.call_capacity, null)
      bandwidth_admission_control   = try(each.value.radios.1.bandwidth_admission_control, null)
      bandwidth_capacity            = try(each.value.radios.1.bandwidth_capacity, null)

      dynamic vaps {
        for_each  = { for vap in try(each.value.radios.1.vaps, []) : vap => vap }
        content {
          name    = vaps.value
        }
      }

      dynamic channel {
        for_each  = { for channel in try(each.value.radios.1.channels, []) : channel => channel }
        content {
          chan    = channel.value
        }
      }
    }
  }
  dynamic radio_2 {
    for_each                        = { for a in (try(each.value.radios.2, []) == [] ? [] : ["1"]) : a => a}
    content {
      radio_id                      = try(each.value.radios.2.radio_id, null)
      mode                          = try(each.value.radios.2.mode, null)
      band                          = try(each.value.radios.2.band, null)
      band_5g_type                  = try(each.value.radios.2.band_5g_type, null)
      drma                          = try(each.value.radios.2.drma, null)
      drma_sensitivity              = try(each.value.radios.2.drma_sensitivity, null)
      airtime_fairness              = try(each.value.radios.2.airtime_fairness, null)
      protection_mode               = try(each.value.radios.2.protection_mode, null)
      powersave_optimize            = try(each.value.radios.2.powersave_optimize, null)
      transmit_optimize             = try(each.value.radios.2.transmit_optimize, null)
      amsdu                         = try(each.value.radios.2.amsdu, null)
      coexistence                   = try(each.value.radios.2.coexistence, null)
      zero_wait_dfs                 = try(each.value.radios.2.zero_wait_dfs, null)
      bss_color                     = try(each.value.radios.2.bss_color, null)
      bss_color_mode                = try(each.value.radios.2.bss_color_mode, null)
      short_guard_interval          = try(each.value.radios.2.short_guard_interval, null)
      mimo_mode                     = try(each.value.radios.2.mimo_mode, null)
      channel_bonding               = try(each.value.radios.2.channel_bonding, null)
      channel_bonding_ext           = try(each.value.radios.2.channel_bonding_ext, null)
      optional_antenna              = try(each.value.radios.2.optional_antenna, null)
      optional_antenna_gain         = try(each.value.radios.2.optional_antenna_gain, null)
      auto_power_level              = try(each.value.radios.2.auto_power_level, null)
      auto_power_high               = try(each.value.radios.2.auto_power_high, null)
      auto_power_low                = try(each.value.radios.2.auto_power_low, null)
      auto_power_target             = try(each.value.radios.2.auto_power_target, null)
      power_mode                    = try(each.value.radios.2.power_mode, null)
      power_level                   = try(each.value.radios.2.power_level, null)
      power_value                   = try(each.value.radios.2.power_value, null)
      dtim                          = try(each.value.radios.2.dtim, null)
      beacon_interval               = try(each.value.radios.2.beacon_interval, null)
      n80211d                       = try(each.value.radios.2.n80211d, null)
      n80211mc                      = try(each.value.radios.2.n80211mc, null)
      rts_threshold                 = try(each.value.radios.2.rts_threshold, null)
      frag_threshold                = try(each.value.radios.2.frag_threshold, null)
      ap_sniffer_bufsize            = try(each.value.radios.2.ap_sniffer_bufsize, null)
      ap_sniffer_chan               = try(each.value.radios.2.ap_sniffer_chan, null)
      ap_sniffer_chan_width         = try(each.value.radios.2.ap_sniffer_chan_width, null)
      ap_sniffer_addr               = try(each.value.radios.2.ap_sniffer_addr, null)
      ap_sniffer_mgmt_beacon        = try(each.value.radios.2.ap_sniffer_mgmt_beacon, null)
      ap_sniffer_mgmt_probe         = try(each.value.radios.2.ap_sniffer_mgmt_probe, null)
      ap_sniffer_mgmt_other         = try(each.value.radios.2.ap_sniffer_mgmt_other, null)
      ap_sniffer_ctl                = try(each.value.radios.2.ap_sniffer_ctl, null)
      ap_sniffer_data               = try(each.value.radios.2.ap_sniffer_data, null)
      sam_ssid                      = try(each.value.radios.2.sam_ssid, null)
      sam_bssid                     = try(each.value.radios.2.sam_bssid, null)
      sam_security_type             = try(each.value.radios.2.sam_security_type, null)
      sam_captive_portal            = try(each.value.radios.2.sam_captive_portal, null)
      sam_cwp_username              = try(each.value.radios.2.sam_cwp_username, null)
      sam_cwp_password              = try(each.value.radios.2.sam_cwp_password, null)
      sam_cwp_test_url              = try(each.value.radios.2.sam_cwp_test_url, null)
      sam_cwp_match_string          = try(each.value.radios.2.sam_cwp_match_string, null)
      sam_cwp_success_string        = try(each.value.radios.2.sam_cwp_success_string, null)
      sam_cwp_failure_string        = try(each.value.radios.2.sam_cwp_failure_string, null)
      sam_eap_method                = try(each.value.radios.2.sam_eap_method, null)
      sam_client_certificate        = try(each.value.radios.2.sam_client_certificate, null)
      sam_private_key               = try(each.value.radios.2.sam_private_key, null)
      sam_private_key_password      = try(each.value.radios.2.sam_private_key_password, null)
      sam_ca_certificate            = try(each.value.radios.2.sam_ca_certificate, null)
      sam_username                  = try(each.value.radios.2.sam_username, null)
      sam_password                  = try(each.value.radios.2.sam_password, null)
      sam_test                      = try(each.value.radios.2.sam_test, null)
      sam_server_type               = try(each.value.radios.2.sam_server_type, null)
      sam_server_ip                 = try(each.value.radios.2.sam_server_ip, null)
      sam_server_fqdn               = try(each.value.radios.2.sam_server_fqdn, null)
      iperf_server_port             = try(each.value.radios.2.iperf_server_port, null)
      iperf_protocol                = try(each.value.radios.2.iperf_protocol, null)
      sam_report_intv               = try(each.value.radios.2.sam_report_intv, null)
      channel_utilization           = try(each.value.radios.2.channel_utilization, null)
      spectrum_analysis             = try(each.value.radios.2.spectrum_analysis, null)
      wids_profile                  = try(each.value.radios.2.wids_profile, null)
      darrp                         = try(each.value.radios.2.darrp, null)
      arrp_profile                  = try(each.value.radios.2.arrp_profile, null)
      max_clients                   = try(each.value.radios.2.max_clients, null)
      max_distance                  = try(each.value.radios.2.max_distance, null)
      frequency_handoff             = try(each.value.radios.2.frequency_handoff, null)
      ap_handoff                    = try(each.value.radios.2.ap_handoff, null)
      vap_all                       = try(each.value.radios.2.vap_all, null)
      call_admission_control        = try(each.value.radios.2.call_admission_control, null)
      call_capacity                 = try(each.value.radios.2.call_capacity, null)
      bandwidth_admission_control   = try(each.value.radios.2.bandwidth_admission_control, null)
      bandwidth_capacity            = try(each.value.radios.2.bandwidth_capacity, null)

      dynamic vaps {
        for_each  = { for vap in try(each.value.radios.2.vaps, []) : vap => vap }
        content {
          name    = vaps.value
        }
      }

      dynamic channel {
        for_each  = { for channel in try(each.value.radios.2.channels, []) : channel => channel }
        content {
          chan    = channel.value
        }
      }
    }
  }
  dynamic radio_3 {
    for_each                        = { for a in (try(each.value.radios.3, []) == [] ? [] : ["1"]) : a => a}
    content {
      mode                          = try(each.value.radios.3.mode, null)
      band                          = try(each.value.radios.3.band, null)
      band_5g_type                  = try(each.value.radios.3.band_5g_type, null)
      drma                          = try(each.value.radios.3.drma, null)
      drma_sensitivity              = try(each.value.radios.3.drma_sensitivity, null)
      airtime_fairness              = try(each.value.radios.3.airtime_fairness, null)
      protection_mode               = try(each.value.radios.3.protection_mode, null)
      powersave_optimize            = try(each.value.radios.3.powersave_optimize, null)
      transmit_optimize             = try(each.value.radios.3.transmit_optimize, null)
      amsdu                         = try(each.value.radios.3.amsdu, null)
      coexistence                   = try(each.value.radios.3.coexistence, null)
      zero_wait_dfs                 = try(each.value.radios.3.zero_wait_dfs, null)
      bss_color                     = try(each.value.radios.3.bss_color, null)
      bss_color_mode                = try(each.value.radios.3.bss_color_mode, null)
      short_guard_interval          = try(each.value.radios.3.short_guard_interval, null)
      mimo_mode                     = try(each.value.radios.3.mimo_mode, null)
      channel_bonding               = try(each.value.radios.3.channel_bonding, null)
      channel_bonding_ext           = try(each.value.radios.3.channel_bonding_ext, null)
      optional_antenna              = try(each.value.radios.3.optional_antenna, null)
      optional_antenna_gain         = try(each.value.radios.3.optional_antenna_gain, null)
      auto_power_level              = try(each.value.radios.3.auto_power_level, null)
      auto_power_high               = try(each.value.radios.3.auto_power_high, null)
      auto_power_low                = try(each.value.radios.3.auto_power_low, null)
      auto_power_target             = try(each.value.radios.3.auto_power_target, null)
      power_mode                    = try(each.value.radios.3.power_mode, null)
      power_level                   = try(each.value.radios.3.power_level, null)
      power_value                   = try(each.value.radios.3.power_value, null)
      dtim                          = try(each.value.radios.3.dtim, null)
      beacon_interval               = try(each.value.radios.3.beacon_interval, null)
      n80211d                       = try(each.value.radios.3.n80211d, null)
      n80211mc                      = try(each.value.radios.3.n80211mc, null)
      rts_threshold                 = try(each.value.radios.3.rts_threshold, null)
      frag_threshold                = try(each.value.radios.3.frag_threshold, null)
      ap_sniffer_bufsize            = try(each.value.radios.3.ap_sniffer_bufsize, null)
      ap_sniffer_chan               = try(each.value.radios.3.ap_sniffer_chan, null)
      ap_sniffer_chan_width         = try(each.value.radios.3.ap_sniffer_chan_width, null)
      ap_sniffer_addr               = try(each.value.radios.3.ap_sniffer_addr, null)
      ap_sniffer_mgmt_beacon        = try(each.value.radios.3.ap_sniffer_mgmt_beacon, null)
      ap_sniffer_mgmt_probe         = try(each.value.radios.3.ap_sniffer_mgmt_probe, null)
      ap_sniffer_mgmt_other         = try(each.value.radios.3.ap_sniffer_mgmt_other, null)
      ap_sniffer_ctl                = try(each.value.radios.3.ap_sniffer_ctl, null)
      ap_sniffer_data               = try(each.value.radios.3.ap_sniffer_data, null)
      sam_ssid                      = try(each.value.radios.3.sam_ssid, null)
      sam_bssid                     = try(each.value.radios.3.sam_bssid, null)
      sam_security_type             = try(each.value.radios.3.sam_security_type, null)
      sam_captive_portal            = try(each.value.radios.3.sam_captive_portal, null)
      sam_cwp_username              = try(each.value.radios.3.sam_cwp_username, null)
      sam_cwp_password              = try(each.value.radios.3.sam_cwp_password, null)
      sam_cwp_test_url              = try(each.value.radios.3.sam_cwp_test_url, null)
      sam_cwp_match_string          = try(each.value.radios.3.sam_cwp_match_string, null)
      sam_cwp_success_string        = try(each.value.radios.3.sam_cwp_success_string, null)
      sam_cwp_failure_string        = try(each.value.radios.3.sam_cwp_failure_string, null)
      sam_eap_method                = try(each.value.radios.3.sam_eap_method, null)
      sam_client_certificate        = try(each.value.radios.3.sam_client_certificate, null)
      sam_private_key               = try(each.value.radios.3.sam_private_key, null)
      sam_private_key_password      = try(each.value.radios.3.sam_private_key_password, null)
      sam_ca_certificate            = try(each.value.radios.3.sam_ca_certificate, null)
      sam_username                  = try(each.value.radios.3.sam_username, null)
      sam_password                  = try(each.value.radios.3.sam_password, null)
      sam_test                      = try(each.value.radios.3.sam_test, null)
      sam_server_type               = try(each.value.radios.3.sam_server_type, null)
      sam_server_ip                 = try(each.value.radios.3.sam_server_ip, null)
      sam_server_fqdn               = try(each.value.radios.3.sam_server_fqdn, null)
      iperf_server_port             = try(each.value.radios.3.iperf_server_port, null)
      iperf_protocol                = try(each.value.radios.3.iperf_protocol, null)
      sam_report_intv               = try(each.value.radios.3.sam_report_intv, null)
      channel_utilization           = try(each.value.radios.3.channel_utilization, null)
      spectrum_analysis             = try(each.value.radios.3.spectrum_analysis, null)
      wids_profile                  = try(each.value.radios.3.wids_profile, null)
      darrp                         = try(each.value.radios.3.darrp, null)
      arrp_profile                  = try(each.value.radios.3.arrp_profile, null)
      max_clients                   = try(each.value.radios.3.max_clients, null)
      max_distance                  = try(each.value.radios.3.max_distance, null)
      frequency_handoff             = try(each.value.radios.3.frequency_handoff, null)
      ap_handoff                    = try(each.value.radios.3.ap_handoff, null)
      vap_all                       = try(each.value.radios.3.vap_all, null)
      call_admission_control        = try(each.value.radios.3.call_admission_control, null)
      call_capacity                 = try(each.value.radios.3.call_capacity, null)
      bandwidth_admission_control   = try(each.value.radios.3.bandwidth_admission_control, null)
      bandwidth_capacity            = try(each.value.radios.3.bandwidth_capacity, null)

      dynamic vaps {
        for_each  = { for vap in try(each.value.radios.3.vaps, []) : vap => vap }
        content {
          name    = vaps.value
        }
      }

      dynamic channel {
        for_each  = { for channel in try(each.value.radios.3.channels, []) : channel => channel }
        content {
          chan    = channel.value
        }
      }
    }
  }
  dynamic radio_4 {
    for_each                        = { for a in (try(each.value.radios.4, []) == [] ? [] : ["1"]) : a => a}
    content {
      mode                          = try(each.value.radios.4.mode, null)
      band                          = try(each.value.radios.4.band, null)
      band_5g_type                  = try(each.value.radios.4.band_5g_type, null)
      drma                          = try(each.value.radios.4.drma, null)
      drma_sensitivity              = try(each.value.radios.4.drma_sensitivity, null)
      airtime_fairness              = try(each.value.radios.4.airtime_fairness, null)
      protection_mode               = try(each.value.radios.4.protection_mode, null)
      powersave_optimize            = try(each.value.radios.4.powersave_optimize, null)
      transmit_optimize             = try(each.value.radios.4.transmit_optimize, null)
      amsdu                         = try(each.value.radios.4.amsdu, null)
      coexistence                   = try(each.value.radios.4.coexistence, null)
      zero_wait_dfs                 = try(each.value.radios.4.zero_wait_dfs, null)
      bss_color                     = try(each.value.radios.4.bss_color, null)
      bss_color_mode                = try(each.value.radios.4.bss_color_mode, null)
      short_guard_interval          = try(each.value.radios.4.short_guard_interval, null)
      mimo_mode                     = try(each.value.radios.4.mimo_mode, null)
      channel_bonding               = try(each.value.radios.4.channel_bonding, null)
      channel_bonding_ext           = try(each.value.radios.4.channel_bonding_ext, null)
      optional_antenna              = try(each.value.radios.4.optional_antenna, null)
      optional_antenna_gain         = try(each.value.radios.4.optional_antenna_gain, null)
      auto_power_level              = try(each.value.radios.4.auto_power_level, null)
      auto_power_high               = try(each.value.radios.4.auto_power_high, null)
      auto_power_low                = try(each.value.radios.4.auto_power_low, null)
      auto_power_target             = try(each.value.radios.4.auto_power_target, null)
      power_mode                    = try(each.value.radios.4.power_mode, null)
      power_level                   = try(each.value.radios.4.power_level, null)
      power_value                   = try(each.value.radios.4.power_value, null)
      dtim                          = try(each.value.radios.4.dtim, null)
      beacon_interval               = try(each.value.radios.4.beacon_interval, null)
      n80211d                       = try(each.value.radios.4.n80211d, null)
      n80211mc                      = try(each.value.radios.4.n80211mc, null)
      rts_threshold                 = try(each.value.radios.4.rts_threshold, null)
      frag_threshold                = try(each.value.radios.4.frag_threshold, null)
      ap_sniffer_bufsize            = try(each.value.radios.4.ap_sniffer_bufsize, null)
      ap_sniffer_chan               = try(each.value.radios.4.ap_sniffer_chan, null)
      ap_sniffer_chan_width         = try(each.value.radios.4.ap_sniffer_chan_width, null)
      ap_sniffer_addr               = try(each.value.radios.4.ap_sniffer_addr, null)
      ap_sniffer_mgmt_beacon        = try(each.value.radios.4.ap_sniffer_mgmt_beacon, null)
      ap_sniffer_mgmt_probe         = try(each.value.radios.4.ap_sniffer_mgmt_probe, null)
      ap_sniffer_mgmt_other         = try(each.value.radios.4.ap_sniffer_mgmt_other, null)
      ap_sniffer_ctl                = try(each.value.radios.4.ap_sniffer_ctl, null)
      ap_sniffer_data               = try(each.value.radios.4.ap_sniffer_data, null)
      sam_ssid                      = try(each.value.radios.4.sam_ssid, null)
      sam_bssid                     = try(each.value.radios.4.sam_bssid, null)
      sam_security_type             = try(each.value.radios.4.sam_security_type, null)
      sam_captive_portal            = try(each.value.radios.4.sam_captive_portal, null)
      sam_cwp_username              = try(each.value.radios.4.sam_cwp_username, null)
      sam_cwp_password              = try(each.value.radios.4.sam_cwp_password, null)
      sam_cwp_test_url              = try(each.value.radios.4.sam_cwp_test_url, null)
      sam_cwp_match_string          = try(each.value.radios.4.sam_cwp_match_string, null)
      sam_cwp_success_string        = try(each.value.radios.4.sam_cwp_success_string, null)
      sam_cwp_failure_string        = try(each.value.radios.4.sam_cwp_failure_string, null)
      sam_eap_method                = try(each.value.radios.4.sam_eap_method, null)
      sam_client_certificate        = try(each.value.radios.4.sam_client_certificate, null)
      sam_private_key               = try(each.value.radios.4.sam_private_key, null)
      sam_private_key_password      = try(each.value.radios.4.sam_private_key_password, null)
      sam_ca_certificate            = try(each.value.radios.4.sam_ca_certificate, null)
      sam_username                  = try(each.value.radios.4.sam_username, null)
      sam_password                  = try(each.value.radios.4.sam_password, null)
      sam_test                      = try(each.value.radios.4.sam_test, null)
      sam_server_type               = try(each.value.radios.4.sam_server_type, null)
      sam_server_ip                 = try(each.value.radios.4.sam_server_ip, null)
      sam_server_fqdn               = try(each.value.radios.4.sam_server_fqdn, null)
      iperf_server_port             = try(each.value.radios.4.iperf_server_port, null)
      iperf_protocol                = try(each.value.radios.4.iperf_protocol, null)
      sam_report_intv               = try(each.value.radios.4.sam_report_intv, null)
      channel_utilization           = try(each.value.radios.4.channel_utilization, null)
      spectrum_analysis             = try(each.value.radios.4.spectrum_analysis, null)
      wids_profile                  = try(each.value.radios.4.wids_profile, null)
      darrp                         = try(each.value.radios.4.darrp, null)
      arrp_profile                  = try(each.value.radios.4.arrp_profile, null)
      max_clients                   = try(each.value.radios.4.max_clients, null)
      max_distance                  = try(each.value.radios.4.max_distance, null)
      frequency_handoff             = try(each.value.radios.4.frequency_handoff, null)
      ap_handoff                    = try(each.value.radios.4.ap_handoff, null)
      vap_all                       = try(each.value.radios.4.vap_all, null)
      call_admission_control        = try(each.value.radios.4.call_admission_control, null)
      call_capacity                 = try(each.value.radios.4.call_capacity, null)
      bandwidth_admission_control   = try(each.value.radios.4.bandwidth_admission_control, null)
      bandwidth_capacity            = try(each.value.radios.4.bandwidth_capacity, null)

      dynamic vaps {
        for_each  = { for vap in try(each.value.radios.4.vaps, []) : vap => vap }
        content {
          name    = vaps.value
        }
      }

      dynamic channel {
        for_each  = { for channel in try(each.value.radios.4.channels, []) : channel => channel }
        content {
          chan    = channel.value
        }
      }
    }
  }

}

resource fortios_wirelesscontroller_vap vaps {
  for_each                                  = { for ssid, settings in try(local.wireless_yaml.ssids, []) : ssid => settings}
  name                                      = each.key
  pre_auth                                  = try(each.value.pre_auth, null)
  external_pre_auth                         = try(each.value.external_pre_auth, null)
  fast_roaming                              = try(each.value.fast_roaming, null)
  external_fast_roaming                     = try(each.value.external_fast_roaming, null)
  mesh_backhaul                             = try(each.value.mesh_backhaul, null)
  atf_weight                                = try(each.value.atf_weight, null)
  max_clients                               = try(each.value.max_clients, null)
  max_clients_ap                            = try(each.value.max_clients_ap, null)
  ssid                                      = try(each.value.ssid, each.key)
  broadcast_ssid                            = try(each.value.broadcast_ssid, null)
  security_obsolete_option                  = try(each.value.security_obsolete_option, null)
  security                                  = try(each.value.security, null)
  pmf                                       = try(each.value.pmf, null)
  pmf_assoc_comeback_timeout                = try(each.value.pmf_assoc_comeback_timeout, null)
  pmf_sa_query_retry_timeout                = try(each.value.pmf_sa_query_retry_timeout, null)
  beacon_protection                         = try(each.value.beacon_protection, null)
  okc                                       = try(each.value.okc, null)
  mbo                                       = try(each.value.mbo, null)
  gas_comeback_delay                        = try(each.value.gas_comeback_delay, null)
  gas_fragmentation_limit                   = try(each.value.gas_fragmentation_limit, null)
  mbo_cell_data_conn_pref                   = try(each.value.mbo_cell_data_conn_pref, null)
  n80211k                                   = try(each.value.n80211k, null)
  n80211v                                   = try(each.value.n80211v, null)
  voice_enterprise                          = try(each.value.voice_enterprise, null)
  neighbor_report_dual_band                 = try(each.value.neighbor_report_dual_band, null)
  fast_bss_transition                       = try(each.value.fast_bss_transition, null)
  ft_mobility_domain                        = try(each.value.ft_mobility_domain, null)
  ft_r0_key_lifetime                        = try(each.value.ft_r0_key_lifetime, null)
  ft_over_ds                                = try(each.value.ft_over_ds, null)
  sae_groups                                = try(each.value.sae_groups, null)
  owe_groups                                = try(each.value.owe_groups, null)
  owe_transition                            = try(each.value.owe_transition, null)
  owe_transition_ssid                       = try(each.value.owe_transition_ssid, null)
  additional_akms                           = try(each.value.additional_akms, null)
  eapol_key_retries                         = try(each.value.eapol_key_retries, null)
  tkip_counter_measure                      = try(each.value.tkip_counter_measure, null)
  external_web                              = try(each.value.external_web, null)
  external_web_format                       = try(each.value.external_web_format, null)
  external_logout                           = try(each.value.external_logout, null)
  mac_username_delimiter                    = try(each.value.mac_username_delimiter, null)
  mac_password_delimiter                    = try(each.value.mac_password_delimiter, null)
  mac_calling_station_delimiter             = try(each.value.mac_calling_station_delimiter, null)
  mac_called_station_delimiter              = try(each.value.mac_called_station_delimiter, null)
  mac_case                                  = try(each.value.mac_case, null)
  called_station_id_type                    = try(each.value.called_station_id_type, null)
  mac_auth_bypass                           = try(each.value.mac_auth_bypass, null)
  radius_mac_auth                           = try(each.value.radius_mac_auth, null)
  radius_mac_auth_server                    = try(each.value.radius_mac_auth_server, null)
  radius_mac_auth_block_interval            = try(each.value.radius_mac_auth_block_interval, null)
  radius_mac_mpsk_auth                      = try(each.value.radius_mac_mpsk_auth, null)
  radius_mac_mpsk_timeout                   = try(each.value.radius_mac_mpsk_timeout, null)
  auth                                      = try(each.value.auth, null)
  encrypt                                   = try(each.value.encrypt, null)
  keyindex                                  = try(each.value.keyindex, null)
  key                                       = try(each.value.key, null)
  passphrase                                = try(each.value.passphrase, null)
  sae_password                              = try(each.value.sae_password, null)
  sae_h2e_only                              = try(each.value.sae_h2e_only, null)
  sae_hnp_only                              = try(each.value.sae_hnp_only, null)
  sae_pk                                    = try(each.value.sae_pk, null)
  sae_private_key                           = try(each.value.sae_private_key, null)
  akm24_only                                = try(each.value.akm24_only, null)
  radius_server                             = try(each.value.radius_server, null)
  nas_filter_rule                           = try(each.value.nas_filter_rule, null)
  domain_name_stripping                     = try(each.value.domain_name_stripping, null)
  acct_interim_interval                     = try(each.value.acct_interim_interval, null)
  local_standalone                          = try(each.value.local_standalone, null)
  local_standalone_nat                      = try(each.value.local_standalone_nat, null)
  ip                                        = try(each.value.ip, null)
  dhcp_lease_time                           = try(each.value.dhcp_lease_time, null)
  local_standalone_dns                      = try(each.value.local_standalone_dns, null)
  local_standalone_dns_ip                   = try(each.value.local_standalone_dns_ip, null)
  local_lan_partition                       = try(each.value.local_lan_partition, null)
  local_bridging                            = try(each.value.local_bridging, null)
  local_lan                                 = try(each.value.local_lan, null)
  local_authentication                      = try(each.value.local_authentication, null)
  portal_message_override_group             = try(each.value.portal_message_override_group, null)
  portal_type                               = try(each.value.portal_type, null)
  security_exempt_list                      = try(each.value.security_exempt_list, null)
  security_redirect_url                     = try(each.value.security_redirect_url, null)
  auth_cert                                 = try(each.value.auth_cert, null)
  auth_portal_addr                          = try(each.value.auth_portal_addr, null)
  intra_vap_privacy                         = try(each.value.intra_vap_privacy, null)
  schedule                                  = try(each.value.schedule, null)
  ldpc                                      = try(each.value.ldpc, null)
  high_efficiency                           = try(each.value.high_efficiency, null)
  target_wake_time                          = try(each.value.target_wake_time, null)
  port_macauth                              = try(each.value.port_macauth, null)
  port_macauth_timeout                      = try(each.value.port_macauth_timeout, null)
  port_macauth_reauth_timeout               = try(each.value.port_macauth_reauth_timeout, null)
  bss_color_partial                         = try(each.value.bss_color_partial, null)
  mpsk_profile                              = try(each.value.mpsk_profile, null)
  mpsk                                      = try(each.value.mpsk, null)
  mpsk_concurrent_clients                   = try(each.value.mpsk_concurrent_clients, null)
  split_tunneling                           = try(each.value.split_tunneling, null)
  nac                                       = try(each.value.nac, null)
  nac_profile                               = try(each.value.nac_profile, null)
  vlanid                                    = try(each.value.vlanid, null)
  vlan_auto                                 = try(each.value.vlan_auto, null)
  dynamic_vlan                              = try(each.value.dynamic_vlan, null)
  captive_portal                            = try(each.value.captive_portal, null)
  captive_network_assistant_bypass          = try(each.value.captive_network_assistant_bypass, null)
  captive_portal_fw_accounting              = try(each.value.captive_portal_fw_accounting, null)
  captive_portal_radius_server              = try(each.value.captive_portal_radius_server, null)
  captive_portal_radius_secret              = try(each.value.captive_portal_radius_secret, null)
  captive_portal_macauth_radius_server      = try(each.value.captive_portal_macauth_radius_server, null)
  captive_portal_macauth_radius_secret      = try(each.value.captive_portal_macauth_radius_secret, null)
  captive_portal_ac_name                    = try(each.value.captive_portal_ac_name, null)
  captive_portal_auth_timeout               = try(each.value.captive_portal_auth_timeout, null)
  captive_portal_session_timeout_interval   = try(each.value.captive_portal_session_timeout_interval, null)
  alias                                     = try(each.value.alias, null)
  multicast_rate                            = try(each.value.multicast_rate, null)
  multicast_enhance                         = try(each.value.multicast_enhance, null)
  igmp_snooping                             = try(each.value.igmp_snooping, null)
  dhcp_address_enforcement                  = try(each.value.dhcp_address_enforcement, null)
  broadcast_suppression                     = try(each.value.broadcast_suppression, null)
  ipv6_rules                                = try(each.value.ipv6_rules, null)
  me_disable_thresh                         = try(each.value.me_disable_thresh, null)
  mu_mimo                                   = try(each.value.mu_mimo, null)
  probe_resp_suppression                    = try(each.value.probe_resp_suppression, null)
  probe_resp_threshold                      = try(each.value.probe_resp_threshold, null)
  radio_sensitivity                         = try(each.value.radio_sensitivity, null)
  quarantine                                = try(each.value.quarantine, null)
  radio_5g_threshold                        = try(each.value.radio_5g_threshold, null)
  radio_2g_threshold                        = try(each.value.radio_2g_threshold, null)
  vlan_pooling                              = try(each.value.vlan_pooling, null)
  dhcp_option43_insertion                   = try(each.value.dhcp_option43_insertion, null)
  dhcp_option82_insertion                   = try(each.value.dhcp_option82_insertion, null)
  dhcp_option82_circuit_id_insertion        = try(each.value.dhcp_option82_circuit_id_insertion, null)
  dhcp_option82_remote_id_insertion         = try(each.value.dhcp_option82_remote_id_insertion, null)
  ptk_rekey                                 = try(each.value.ptk_rekey, null)
  ptk_rekey_intv                            = try(each.value.ptk_rekey_intv, null)
  gtk_rekey                                 = try(each.value.gtk_rekey, null)
  gtk_rekey_intv                            = try(each.value.gtk_rekey_intv, null)
  eap_reauth                                = try(each.value.eap_reauth, null)
  eap_reauth_intv                           = try(each.value.eap_reauth_intv, null)
  roaming_acct_interim_update               = try(each.value.roaming_acct_interim_update, null)
  qos_profile                               = try(each.value.qos_profile, null)
  hotspot20_profile                         = try(each.value.hotspot20_profile, null)
  access_control_list                       = try(each.value.access_control_list, null)
  primary_wag_profile                       = try(each.value.primary_wag_profile, null)
  secondary_wag_profile                     = try(each.value.secondary_wag_profile, null)
  tunnel_echo_interval                      = try(each.value.tunnel_echo_interval, null)
  tunnel_fallback_interval                  = try(each.value.tunnel_fallback_interval, null)
  rates_11a                                 = try(each.value.rates_11a, null)
  rates_11bg                                = try(each.value.rates_11bg, null)
  rates_11n_ss12                            = try(each.value.rates_11n_ss12, null)
  rates_11n_ss34                            = try(each.value.rates_11n_ss34, null)
  rates_11ac_mcs_map                        = try(each.value.rates_11ac_mcs_map, null)
  rates_11ax_mcs_map                        = try(each.value.rates_11ax_mcs_map, null)
  rates_11be_mcs_map                        = try(each.value.rates_11be_mcs_map, null)
  rates_11be_mcs_map_160                    = try(each.value.rates_11be_mcs_map_160, null)
  rates_11be_mcs_map_320                    = try(each.value.rates_11be_mcs_map_320, null)
  rates_11ac_ss12                           = try(each.value.rates_11ac_ss12, null)
  rates_11ac_ss34                           = try(each.value.rates_11ac_ss34, null)
  rates_11ax_ss12                           = try(each.value.rates_11ax_ss12, null)
  rates_11ax_ss34                           = try(each.value.rates_11ax_ss34, null)
  utm_profile                               = try(each.value.utm_profile, null)
  utm_status                                = try(each.value.utm_status, null)
  utm_log                                   = try(each.value.utm_log, null)
  ips_sensor                                = try(each.value.ips_sensor, null)
  application_list                          = try(each.value.application_list, null)
  antivirus_profile                         = try(each.value.antivirus_profile, null)
  webfilter_profile                         = try(each.value.webfilter_profile, null)
  scan_botnet_connections                   = try(each.value.scan_botnet_connections, null)
  address_group                             = try(each.value.address_group, null)
  address_group_policy                      = try(each.value.address_group_policy, null)
  mac_filter                                = try(each.value.mac_filter, null)
  mac_filter_policy_other                   = try(each.value.mac_filter_policy_other, null)
  sticky_client_remove                      = try(each.value.sticky_client_remove, null)
  sticky_client_threshold_5g                = try(each.value.sticky_client_threshold_5g, null)
  sticky_client_threshold_2g                = try(each.value.sticky_client_threshold_2g, null)
  sticky_client_threshold_6g                = try(each.value.sticky_client_threshold_6g, null)
  bstm_rssi_disassoc_timer                  = try(each.value.bstm_rssi_disassoc_timer, null)
  bstm_load_balancing_disassoc_timer        = try(each.value.bstm_load_balancing_disassoc_timer, null)
  bstm_disassociation_imminent              = try(each.value.bstm_disassociation_imminent, null)
  beacon_advertising                        = try(each.value.beacon_advertising, null)
  osen                                      = try(each.value.osen, null)
  application_detection_engine              = try(each.value.application_detection_engine, null)
  application_dscp_marking                  = try(each.value.application_dscp_marking, null)
  application_report_intv                   = try(each.value.application_report_intv, null)
  l3_roaming                                = try(each.value.l3_roaming, null)
  l3_roaming_mode                           = try(each.value.l3_roaming_mode, null)


  dynamic radius_mac_auth_usergroups {
    for_each    = { for item in try(each.value.radius_mac_auth_usergroups, []) : item => item }
    content {
      name      = radius_mac_auth_usergroups.value
    }
  }
  dynamic usergroup {
    for_each    = { for item in try(each.value.usergroups, []) : item => item }
    content {
      name      = usergroup.value
    }
  }
  dynamic selected_usergroups {
    for_each    = { for item in try(each.value.selected_usergroups, []) : item => item }
    content {
      name      = selected_usergroups.value
    }
  }
  dynamic vlan_name {
    for_each    = { for key, item in try(each.value.vlans, []) : key => item }
    content {
      name      = vlan_name.key
      vlan_id   = vlan_name.item
    }
  }
}

resource fortios_wirelesscontroller_vapgroup vapgroups {
  for_each      = { for name, group in try(local.wireless_yaml.ssid_groups, []) : name => group }
  name          = each.key
  comment       = try(each.value.comment, null)
  dynamic vaps {
    for_each    = { for vap in try(each.value.ssids, []) : vap => vap }
    content {
      name      = vaps.value
    }
  }
}
