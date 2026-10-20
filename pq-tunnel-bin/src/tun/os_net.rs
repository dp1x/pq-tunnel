//! OS networking lifecycle: routes, DNS, firewall, journaling, rollback (D33 §2.3-2.7).
//!
//! Pure logic + command generation. Platform commands are returned as strings
//! so they can be unit-tested without executing privileged operations. A
//! single [`Journal`] records every mutation for reversible teardown.

/// A journal entry recording one mutation that must be reversed on teardown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalEntry {
    Route {
        family: u8,
        dst: String,
        iface: String,
        metric: u32,
    },
    Rule {
        family: u8,
        priority: u32,
        spec: String,
    },
    Dns {
        iface: String,
        previous: Vec<String>,
    },
    FirewallRule {
        name: String,
    },
    InterfaceAddress {
        iface: String,
        addr: String,
    },
    KillSwitch {
        level: u8,
    },
}

#[derive(Debug, Default, Clone)]
pub struct Journal {
    pub entries: Vec<JournalEntry>,
}

impl Journal {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn record(&mut self, e: JournalEntry) {
        self.entries.push(e);
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Linux: commands to install policy routing (destination exception).
pub fn linux_install_routes(
    server_v4: &str,
    server_v6: &str,
    tun_iface: &str,
    phys_iface: &str,
) -> Vec<String> {
    let mut cmds = Vec::new();
    cmds.push(format!("ip link set dev {tun_iface} up"));
    cmds.push(format!("ip addr add 10.77.0.2/32 dev {tun_iface}"));
    cmds.push(format!("ip -6 addr add fd00:77::2/128 dev {tun_iface}"));
    cmds.push(format!("ip route replace {server_v4}/32 dev {phys_iface}"));
    cmds.push(format!(
        "ip -6 route replace {server_v6}/128 dev {phys_iface}"
    ));
    cmds.push(format!("ip route add default dev {tun_iface} table 100"));
    cmds.push(format!("ip -6 route add default dev {tun_iface} table 100"));
    cmds.push(format!(
        "ip rule add priority 100 to {server_v4}/32 lookup main"
    ));
    cmds.push(format!(
        "ip -6 rule add priority 100 to {server_v6}/128 lookup main"
    ));
    cmds.push("ip rule add priority 200 lookup 100".to_string());
    cmds.push("ip -6 rule add priority 200 lookup 100".to_string());
    cmds.push("ip rule add priority 101 table main suppress_prefixlength 0".to_string());
    cmds
}

/// Linux: teardown commands (reverse order).
pub fn linux_teardown_routes(tun_iface: &str, server_v4: &str, server_v6: &str) -> Vec<String> {
    let mut cmds = Vec::new();
    cmds.push("ip rule del priority 200".to_string());
    cmds.push("ip -6 rule del priority 200".to_string());
    cmds.push("ip rule del priority 101".to_string());
    cmds.push(format!(
        "ip rule del priority 100 to {server_v4}/32 lookup main"
    ));
    cmds.push(format!(
        "ip -6 rule del priority 100 to {server_v6}/128 lookup main"
    ));
    cmds.push(format!("ip route del default dev {tun_iface} table 100"));
    cmds.push(format!("ip -6 route del default dev {tun_iface} table 100"));
    cmds.push(format!("ip link set dev {tun_iface} down"));
    cmds
}

/// Linux DNS via resolvectl.
pub fn linux_dns_apply(iface: &str, dns: &str) -> Vec<String> {
    vec![
        format!("resolvectl dns {iface} {dns}"),
        format!("resolvectl domain {iface} ~."),
    ]
}
pub fn linux_dns_revert(iface: &str) -> Vec<String> {
    vec![format!("resolvectl revert {iface}")]
}

/// Linux kill-switch L2: blackhole rule.
pub fn linux_killswitch_install(server_v4: &str, server_v6: &str) -> Vec<String> {
    vec![
        "ip rule add priority 110 blackhole".to_string(),
        format!("ip rule add priority 100 to {server_v4}/32 lookup main"),
        format!("ip -6 rule add priority 100 to {server_v6}/128 lookup main"),
    ]
}
pub fn linux_killswitch_remove() -> Vec<String> {
    vec!["ip rule del priority 110".to_string()]
}

/// Windows: route installation via New-NetRoute.
pub fn windows_install_routes(
    server_v4: &str,
    server_v6: &str,
    tun_idx: u32,
    phys_idx: u32,
    phys_gw: &str,
) -> Vec<String> {
    let mut cmds = Vec::new();
    cmds.push(format!("New-NetRoute -DestinationPrefix \"{server_v4}/32\" -InterfaceIndex {phys_idx} -NextHop {phys_gw} -RouteMetric 1 -PolicyStore ActiveStore"));
    cmds.push(format!("New-NetRoute -DestinationPrefix \"{server_v6}/128\" -InterfaceIndex {phys_idx} -NextHop {phys_gw} -RouteMetric 1 -PolicyStore ActiveStore"));
    cmds.push(format!("New-NetRoute -DestinationPrefix \"0.0.0.0/0\" -InterfaceIndex {tun_idx} -NextHop 0.0.0.0 -RouteMetric 0 -PolicyStore ActiveStore"));
    cmds.push(format!("New-NetRoute -DestinationPrefix \"::/0\" -InterfaceIndex {tun_idx} -NextHop :: -RouteMetric 0 -PolicyStore ActiveStore"));
    cmds.push(format!(
        "Set-NetIPInterface -InterfaceIndex {tun_idx} -InterfaceMetric 1"
    ));
    cmds
}

/// Windows DNS.
pub fn windows_dns_apply(iface_idx: u32, dns: &str) -> Vec<String> {
    vec![format!(
        "Set-DnsClientServerAddress -InterfaceIndex {iface_idx} -ServerAddresses {dns}"
    )]
}
pub fn windows_dns_revert(iface_idx: u32) -> Vec<String> {
    vec![format!(
        "Set-DnsClientServerAddress -InterfaceIndex {iface_idx} -ResetServerAddresses"
    )]
}

/// Windows firewall kill-switch: default outbound block + allow server.
pub fn windows_killswitch_install(server_v4: &str, server_port: u16) -> Vec<String> {
    vec![
        "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block"
            .to_string(),
        format!(
            "New-NetFirewallRule -DisplayName \"pq-tunnel-server\" -Direction Outbound -RemoteAddress {server_v4} -Protocol UDP -RemotePort {server_port} -Action Allow"
        ),
    ]
}
pub fn windows_killswitch_remove() -> Vec<String> {
    vec![
        "Remove-NetFirewallRule -DisplayName \"pq-tunnel-server\"".to_string(),
        "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow"
            .to_string(),
    ]
}

/// Reconcile stale default routes bound to non-existent interfaces.
pub fn reconcile_stale_routes(existing_default_ifaces: &[u32], live_ifaces: &[u32]) -> Vec<u32> {
    existing_default_ifaces
        .iter()
        .copied()
        .filter(|i| !live_ifaces.contains(i))
        .collect()
}

/// Journal-based rollback helper: reverse entries.
pub fn rollback_plan(journal: &Journal) -> Vec<String> {
    let mut out = Vec::new();
    for e in journal.entries.iter().rev() {
        match e {
            JournalEntry::Route { dst, iface, .. } => {
                out.push(format!("remove route {dst} dev {iface}"))
            }
            JournalEntry::Rule { priority, .. } => {
                out.push(format!("remove rule priority {priority}"))
            }
            JournalEntry::Dns { iface, .. } => out.push(format!("revert dns {iface}")),
            JournalEntry::FirewallRule { name } => out.push(format!("remove firewall rule {name}")),
            JournalEntry::InterfaceAddress { iface, addr } => {
                out.push(format!("remove addr {addr} dev {iface}"))
            }
            JournalEntry::KillSwitch { level } => {
                out.push(format!("remove killswitch level {level}"))
            }
        }
    }
    out
}

/// Validate that an inner IP packet's declared length matches its bytes.
pub fn ip_ok(pkt: &[u8]) -> bool {
    crate::tun::validate_inner(pkt)
}

/// Check source anti-spoof via tun_policy.
pub fn source_ok(pkt: &[u8]) -> bool {
    let assignment = crate::tun_policy::ClientAssignment::default();
    match crate::tun_policy::extract_src_ip(pkt) {
        Some(src) => crate::tun_policy::source_allowed(src, &assignment),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_install_contains_bypass_before_default() {
        let cmds = linux_install_routes("1.2.3.4", "2001:db8::1", "pqtun0", "eth0");
        let bypass_pos = cmds
            .iter()
            .position(|c| c.contains("route replace 1.2.3.4"))
            .unwrap();
        let default_pos = cmds
            .iter()
            .position(|c| c.contains("route add default"))
            .unwrap();
        assert!(bypass_pos < default_pos);
    }

    #[test]
    fn linux_install_has_policy_rules() {
        let cmds = linux_install_routes("1.2.3.4", "2001:db8::1", "pqtun0", "eth0");
        assert!(
            cmds.iter()
                .any(|c| c.contains("rule add priority 100 to 1.2.3.4"))
        );
        assert!(cmds.iter().any(|c| c.contains("suppress_prefixlength 0")));
    }

    #[test]
    fn windows_install_bypass_first() {
        let cmds = windows_install_routes("1.2.3.4", "2001:db8::1", 5, 3, "192.168.1.1");
        let bypass_pos = cmds.iter().position(|c| c.contains("1.2.3.4/32")).unwrap();
        let default_pos = cmds.iter().position(|c| c.contains("0.0.0.0/0")).unwrap();
        assert!(bypass_pos < default_pos);
    }

    #[test]
    fn reconcile_stale() {
        let stale = reconcile_stale_routes(&[2, 5, 9], &[1, 2, 3]);
        assert_eq!(stale, vec![5, 9]);
    }

    #[test]
    fn rollback_reverse_order() {
        let mut j = Journal::new();
        j.record(JournalEntry::Route {
            family: 4,
            dst: "default".into(),
            iface: "tun0".into(),
            metric: 0,
        });
        j.record(JournalEntry::Dns {
            iface: "tun0".into(),
            previous: vec![],
        });
        let plan = rollback_plan(&j);
        assert!(plan[0].contains("revert dns"));
        assert!(plan[1].contains("remove route"));
    }

    #[test]
    fn windows_killswitch_has_default_block() {
        let cmds = windows_killswitch_install("1.2.3.4", 4433);
        assert!(
            cmds.iter()
                .any(|c| c.contains("DefaultOutboundAction Block"))
        );
        assert!(cmds.iter().any(|c| c.contains("Action Allow")));
    }
}
