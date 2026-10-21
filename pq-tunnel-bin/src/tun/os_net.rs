//! OS networking lifecycle: routes, DNS, firewall, journaling, rollback (D33 §2.3-2.7).
//!
//! Pure logic + command generation. Platform commands are returned as strings
//! so they can be unit-tested without executing privileged operations. A
//! single [`Journal`] records every mutation for reversible teardown.
//!
//! Execution helpers ([`run_command`], [`run_commands`], ...) are provided for
//! the privileged runtime, but every mutating call is checked: a non-zero exit
//! status is reported, never swallowed.

use std::process::Command;

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

/// Run one shell command, returning an error on non-zero exit or spawn failure.
pub fn run_command(cmd: &str) -> Result<(), String> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .map_err(|e| format!("failed to spawn `{cmd}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed (exit {status}): {cmd}"))
    }
}

/// Run every command, stopping at the first failure.
pub fn run_commands(cmds: &[String]) -> Result<(), String> {
    for c in cmds {
        run_command(c)?;
    }
    Ok(())
}

/// Alias kept for callers that expect an "apply" spelling.
pub fn apply_commands(cmds: &[String]) -> Result<(), String> {
    run_commands(cmds)
}

/// Alias kept for callers that expect a "checked" spelling.
pub fn run_checked(cmds: &[String]) -> Result<(), String> {
    run_commands(cmds)
}

/// Apply `setup`; on any failure run `teardown` (best effort) and return the error.
pub fn run_with_rollback(setup: &[String], teardown: &[String]) -> Result<(), String> {
    for c in setup {
        if let Err(e) = run_command(c) {
            for t in teardown {
                let _ = run_command(t);
            }
            return Err(e);
        }
    }
    Ok(())
}

/// Discover the physical interface (and optional gateway) used to reach `remote`.
///
/// Uses `ip route get`, which does not mutate the routing table. Returns
/// `(iface, gateway)` where `gateway` is `None` when the destination is on-link.
pub fn discover_physical_route(remote: &str) -> Result<(String, Option<String>), String> {
    let family = if remote.contains(':') { "-6" } else { "-4" };
    let out = Command::new("ip")
        .args([family, "route", "get", remote])
        .output()
        .map_err(|e| format!("ip route get failed to spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ip route get {remote} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut iface: Option<String> = None;
    let mut gateway: Option<String> = None;
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let mut i = 0usize;
    while i < tokens.len() {
        match tokens[i] {
            "dev" => {
                if i + 1 < tokens.len() {
                    iface = Some(tokens[i + 1].to_string());
                }
                i += 2;
            }
            "via" => {
                if i + 1 < tokens.len() {
                    gateway = Some(tokens[i + 1].to_string());
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    match iface {
        Some(i) => Ok((i, gateway)),
        None => Err(format!(
            "could not discover physical interface for {remote}"
        )),
    }
}

/// Linux: commands to install policy routing (destination exception).
///
/// `server_v4` / `server_v6` may be empty when the remote has no address in
/// that family; the corresponding family-specific commands are then omitted
/// instead of reusing an IPv4 literal in an IPv6 command.
pub fn linux_install_routes(
    server_v4: &str,
    server_v6: &str,
    tun_iface: &str,
    phys_iface: &str,
) -> Vec<String> {
    linux_install_routes_with_gateway(server_v4, server_v6, tun_iface, phys_iface, None, None)
}

/// Like [`linux_install_routes`] but allows a gateway for the bypass host route.
pub fn linux_install_routes_with_gateway(
    server_v4: &str,
    server_v6: &str,
    tun_iface: &str,
    phys_iface: &str,
    gateway_v4: Option<&str>,
    gateway_v6: Option<&str>,
) -> Vec<String> {
    let mut cmds = Vec::new();
    cmds.push(format!("ip link set dev {tun_iface} up"));
    cmds.push(format!("ip addr add 10.77.0.2/32 dev {tun_iface}"));
    cmds.push(format!("ip -6 addr add fd00:77::2/128 dev {tun_iface}"));

    if !server_v4.is_empty() {
        let bypass = match gateway_v4 {
            Some(gw) => format!("ip route replace {server_v4}/32 via {gw} dev {phys_iface}"),
            None => format!("ip route replace {server_v4}/32 dev {phys_iface}"),
        };
        cmds.push(bypass);
    }
    if !server_v6.is_empty() {
        let bypass = match gateway_v6 {
            Some(gw) => format!("ip -6 route replace {server_v6}/128 via {gw} dev {phys_iface}"),
            None => format!("ip -6 route replace {server_v6}/128 dev {phys_iface}"),
        };
        cmds.push(bypass);
    }

    cmds.push(format!("ip route add default dev {tun_iface} table 100"));
    cmds.push(format!("ip -6 route add default dev {tun_iface} table 100"));

    if !server_v4.is_empty() {
        cmds.push(format!(
            "ip rule add priority 100 to {server_v4}/32 lookup main"
        ));
    }
    if !server_v6.is_empty() {
        cmds.push(format!(
            "ip -6 rule add priority 100 to {server_v6}/128 lookup main"
        ));
    }
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
    if !server_v4.is_empty() {
        cmds.push(format!(
            "ip rule del priority 100 to {server_v4}/32 lookup main"
        ));
    }
    if !server_v6.is_empty() {
        cmds.push(format!(
            "ip -6 rule del priority 100 to {server_v6}/128 lookup main"
        ));
    }
    cmds.push(format!("ip route del default dev {tun_iface} table 100"));
    cmds.push(format!("ip -6 route del default dev {tun_iface} table 100"));
    if !server_v4.is_empty() {
        cmds.push(format!("ip route del {server_v4}/32"));
    }
    if !server_v6.is_empty() {
        cmds.push(format!("ip -6 route del {server_v6}/128"));
    }
    cmds.push(format!("ip addr del 10.77.0.2/32 dev {tun_iface}"));
    cmds.push(format!("ip -6 addr del fd00:77::2/128 dev {tun_iface}"));
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

/// Linux kill-switch L2: blackhole rule (bypass already installed at priority 100).
pub fn linux_killswitch_install(server_v4: &str, server_v6: &str) -> Vec<String> {
    let mut cmds = Vec::new();
    cmds.push("ip rule add priority 110 blackhole".to_string());
    if !server_v4.is_empty() {
        cmds.push(format!(
            "ip rule add priority 100 to {server_v4}/32 lookup main"
        ));
    }
    if !server_v6.is_empty() {
        cmds.push(format!(
            "ip -6 rule add priority 100 to {server_v6}/128 lookup main"
        ));
    }
    cmds
}
pub fn linux_killswitch_remove() -> Vec<String> {
    vec!["ip rule del priority 110".to_string()]
}

/// Server-side Linux helpers.
pub fn linux_server_install(
    tun_iface: &str,
    client_v4_cidr: &str,
    client_v6_cidr: &str,
) -> Vec<String> {
    let mut cmds = Vec::new();
    cmds.push(format!("ip link set dev {tun_iface} up"));
    if !client_v4_cidr.is_empty() {
        cmds.push(format!("ip addr add {client_v4_cidr} dev {tun_iface}"));
    }
    if !client_v6_cidr.is_empty() {
        cmds.push(format!("ip -6 addr add {client_v6_cidr} dev {tun_iface}"));
    }
    cmds
}

pub fn linux_server_teardown(
    tun_iface: &str,
    client_v4_cidr: &str,
    client_v6_cidr: &str,
) -> Vec<String> {
    let mut cmds = Vec::new();
    if !client_v4_cidr.is_empty() {
        cmds.push(format!("ip addr del {client_v4_cidr} dev {tun_iface}"));
    }
    if !client_v6_cidr.is_empty() {
        cmds.push(format!("ip -6 addr del {client_v6_cidr} dev {tun_iface}"));
    }
    cmds.push(format!("ip link set dev {tun_iface} down"));
    cmds
}

pub fn linux_enable_forwarding() -> Vec<String> {
    vec![
        "sysctl -w net.ipv4.ip_forward=1".to_string(),
        "sysctl -w net.ipv6.conf.all.forwarding=1".to_string(),
    ]
}

pub fn linux_disable_forwarding() -> Vec<String> {
    vec![
        "sysctl -w net.ipv4.ip_forward=0".to_string(),
        "sysctl -w net.ipv6.conf.all.forwarding=0".to_string(),
    ]
}

pub fn linux_nat_install(client_v4_subnet: &str) -> Vec<String> {
    if client_v4_subnet.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "iptables -t nat -A POSTROUTING -s {client_v4_subnet} -j MASQUERADE"
        )]
    }
}

pub fn linux_nat_install_ipv6(client_v6_subnet: &str) -> Vec<String> {
    if client_v6_subnet.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "ip6tables -t nat -A POSTROUTING -s {client_v6_subnet} -j MASQUERADE"
        )]
    }
}

pub fn linux_nat_remove(client_v4_subnet: &str) -> Vec<String> {
    if client_v4_subnet.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "iptables -t nat -D POSTROUTING -s {client_v4_subnet} -j MASQUERADE"
        )]
    }
}

pub fn linux_nat_remove_ipv6(client_v6_subnet: &str) -> Vec<String> {
    if client_v6_subnet.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "ip6tables -t nat -D POSTROUTING -s {client_v6_subnet} -j MASQUERADE"
        )]
    }
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
    if !server_v4.is_empty() {
        cmds.push(format!(
            "New-NetRoute -DestinationPrefix \"{server_v4}/32\" -InterfaceIndex {phys_idx} -NextHop {phys_gw} -RouteMetric 1 -PolicyStore ActiveStore"
        ));
    }
    if !server_v6.is_empty() {
        cmds.push(format!(
            "New-NetRoute -DestinationPrefix \"{server_v6}/128\" -InterfaceIndex {phys_idx} -NextHop {phys_gw} -RouteMetric 1 -PolicyStore ActiveStore"
        ));
    }
    cmds.push(format!(
        "New-NetRoute -DestinationPrefix \"0.0.0.0/0\" -InterfaceIndex {tun_idx} -NextHop 0.0.0.0 -RouteMetric 0 -PolicyStore ActiveStore"
    ));
    cmds.push(format!(
        "New-NetRoute -DestinationPrefix \"::/0\" -InterfaceIndex {tun_idx} -NextHop :: -RouteMetric 0 -PolicyStore ActiveStore"
    ));
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
            JournalEntry::Route {
                family, dst, iface, ..
            } => {
                if *family == 6 {
                    out.push(format!("ip -6 route del {dst} dev {iface}  # remove route"));
                } else {
                    out.push(format!("ip route del {dst} dev {iface}  # remove route"));
                }
            }
            JournalEntry::Rule {
                family, priority, ..
            } => {
                if *family == 6 {
                    out.push(format!("ip -6 rule del priority {priority}  # remove rule"));
                } else {
                    out.push(format!("ip rule del priority {priority}  # remove rule"));
                }
            }
            JournalEntry::Dns { iface, .. } => {
                out.push(format!("resolvectl revert {iface}  # revert dns"));
            }
            JournalEntry::FirewallRule { name } => {
                out.push(format!(
                    "iptables -D INPUT -m comment --comment {name} 2>/dev/null || true"
                ));
            }
            JournalEntry::InterfaceAddress { iface, addr } => {
                if addr.contains(':') {
                    out.push(format!("ip -6 addr del {addr} dev {iface}"));
                } else {
                    out.push(format!("ip addr del {addr} dev {iface}"));
                }
            }
            JournalEntry::KillSwitch { level } => {
                out.push(format!("remove killswitch level {level}"));
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
    fn linux_install_family_correct_no_ipv4_in_ipv6() {
        let cmds = linux_install_routes("1.2.3.4", "2001:db8::1", "pqtun0", "eth0");
        assert!(
            !cmds
                .iter()
                .any(|c| c.contains("ip -6 route replace 1.2.3.4"))
        );
        assert!(
            !cmds
                .iter()
                .any(|c| c.contains("ip -6 rule add priority 100 to 1.2.3.4"))
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("ip route replace 1.2.3.4/32"))
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("ip -6 route replace 2001:db8::1/128"))
        );
    }

    #[test]
    fn linux_install_omits_ipv6_bypass_when_empty() {
        let cmds = linux_install_routes("1.2.3.4", "", "pqtun0", "eth0");
        assert!(!cmds.iter().any(|c| c.contains("ip -6 route replace")));
        assert!(
            !cmds
                .iter()
                .any(|c| c.contains("ip -6 rule add priority 100"))
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("ip route replace 1.2.3.4/32"))
        );
    }

    #[test]
    fn linux_install_omits_ipv4_bypass_when_empty() {
        let cmds = linux_install_routes("", "2001:db8::1", "pqtun0", "eth0");
        assert!(!cmds.iter().any(|c| c.contains("ip route replace")));
        assert!(
            !cmds
                .iter()
                .any(|c| c.contains("ip rule add priority 100 to"))
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("ip -6 route replace 2001:db8::1/128"))
        );
    }

    #[test]
    fn windows_install_bypass_first() {
        let cmds = windows_install_routes("1.2.3.4", "2001:db8::1", 5, 3, "192.168.1.1");
        let bypass_pos = cmds.iter().position(|c| c.contains("1.2.3.4/32")).unwrap();
        let default_pos = cmds.iter().position(|c| c.contains("0.0.0.0/0")).unwrap();
        assert!(bypass_pos < default_pos);
    }

    #[test]
    fn windows_install_family_correct() {
        let cmds = windows_install_routes("1.2.3.4", "", 5, 3, "192.168.1.1");
        assert!(!cmds.iter().any(|c| c.contains("2001:db8::1/128")));
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
        assert!(plan[1].contains("remove route") || plan[1].contains("route del"));
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

    #[test]
    fn checked_runner_reports_failure() {
        assert!(run_command("true").is_ok());
        assert!(run_command("false").is_err());
    }
}
