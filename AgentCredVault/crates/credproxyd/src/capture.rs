//! Netfilter capture rules owned by the daemon (design §4.2.1).
//!
//! The daemon installs exactly one rule: a DNAT in the dedicated
//! `CREDSVAULT_PREROUTING` chain, jumped to from the top of `nat PREROUTING`.
//! Forwarding, host input filtering and source NAT stay with whatever already
//! owns the bridge (libvirt, a CNI, or the operator); the daemon only redirects
//! the traffic it needs to see. A repeated install leaves the same rule and
//! does not flush a chain that already matches.
//!
//! Lifecycle (decision: fail closed): installation is part of daemon startup
//! and an installation error refuses startup; a clean stop or a crash keeps
//! the rules in place, so traffic cannot bypass the proxy while the daemon is
//! down. Only the explicit `credproxyd uninstall-capture` command removes
//! them. Uninstall also removes the `CREDSVAULT_FORWARD` / `INPUT` /
//! `POSTROUTING` chains left by earlier full-profile builds.
//!
//! V1 covers IPv4 TCP/443 only, matching the design's capture boundary.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

pub const CHAIN_PREROUTING: &str = "CREDSVAULT_PREROUTING";
pub const CHAIN_FORWARD: &str = "CREDSVAULT_FORWARD";
pub const CHAIN_INPUT: &str = "CREDSVAULT_INPUT";
pub const CHAIN_POSTROUTING: &str = "CREDSVAULT_POSTROUTING";

/// Deployment parameters for capture, as they appear in the bootstrap file.
///
/// `subnet` is the address range seen on the bridge (the VM/sandbox side) and
/// `gateway` is the host address on that bridge. The DNAT target is
/// `gateway:<listen port>`: the transparent listener may bind `0.0.0.0` or the
/// gateway address itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFileConfig {
    pub interface: String,
    pub subnet: String,
    pub gateway: String,
}

/// Validated capture configuration bound to one listen address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    interface: String,
    subnet: String,
    gateway: Ipv4Addr,
    listen: SocketAddr,
}

impl CaptureConfig {
    pub fn from_file(file: &CaptureFileConfig, listen: SocketAddr) -> Result<CaptureConfig> {
        let interface = file.interface.trim();
        validate_interface(interface)?;

        let (subnet_addr, prefix) = parse_subnet(&file.subnet)?;
        let gateway: Ipv4Addr = file.gateway.trim().parse().with_context(|| {
            format!(
                "capture.gateway {:?}: expected an IPv4 address",
                file.gateway
            )
        })?;
        if !in_subnet(subnet_addr, prefix, gateway) {
            bail!(
                "capture.gateway {gateway} is outside capture.subnet {}/{}",
                subnet_addr,
                prefix
            );
        }

        let listen_ip = match listen.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => bail!("capture requires an IPv4 listener, got {listen}"),
        };
        if listen.port() == 0 {
            bail!("capture requires a non-zero listener port, got {listen}");
        }
        if !listen_ip.is_unspecified() && listen_ip != gateway {
            bail!(
                "capture listener {listen} must bind 0.0.0.0 or the capture gateway {gateway} \
                 (DNAT sends captured traffic to {gateway})"
            );
        }

        Ok(CaptureConfig {
            interface: interface.to_string(),
            subnet: format!("{subnet_addr}/{prefix}"),
            gateway,
            listen,
        })
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn subnet(&self) -> &str {
        &self.subnet
    }

    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub fn dnat_target(&self) -> String {
        format!("{}:{}", self.gateway, self.listen.port())
    }

    /// The single rule this deployment needs: redirect TCP/443 from the
    /// bridge to the transparent listener. Everything else about the bridge
    /// (forwarding, host access, source NAT) remains owned by libvirt, the CNI,
    /// or the operator.
    pub fn plan(&self) -> Plan {
        let iface = self.interface.clone();
        let subnet = self.subnet.clone();
        let dnat = self.dnat_target();

        Plan {
            chains: vec![("nat", CHAIN_PREROUTING)],
            rules: vec![Rule::new(
                "nat",
                CHAIN_PREROUTING,
                vec![
                    "-i",
                    &iface,
                    "-s",
                    &subnet,
                    "-p",
                    "tcp",
                    "--dport",
                    "443",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    &dnat,
                ],
            )],
            jumps: vec![Jump {
                table: "nat",
                parent: "PREROUTING",
                chain: CHAIN_PREROUTING,
            }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub table: &'static str,
    pub chain: &'static str,
    pub spec: Vec<String>,
}

impl Rule {
    fn new(table: &'static str, chain: &'static str, spec: Vec<&str>) -> Rule {
        Rule {
            table,
            chain,
            spec: spec.into_iter().map(str::to_string).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jump {
    pub table: &'static str,
    pub parent: &'static str,
    pub chain: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub chains: Vec<(&'static str, &'static str)>,
    pub rules: Vec<Rule>,
    pub jumps: Vec<Jump>,
}

/// The subset of `iptables` the capture lifecycle needs. A fake implementation
/// keeps the rule planning testable without root or a real netfilter.
pub trait Firewall {
    /// Confirms the tool is usable (present, privileged, table readable).
    fn probe(&self) -> Result<()>;
    /// Runs a mutating command and fails on a non-zero exit.
    fn exec(&self, table: &str, args: &[&str]) -> Result<()>;
    /// Whether the exact rule/chain named by `args` exists.
    fn has_rule(&self, table: &str, args: &[&str]) -> Result<bool>;
    fn has_chain(&self, table: &str, chain: &str) -> Result<bool>;
}

/// `iptables` with the xtables lock held for a bounded wait.
pub struct Iptables;

impl Iptables {
    fn output(&self, table: &str, args: &[&str]) -> Result<Output> {
        Command::new("iptables")
            .arg("-w")
            .arg("-t")
            .arg(table)
            .args(args)
            .output()
            .context("run iptables")
    }
}

impl Firewall for Iptables {
    fn probe(&self) -> Result<()> {
        let out = self.output("filter", &["-S"])?;
        if !out.status.success() {
            bail!(
                "iptables is not usable: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    fn exec(&self, table: &str, args: &[&str]) -> Result<()> {
        let out = self.output(table, args)?;
        if !out.status.success() {
            bail!(
                "iptables -t {table} {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    fn has_rule(&self, table: &str, args: &[&str]) -> Result<bool> {
        let out = self.output(table, args)?;
        match out.status.code() {
            Some(0) => Ok(true),
            // iptables exits 1 for "no such rule/chain"; anything else
            // (permission, lock timeout, bad syntax) must not be mistaken for
            // "absent", or a failed install could look idempotent.
            Some(1) => Ok(false),
            _ => bail!(
                "iptables -t {table} {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        }
    }

    fn has_chain(&self, table: &str, chain: &str) -> Result<bool> {
        self.has_rule(table, &["-S", chain])
    }
}

/// Installs or refreshes the capture rules. Idempotent: a second run leaves an
/// identical chain set and does not flush chains whose rules already match.
pub fn install(cfg: &CaptureConfig, fw: &dyn Firewall) -> Result<()> {
    let plan = cfg.plan();
    fw.probe()?;

    for (table, chain) in &plan.chains {
        if !fw.has_chain(table, chain)? {
            fw.exec(table, &["-N", chain])
                .with_context(|| format!("create chain {chain}"))?;
        }
    }

    for (table, chain) in &plan.chains {
        let wanted: Vec<&Rule> = plan
            .rules
            .iter()
            .filter(|r| r.table == *table && r.chain == *chain)
            .collect();
        let mut missing = false;
        for rule in &wanted {
            if !has_spec(fw, rule.table, rule.chain, &rule.spec)? {
                missing = true;
                break;
            }
        }
        if missing {
            fw.exec(table, &["-F", chain])
                .with_context(|| format!("flush chain {chain}"))?;
            for rule in &wanted {
                let mut args = vec!["-A", chain];
                args.extend(rule.spec.iter().map(String::as_str));
                fw.exec(table, &args)
                    .with_context(|| format!("append to {chain}"))?;
            }
        }
        // Verify the final state even when nothing had to change.
        for rule in &wanted {
            if !has_spec(fw, rule.table, rule.chain, &rule.spec)? {
                bail!("rule did not install in {chain}: {}", rule.spec.join(" "));
            }
        }
    }

    for jump in &plan.jumps {
        // Re-assert precedence: an earlier deployment or another tool may have
        // inserted a matching rule above ours. Deleting only the jump while
        // the chain keeps its rules leaves no window in which captured
        // traffic is handled by an empty chain.
        loop {
            if !fw.has_rule(jump.table, &["-C", jump.parent, "-j", jump.chain])? {
                break;
            }
            fw.exec(jump.table, &["-D", jump.parent, "-j", jump.chain])
                .with_context(|| format!("remove old jump {} -> {}", jump.parent, jump.chain))?;
        }
        fw.exec(jump.table, &["-I", jump.parent, "1", "-j", jump.chain])
            .with_context(|| format!("insert jump {} -> {}", jump.parent, jump.chain))?;
        if !fw.has_rule(jump.table, &["-C", jump.parent, "-j", jump.chain])? {
            bail!("jump did not install: {} -> {}", jump.parent, jump.chain);
        }
    }
    Ok(())
}

/// Removes every capture chain and jump, including the `CREDSVAULT_FORWARD` /
/// `INPUT` / `POSTROUTING` chains left by earlier full-profile builds. This is
/// the only path that removes rules; stop, crash and restart all keep them.
/// Idempotent.
pub fn uninstall(fw: &dyn Firewall) -> Result<()> {
    fw.probe()?;
    let jumps = [
        ("nat", "PREROUTING", CHAIN_PREROUTING),
        ("filter", "FORWARD", CHAIN_FORWARD),
        ("filter", "INPUT", CHAIN_INPUT),
        ("nat", "POSTROUTING", CHAIN_POSTROUTING),
    ];
    for (table, parent, chain) in jumps {
        loop {
            if !fw.has_rule(table, &["-C", parent, "-j", chain])? {
                break;
            }
            fw.exec(table, &["-D", parent, "-j", chain])
                .with_context(|| format!("remove jump {parent} -> {chain}"))?;
        }
    }
    let chains = [
        ("nat", CHAIN_PREROUTING),
        ("filter", CHAIN_FORWARD),
        ("filter", CHAIN_INPUT),
        ("nat", CHAIN_POSTROUTING),
    ];
    for (table, chain) in chains {
        if !fw.has_chain(table, chain)? {
            continue;
        }
        // A chain that still has references cannot be deleted; the jump
        // removal above covers ours. Flushing first makes the intent explicit.
        fw.exec(table, &["-F", chain])
            .with_context(|| format!("flush chain {chain}"))?;
        fw.exec(table, &["-X", chain])
            .with_context(|| format!("delete chain {chain}"))?;
    }
    Ok(())
}

fn has_spec(fw: &dyn Firewall, table: &str, chain: &str, spec: &[String]) -> Result<bool> {
    let mut args = vec!["-C", chain];
    args.extend(spec.iter().map(String::as_str));
    fw.has_rule(table, &args)
}

fn validate_interface(interface: &str) -> Result<()> {
    if interface.is_empty() || interface.len() > 15 {
        bail!("capture.interface {interface:?}: expected 1-15 characters (Linux IFNAMSIZ)");
    }
    // Anything that could be read as an iptables option, a negation or a path
    // is rejected; iptables receives these values as separate argv entries,
    // but a leading '-' or a bare '!' would still change the rule's meaning.
    if interface.starts_with('-')
        || interface.contains('/')
        || interface.contains(char::is_whitespace)
        || !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
    {
        bail!("capture.interface {interface:?}: not a valid interface name");
    }
    Ok(())
}

fn parse_subnet(value: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = value
        .split_once('/')
        .with_context(|| format!("capture.subnet {value:?}: expected address/prefix"))?;
    let addr: Ipv4Addr = addr
        .parse()
        .with_context(|| format!("capture.subnet {value:?}: invalid IPv4 address"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("capture.subnet {value:?}: invalid prefix length"))?;
    if !(8..=32).contains(&prefix) {
        bail!("capture.subnet {value:?}: prefix length must be 8..=32");
    }
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    let bits = u32::from(addr);
    if bits & !mask != 0 {
        bail!(
            "capture.subnet {value:?}: host bits set; use {}/{prefix}",
            Ipv4Addr::from(bits & mask)
        );
    }
    Ok((addr, prefix))
}

fn in_subnet(network: Ipv4Addr, prefix: u8, ip: Ipv4Addr) -> bool {
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(network) & mask == u32::from(ip) & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    fn file() -> CaptureFileConfig {
        CaptureFileConfig {
            interface: "virbr-cpb".into(),
            subnet: "192.168.56.0/24".into(),
            gateway: "192.168.56.1".into(),
        }
    }

    fn listen() -> SocketAddr {
        "192.168.56.1:4100".parse().unwrap()
    }

    #[test]
    fn plan_is_only_the_dnat_rule() {
        let cfg = CaptureConfig::from_file(&file(), listen()).unwrap();
        let plan = cfg.plan();
        assert_eq!(plan.chains, vec![("nat", CHAIN_PREROUTING)]);
        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.rules[0].table, "nat");
        assert_eq!(plan.rules[0].chain, CHAIN_PREROUTING);
        assert_eq!(
            plan.rules[0].spec.join(" "),
            "-i virbr-cpb -s 192.168.56.0/24 -p tcp --dport 443 -j DNAT \
             --to-destination 192.168.56.1:4100"
        );
        assert_eq!(
            plan.jumps,
            vec![Jump {
                table: "nat",
                parent: "PREROUTING",
                chain: CHAIN_PREROUTING,
            }]
        );
    }

    #[test]
    fn wildcard_listener_uses_the_gateway_for_dnat() {
        let cfg = CaptureConfig::from_file(&file(), "0.0.0.0:4100".parse().unwrap()).unwrap();
        assert_eq!(cfg.dnat_target(), "192.168.56.1:4100");
        // Any other bound address would receive no captured traffic.
        let err = CaptureConfig::from_file(&file(), "10.0.0.2:4100".parse().unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("must bind"), "{err}");
    }

    #[test]
    fn config_validation_rejects_dangerous_values() {
        for (field, value) in [
            ("interface", ""),
            ("interface", "-i"),
            ("interface", "virbr cpb"),
            ("interface", "0123456789abcdef"),
            ("subnet", "192.168.56.1/24"),
            ("subnet", "10.0.0.0/4"),
            ("subnet", "10.0.0.0"),
            ("gateway", "10.1.0.1"),
            ("gateway", "not-an-ip"),
        ] {
            let mut f = file();
            match field {
                "interface" => f.interface = value.into(),
                "subnet" => f.subnet = value.into(),
                "gateway" => f.gateway = value.into(),
                _ => unreachable!(),
            }
            assert!(
                CaptureConfig::from_file(&f, listen()).is_err(),
                "{field}={value:?} must be rejected"
            );
        }
    }

    /// In-memory iptables: enough of `-N/-F/-A/-I/-D/-X/-C` to exercise the
    /// install/uninstall state machine without root.
    type ChainMap = BTreeMap<(String, String), Vec<Vec<String>>>;

    #[derive(Default)]
    struct Fake {
        chains: RefCell<ChainMap>,
        mutations: RefCell<usize>,
        fail_on: Option<String>,
    }

    impl Fake {
        fn new() -> Fake {
            Fake::default()
        }

        fn with_failure(needle: &str) -> Fake {
            Fake {
                fail_on: Some(needle.into()),
                ..Fake::default()
            }
        }

        fn mutate(&self, table: &str, args: &[&str]) -> Result<()> {
            if let Some(needle) = &self.fail_on {
                if args.join(" ").contains(needle) {
                    bail!("injected failure on {}", args.join(" "));
                }
            }
            *self.mutations.borrow_mut() += 1;
            let mut chains = self.chains.borrow_mut();
            match args[0] {
                "-N" => {
                    chains.insert((table.into(), args[1].into()), Vec::new());
                }
                "-F" => {
                    if let Some(rules) = chains.get_mut(&(table.into(), args[1].into())) {
                        rules.clear();
                    }
                }
                "-A" => {
                    let key = (table.into(), args[1].into());
                    chains
                        .entry(key)
                        .or_default()
                        .push(args[2..].iter().map(|s| s.to_string()).collect());
                }
                "-I" => {
                    let key = (table.into(), args[1].into());
                    let spec: Vec<String> = args[3..].iter().map(|s| s.to_string()).collect();
                    chains.entry(key).or_default().insert(0, spec);
                }
                "-D" => {
                    if let Some(rules) = chains.get_mut(&(table.into(), args[1].into())) {
                        let spec: Vec<String> = args[2..].iter().map(|s| s.to_string()).collect();
                        if let Some(pos) = rules.iter().position(|r| *r == spec) {
                            rules.remove(pos);
                        }
                    }
                }
                "-X" => {
                    chains.remove(&(table.into(), args[1].into()));
                }
                other => bail!("fake iptables: unsupported {other}"),
            }
            Ok(())
        }

        fn snapshot(&self) -> ChainMap {
            self.chains.borrow().clone()
        }
    }

    impl Firewall for Fake {
        fn probe(&self) -> Result<()> {
            Ok(())
        }

        fn exec(&self, table: &str, args: &[&str]) -> Result<()> {
            self.mutate(table, args)
        }

        fn has_rule(&self, table: &str, args: &[&str]) -> Result<bool> {
            let chains = self.chains.borrow();
            match args[0] {
                "-C" => {
                    let Some(rules) = chains.get(&(table.into(), args[1].into())) else {
                        return Ok(false);
                    };
                    let spec: Vec<String> = args[2..].iter().map(|s| s.to_string()).collect();
                    Ok(rules.contains(&spec))
                }
                "-S" => Ok(chains.contains_key(&(table.into(), args[1].into()))),
                _ => bail!("fake iptables: unsupported check {}", args[0]),
            }
        }

        fn has_chain(&self, table: &str, chain: &str) -> Result<bool> {
            Ok(self
                .chains
                .borrow()
                .contains_key(&(table.into(), chain.into())))
        }
    }

    #[test]
    fn install_is_idempotent_and_jumps_sit_at_the_top() {
        let cfg = CaptureConfig::from_file(&file(), listen()).unwrap();
        let fw = Fake::new();
        install(&cfg, &fw).unwrap();
        let first = fw.snapshot();
        let mutations = *fw.mutations.borrow();
        install(&cfg, &fw).unwrap();
        assert_eq!(fw.snapshot(), first);
        // The second run re-inserts the single jump to keep precedence, but it
        // must not rewrite the chain contents: one delete plus one insert.
        assert!(
            *fw.mutations.borrow() - mutations == 2,
            "second install touched more than the PREROUTING jump"
        );
        let rules = &first[&("nat".to_string(), "PREROUTING".to_string())];
        assert_eq!(
            rules.first().unwrap(),
            &vec!["-j".to_string(), CHAIN_PREROUTING.to_string()]
        );
    }

    #[test]
    fn install_rebuilds_a_stale_chain() {
        let cfg = CaptureConfig::from_file(&file(), listen()).unwrap();
        let fw = Fake::new();
        install(&cfg, &fw).unwrap();
        fw.exec("nat", &["-F", CHAIN_PREROUTING]).unwrap();
        install(&cfg, &fw).unwrap();
        let snapshot = fw.snapshot();
        assert_eq!(snapshot[&("nat".into(), CHAIN_PREROUTING.into())].len(), 1);
    }

    #[test]
    fn install_failure_is_an_error() {
        let cfg = CaptureConfig::from_file(&file(), listen()).unwrap();
        let fw = Fake::with_failure("-I PREROUTING");
        assert!(install(&cfg, &fw).is_err());
    }

    #[test]
    fn uninstall_removes_jumps_and_chains_and_is_idempotent() {
        let cfg = CaptureConfig::from_file(&file(), listen()).unwrap();
        let fw = Fake::new();
        install(&cfg, &fw).unwrap();
        uninstall(&fw).unwrap();
        let snapshot = fw.snapshot();
        for (table, parent) in [
            ("nat", "PREROUTING"),
            ("filter", "FORWARD"),
            ("filter", "INPUT"),
            ("nat", "POSTROUTING"),
        ] {
            assert!(
                snapshot
                    .get(&(table.to_string(), parent.to_string()))
                    .is_none_or(Vec::is_empty),
                "{parent} still has capture rules"
            );
        }
        for (table, chain) in [
            ("nat", CHAIN_PREROUTING),
            ("filter", CHAIN_FORWARD),
            ("filter", CHAIN_INPUT),
            ("nat", CHAIN_POSTROUTING),
        ] {
            assert!(!snapshot.contains_key(&(table.to_string(), chain.to_string())));
        }
        uninstall(&fw).unwrap();
    }
}
