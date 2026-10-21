use crate::{
    domain::{
        InterfaceAddress, InterfaceKind, LocalNetworkOverview, MihomoRuntime, NetworkInterfaceInfo,
    },
    error::DiagnosticError,
    network::overview::classify_address_scope,
    ports::NetworkOverviewProvider,
};
use async_trait::async_trait;
use if_addrs::Interface;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
    sync::Arc,
};
use tokio::process::Command;

const ROUTE_EXECUTABLE: &str = "/sbin/route";
const ROUTE_ARGUMENTS: &[&str] = &["-n", "get", "default"];
const NETWORKSETUP_EXECUTABLE: &str = "/usr/sbin/networksetup";
const NETWORKSETUP_ARGUMENTS: &[&str] = &["-listallhardwareports"];

#[derive(Debug, Clone, PartialEq, Eq)]
struct HardwarePort {
    display_name: String,
    kind: InterfaceKind,
}

#[async_trait]
trait OverviewSource: Send + Sync {
    async fn interfaces(&self) -> Result<Vec<Interface>, DiagnosticError>;
    async fn command_output(
        &self,
        executable: &str,
        arguments: &[&str],
    ) -> Result<String, DiagnosticError>;
}

struct SystemOverviewSource;

struct RawProcessOutput {
    success: bool,
    status: String,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn decode_process_result(
    executable: &str,
    result: io::Result<RawProcessOutput>,
) -> Result<String, DiagnosticError> {
    let output = result.map_err(|error| DiagnosticError::System(error.to_string()))?;
    let RawProcessOutput {
        success,
        status,
        stdout,
        stderr,
    } = output;
    drop(stderr);
    if !success {
        return Err(DiagnosticError::System(format!(
            "{executable} exited with {status}"
        )));
    }
    String::from_utf8(stdout).map_err(|error| DiagnosticError::System(error.to_string()))
}

#[async_trait]
impl OverviewSource for SystemOverviewSource {
    async fn interfaces(&self) -> Result<Vec<Interface>, DiagnosticError> {
        if_addrs::get_if_addrs().map_err(|error| DiagnosticError::System(error.to_string()))
    }

    async fn command_output(
        &self,
        executable: &str,
        arguments: &[&str],
    ) -> Result<String, DiagnosticError> {
        let result = Command::new(executable)
            .args(arguments)
            .output()
            .await
            .map(|output| RawProcessOutput {
                success: output.status.success(),
                status: output.status.to_string(),
                stdout: output.stdout,
                stderr: output.stderr,
            });
        decode_process_result(executable, result)
    }
}

#[derive(Clone)]
pub struct MacNetworkOverviewProvider {
    mihomo: MihomoRuntime,
    source: Arc<dyn OverviewSource>,
}

impl MacNetworkOverviewProvider {
    pub fn new(mihomo: MihomoRuntime) -> Self {
        Self {
            mihomo,
            source: Arc::new(SystemOverviewSource),
        }
    }

    #[cfg(test)]
    fn with_source<S>(mihomo: MihomoRuntime, source: Arc<S>) -> Self
    where
        S: OverviewSource + 'static,
    {
        Self { mihomo, source }
    }
}

#[async_trait]
impl NetworkOverviewProvider for MacNetworkOverviewProvider {
    async fn local_overview(&self) -> Result<LocalNetworkOverview, DiagnosticError> {
        let interfaces = self.source.interfaces().await?;
        let route_output = self
            .source
            .command_output(ROUTE_EXECUTABLE, ROUTE_ARGUMENTS)
            .await?;
        let hardware_ports_output = self
            .source
            .command_output(NETWORKSETUP_EXECUTABLE, NETWORKSETUP_ARGUMENTS)
            .await?;
        Ok(build_overview(
            interfaces,
            &route_output,
            &hardware_ports_output,
            self.mihomo.clone(),
        ))
    }
}

pub fn build_overview(
    interfaces: Vec<Interface>,
    route_output: &str,
    hardware_ports_output: &str,
    mihomo: MihomoRuntime,
) -> LocalNetworkOverview {
    let hardware_ports = parse_hardware_ports(hardware_ports_output);
    let route_candidate = parse_default_interface(route_output);
    let mut addresses_by_interface = BTreeMap::<String, BTreeSet<IpAddr>>::new();

    for interface in interfaces.into_iter().filter(Interface::is_oper_up) {
        let ip = interface.ip();
        addresses_by_interface
            .entry(interface.name)
            .or_default()
            .insert(ip);
    }

    let retained_interfaces = addresses_by_interface
        .into_iter()
        .filter_map(|(name, addresses)| {
            let addresses = addresses
                .into_iter()
                .filter_map(|ip| {
                    classify_address_scope(ip).map(|scope| InterfaceAddress { ip, scope })
                })
                .collect::<Vec<_>>();
            (!addresses.is_empty()).then_some((name, addresses))
        })
        .collect::<BTreeMap<_, _>>();
    let default_interface =
        route_candidate.filter(|candidate| retained_interfaces.contains_key(candidate.as_str()));
    let interfaces = retained_interfaces
        .into_iter()
        .map(|(name, addresses)| {
            let (display_name, kind) = interface_label(&name, hardware_ports.get(&name));
            NetworkInterfaceInfo {
                is_default: default_interface.as_deref() == Some(name.as_str()),
                name,
                display_name,
                kind,
                addresses,
            }
        })
        .collect();

    LocalNetworkOverview {
        interfaces,
        default_interface,
        mihomo,
    }
}

fn parse_hardware_ports(output: &str) -> BTreeMap<String, HardwarePort> {
    let mut candidates = BTreeMap::<String, Option<HardwarePort>>::new();
    let mut display_name = None::<String>;
    let mut device = None::<String>;
    let mut malformed = false;

    for line in output.lines().map(str::trim) {
        if line.starts_with("VLAN Configurations") {
            retain_hardware_block(
                &mut candidates,
                display_name.take(),
                device.take(),
                malformed,
            );
            break;
        }
        if line.is_empty() {
            retain_hardware_block(
                &mut candidates,
                display_name.take(),
                device.take(),
                malformed,
            );
            malformed = false;
            continue;
        }
        if let Some(value) = line.strip_prefix("Hardware Port:").map(str::trim) {
            if display_name.is_some() || device.is_some() || malformed {
                retain_hardware_block(
                    &mut candidates,
                    display_name.take(),
                    device.take(),
                    malformed,
                );
                malformed = false;
            }
            display_name = (!value.is_empty()).then(|| value.to_owned());
            malformed |= value.is_empty();
            continue;
        }
        let Some(value) = line.strip_prefix("Device:").map(str::trim) else {
            continue;
        };
        if device.is_some() || !valid_interface_name(value) {
            malformed = true;
        } else {
            device = Some(value.to_owned());
        }
    }
    retain_hardware_block(&mut candidates, display_name, device, malformed);

    candidates
        .into_iter()
        .filter_map(|(device, candidate)| candidate.map(|port| (device, port)))
        .collect()
}

fn retain_hardware_block(
    candidates: &mut BTreeMap<String, Option<HardwarePort>>,
    display_name: Option<String>,
    device: Option<String>,
    malformed: bool,
) {
    if malformed {
        return;
    }
    let (Some(display_name), Some(device)) = (display_name, device) else {
        return;
    };
    let port = HardwarePort {
        kind: hardware_port_kind(&display_name),
        display_name,
    };
    match candidates.entry(device) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(Some(port));
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            if entry.get().as_ref() != Some(&port) {
                entry.insert(None);
            }
        }
    }
}

fn hardware_port_kind(display_name: &str) -> InterfaceKind {
    let normalized = display_name.to_ascii_lowercase();
    if normalized.contains("wi-fi") || normalized.contains("wifi") || normalized.contains("airport")
    {
        InterfaceKind::Wifi
    } else if normalized.contains("ethernet") {
        InterfaceKind::Ethernet
    } else {
        InterfaceKind::Other
    }
}

fn interface_label(name: &str, hardware_port: Option<&HardwarePort>) -> (String, InterfaceKind) {
    if name.starts_with("utun") {
        return ("TUN".into(), InterfaceKind::Tun);
    }
    if name.starts_with("lo") {
        return ("Loopback".into(), InterfaceKind::Loopback);
    }
    hardware_port.map_or_else(
        || (name.to_owned(), InterfaceKind::Other),
        |port| (port.display_name.clone(), port.kind),
    )
}

fn parse_default_interface(output: &str) -> Option<String> {
    let candidates = output
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("interface:").map(str::trim))
        .filter(|candidate| valid_interface_name(candidate))
        .collect::<BTreeSet<_>>();

    (candidates.len() == 1).then(|| (*candidates.first().expect("one candidate")).to_owned())
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::{
        MacNetworkOverviewProvider, OverviewSource, RawProcessOutput, decode_process_result,
    };
    use crate::{domain::MihomoRuntime, error::DiagnosticError, ports::NetworkOverviewProvider};
    use async_trait::async_trait;
    use if_addrs::{IfAddr, IfOperStatus, Ifv4Addr, Interface};
    use std::{
        io,
        net::Ipv4Addr,
        sync::{Arc, Mutex},
    };

    struct FixtureSource {
        interfaces: Result<Vec<Interface>, &'static str>,
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl FixtureSource {
        fn available() -> Self {
            Self {
                interfaces: Ok(vec![Interface {
                    name: "en0".into(),
                    addr: IfAddr::V4(Ifv4Addr {
                        ip: Ipv4Addr::new(192, 168, 1, 20),
                        netmask: Ipv4Addr::new(255, 255, 255, 0),
                        prefixlen: 24,
                        broadcast: None,
                    }),
                    index: Some(4),
                    oper_status: IfOperStatus::Up,
                    is_p2p: false,
                }]),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl OverviewSource for FixtureSource {
        async fn interfaces(&self) -> Result<Vec<Interface>, DiagnosticError> {
            self.interfaces
                .clone()
                .map_err(|message| DiagnosticError::System(message.into()))
        }

        async fn command_output(
            &self,
            executable: &str,
            arguments: &[&str],
        ) -> Result<String, DiagnosticError> {
            self.calls.lock().unwrap().push((
                executable.into(),
                arguments
                    .iter()
                    .map(|argument| (*argument).into())
                    .collect(),
            ));
            match (executable, arguments) {
                ("/sbin/route", ["-n", "get", "default"]) => Ok("interface: en0\n".into()),
                ("/usr/sbin/networksetup", ["-listallhardwareports"]) => {
                    Ok("Hardware Port: Wi-Fi\nDevice: en0\n".into())
                }
                _ => Err(DiagnosticError::System("unexpected command".into())),
            }
        }
    }

    fn runtime() -> MihomoRuntime {
        MihomoRuntime {
            available: true,
            mode: Some("rule".into()),
            tun_enabled: Some(true),
            controller: Some("manual_loopback".into()),
        }
    }

    #[test]
    fn raw_process_success_returns_stdout_and_ignores_stderr() {
        let output = decode_process_result(
            "/fixed/tool",
            Ok(RawProcessOutput {
                success: true,
                status: "exit status: 0".into(),
                stdout: b"fixture stdout\n".to_vec(),
                stderr: b"ignored stderr".to_vec(),
            }),
        )
        .unwrap();

        assert_eq!(output, "fixture stdout\n");
    }

    #[test]
    fn raw_process_spawn_errors_become_system_errors() {
        let error = decode_process_result(
            "/fixed/tool",
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "fixture spawn error",
            )),
        )
        .unwrap_err();

        assert!(matches!(error, DiagnosticError::System(_)));
        assert!(error.to_string().contains("fixture spawn error"));
    }

    #[test]
    fn raw_process_nonzero_status_does_not_leak_stderr() {
        let error = decode_process_result(
            "/fixed/tool",
            Ok(RawProcessOutput {
                success: false,
                status: "exit status: 7".into(),
                stdout: b"untrusted stdout".to_vec(),
                stderr: b"fixture-secret-stderr".to_vec(),
            }),
        )
        .unwrap_err();
        let rendered = error.to_string();

        assert!(rendered.contains("/fixed/tool"));
        assert!(rendered.contains("exit status: 7"));
        assert!(!rendered.contains("fixture-secret-stderr"));
        assert!(!rendered.contains("untrusted stdout"));
    }

    #[test]
    fn raw_process_success_rejects_invalid_utf8_stdout() {
        let error = decode_process_result(
            "/fixed/tool",
            Ok(RawProcessOutput {
                success: true,
                status: "exit status: 0".into(),
                stdout: vec![0xff],
                stderr: Vec::new(),
            }),
        )
        .unwrap_err();

        assert!(matches!(error, DiagnosticError::System(_)));
    }

    #[tokio::test]
    async fn provider_uses_only_fixed_executable_paths_and_argv() {
        let source = Arc::new(FixtureSource::available());
        let provider = MacNetworkOverviewProvider::with_source(runtime(), source.clone());

        let overview = provider.local_overview().await.unwrap();

        assert_eq!(overview.mihomo, runtime());
        assert_eq!(overview.default_interface.as_deref(), Some("en0"));
        assert_eq!(overview.interfaces[0].display_name, "Wi-Fi");
        assert_eq!(
            *source.calls.lock().unwrap(),
            vec![
                (
                    "/sbin/route".into(),
                    vec!["-n".into(), "get".into(), "default".into()]
                ),
                (
                    "/usr/sbin/networksetup".into(),
                    vec!["-listallhardwareports".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn provider_returns_interface_collection_failures() {
        let source = Arc::new(FixtureSource {
            interfaces: Err("fixture enumeration failed"),
            calls: Mutex::new(Vec::new()),
        });
        let provider = MacNetworkOverviewProvider::with_source(runtime(), source.clone());

        let error = provider.local_overview().await.unwrap_err();

        assert!(matches!(error, DiagnosticError::System(_)));
        assert!(source.calls.lock().unwrap().is_empty());
    }
}
