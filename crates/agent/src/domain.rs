use serde::{Deserialize, Serialize, de::Error as DeError, ser::SerializeStruct};
use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Confirmed,
    Inferred,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStage {
    Validating,
    Proxy,
    Dns,
    Route,
    Http,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub level: EvidenceLevel,
    pub source: String,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficDecisionKind {
    Direct,
    Proxy,
    Reject,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficNodeKind {
    Tun,
    TrafficRule,
    PolicyGroup,
    ProxyNode,
    Blocked,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficRule {
    pub rule_type: String,
    pub payload: Option<String>,
    pub target: String,
    pub level: EvidenceLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficNode {
    pub kind: TrafficNodeKind,
    pub name: String,
    pub node_type: Option<String>,
    pub endpoint: Option<PeerEndpoint>,
    pub alive: Option<bool>,
    pub delay_ms: Option<u16>,
    pub level: EvidenceLevel,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficDecision {
    pub kind: TrafficDecisionKind,
    pub mode: Option<String>,
    pub tun_enabled: Option<bool>,
    pub rule: Option<TrafficRule>,
    pub chain: Vec<TrafficNode>,
    pub evidence: Vec<Evidence>,
}

impl TrafficDecision {
    pub fn unknown(source: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            kind: TrafficDecisionKind::Unknown,
            mode: None,
            tun_enabled: None,
            rule: None,
            chain: Vec::new(),
            evidence: vec![Evidence {
                level: EvidenceLevel::Unknown,
                source: source.into(),
                summary: summary.into(),
            }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MihomoRuntime {
    pub available: bool,
    pub mode: Option<String>,
    pub tun_enabled: Option<bool>,
    #[serde(
        default,
        serialize_with = "serialize_sanitized_controller",
        deserialize_with = "deserialize_sanitized_controller"
    )]
    pub controller: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Wifi,
    Ethernet,
    Tun,
    Loopback,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressScope {
    Loopback,
    LinkLocal,
    Private,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceAddress {
    pub ip: IpAddr,
    pub scope: AddressScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub display_name: String,
    pub kind: InterfaceKind,
    pub is_default: bool,
    pub addresses: Vec<InterfaceAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalNetworkOverview {
    pub interfaces: Vec<NetworkInterfaceInfo>,
    pub default_interface: Option<String>,
    pub mihomo: MihomoRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressObservation {
    pub provider: String,
    pub ip: IpAddr,
    pub elapsed_ms: u64,
    pub traffic_decision: TrafficDecision,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedMode {
    Quick,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedSampleKind {
    Latency,
    Download,
    Upload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeedMeasurement {
    pub kind: SpeedSampleKind,
    pub bytes: u64,
    pub count: u16,
}

impl SpeedMeasurement {
    pub const fn latency(num_packets: u16) -> Self {
        Self {
            kind: SpeedSampleKind::Latency,
            bytes: 0,
            count: num_packets,
        }
    }

    pub const fn transfer(kind: SpeedSampleKind, bytes: u64, count: u16) -> Self {
        Self { kind, bytes, count }
    }
}

impl Serialize for SpeedMeasurement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SpeedMeasurement", 3)?;
        state.serialize_field("type", &self.kind)?;
        match self.kind {
            SpeedSampleKind::Latency => state.serialize_field("numPackets", &self.count)?,
            SpeedSampleKind::Download | SpeedSampleKind::Upload => {
                state.serialize_field("bytes", &self.bytes)?;
                state.serialize_field("count", &self.count)?;
            }
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for SpeedMeasurement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "type", deny_unknown_fields)]
        enum Wire {
            #[serde(rename = "latency")]
            Latency {
                #[serde(rename = "numPackets")]
                num_packets: u16,
            },
            #[serde(rename = "download")]
            Download { bytes: u64, count: u16 },
            #[serde(rename = "upload")]
            Upload { bytes: u64, count: u16 },
        }

        match Wire::deserialize(deserializer)? {
            Wire::Latency { num_packets } => Ok(Self::latency(num_packets)),
            Wire::Download { bytes, count } => {
                Ok(Self::transfer(SpeedSampleKind::Download, bytes, count))
            }
            Wire::Upload { bytes, count } => {
                Ok(Self::transfer(SpeedSampleKind::Upload, bytes, count))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedMeasurementPlan {
    pub mode: SpeedMode,
    pub deadline_ms: u64,
    pub max_bytes: u64,
    pub include_loaded_latency: bool,
    pub measurements: Vec<SpeedMeasurement>,
}

impl SpeedMeasurementPlan {
    pub fn planned_bytes(&self) -> u64 {
        self.measurements.iter().fold(0_u64, |total, measurement| {
            measurement
                .bytes
                .saturating_mul(u64::from(measurement.count))
                .saturating_add(total)
        })
    }

    pub fn contains_packet_loss(&self) -> bool {
        false
    }
}

pub fn plan_for(mode: SpeedMode) -> SpeedMeasurementPlan {
    let (deadline_ms, max_bytes, include_loaded_latency, measurements) = match mode {
        SpeedMode::Quick => (
            15_000,
            40_000_000,
            false,
            vec![
                SpeedMeasurement::latency(10),
                SpeedMeasurement::transfer(SpeedSampleKind::Download, 100_000, 2),
                SpeedMeasurement::transfer(SpeedSampleKind::Download, 1_000_000, 2),
                SpeedMeasurement::transfer(SpeedSampleKind::Download, 5_000_000, 3),
                SpeedMeasurement::transfer(SpeedSampleKind::Upload, 100_000, 2),
                SpeedMeasurement::transfer(SpeedSampleKind::Upload, 1_000_000, 2),
                SpeedMeasurement::transfer(SpeedSampleKind::Upload, 5_000_000, 2),
            ],
        ),
        SpeedMode::Full => (
            40_000,
            200_000_000,
            true,
            vec![
                SpeedMeasurement::latency(20),
                SpeedMeasurement::transfer(SpeedSampleKind::Download, 100_000, 3),
                SpeedMeasurement::transfer(SpeedSampleKind::Download, 1_000_000, 3),
                SpeedMeasurement::transfer(SpeedSampleKind::Download, 10_000_000, 5),
                SpeedMeasurement::transfer(SpeedSampleKind::Download, 25_000_000, 3),
                SpeedMeasurement::transfer(SpeedSampleKind::Upload, 100_000, 3),
                SpeedMeasurement::transfer(SpeedSampleKind::Upload, 1_000_000, 3),
                SpeedMeasurement::transfer(SpeedSampleKind::Upload, 10_000_000, 4),
            ],
        ),
    };
    SpeedMeasurementPlan {
        mode,
        deadline_ms,
        max_bytes,
        include_loaded_latency,
        measurements,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpeedSample {
    pub kind: SpeedSampleKind,
    pub bytes: u64,
    pub bps: Option<f64>,
    pub duration_ms: f64,
    pub latency_ms: Option<f64>,
}

impl Serialize for SpeedSample {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SpeedSample", 5)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("bytes", &self.bytes)?;
        state.serialize_field("bps", &self.bps)?;
        state.serialize_field("duration_ms", &self.duration_ms)?;
        state.serialize_field("latency_ms", &self.latency_ms)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SpeedSample {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: SpeedSampleKind,
            bytes: u64,
            bps: Option<f64>,
            duration_ms: f64,
            latency_ms: Option<f64>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let sample = Self {
            kind: wire.kind,
            bytes: wire.bytes,
            bps: wire.bps,
            duration_ms: wire.duration_ms,
            latency_ms: wire.latency_ms,
        };
        sample.validate_shape().map_err(D::Error::custom)?;
        Ok(sample)
    }
}

impl SpeedSample {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if !self.duration_ms.is_finite() || !(0.0..=120_000.0).contains(&self.duration_ms) {
            return Err("duration_ms must be finite and between 0 and 120000");
        }
        if let Some(bps) = self.bps
            && (!bps.is_finite() || !(0.0..=100_000_000_000.0).contains(&bps))
        {
            return Err("bps must be finite and between 0 and 100000000000");
        }
        if let Some(latency) = self.latency_ms
            && (!latency.is_finite() || !(0.0..=120_000.0).contains(&latency))
        {
            return Err("latency_ms must be finite and between 0 and 120000");
        }
        match self.kind {
            SpeedSampleKind::Latency if self.bytes != 0 || self.bps.is_some() => {
                Err("latency samples require zero bytes and no bps")
            }
            SpeedSampleKind::Latency if self.latency_ms.is_none() => {
                Err("latency samples require latency_ms")
            }
            SpeedSampleKind::Download | SpeedSampleKind::Upload
                if self.bytes == 0 || self.bps.is_none() =>
            {
                Err("transfer samples require bytes and bps")
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpeedMetrics {
    pub download_bps: f64,
    pub upload_bps: f64,
    pub unloaded_latency_ms: f64,
    pub unloaded_jitter_ms: f64,
    pub download_loaded_latency_ms: Option<f64>,
    pub upload_loaded_latency_ms: Option<f64>,
}

impl Serialize for SpeedMetrics {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SpeedMetrics", 6)?;
        state.serialize_field("download_bps", &self.download_bps)?;
        state.serialize_field("upload_bps", &self.upload_bps)?;
        state.serialize_field("unloaded_latency_ms", &self.unloaded_latency_ms)?;
        state.serialize_field("unloaded_jitter_ms", &self.unloaded_jitter_ms)?;
        state.serialize_field(
            "download_loaded_latency_ms",
            &self.download_loaded_latency_ms,
        )?;
        state.serialize_field("upload_loaded_latency_ms", &self.upload_loaded_latency_ms)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SpeedMetrics {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            download_bps: f64,
            upload_bps: f64,
            unloaded_latency_ms: f64,
            unloaded_jitter_ms: f64,
            download_loaded_latency_ms: Option<f64>,
            upload_loaded_latency_ms: Option<f64>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let metrics = Self {
            download_bps: wire.download_bps,
            upload_bps: wire.upload_bps,
            unloaded_latency_ms: wire.unloaded_latency_ms,
            unloaded_jitter_ms: wire.unloaded_jitter_ms,
            download_loaded_latency_ms: wire.download_loaded_latency_ms,
            upload_loaded_latency_ms: wire.upload_loaded_latency_ms,
        };
        metrics.validate().map_err(D::Error::custom)?;
        Ok(metrics)
    }
}

impl SpeedMetrics {
    pub fn validate(&self) -> Result<(), &'static str> {
        for value in [self.download_bps, self.upload_bps] {
            if !value.is_finite() || !(0.0..=100_000_000_000.0).contains(&value) {
                return Err("bandwidth values must be finite and between 0 and 100000000000");
            }
        }
        for value in [self.unloaded_latency_ms, self.unloaded_jitter_ms]
            .into_iter()
            .chain(self.download_loaded_latency_ms)
            .chain(self.upload_loaded_latency_ms)
        {
            if !value.is_finite() || !(0.0..=120_000.0).contains(&value) {
                return Err("latency values must be finite and between 0 and 120000");
            }
        }
        Ok(())
    }

    pub fn validate_for_mode(&self, mode: SpeedMode) -> Result<(), &'static str> {
        self.validate()?;
        match mode {
            SpeedMode::Quick
                if self.download_loaded_latency_ms.is_some()
                    || self.upload_loaded_latency_ms.is_some() =>
            {
                Err("quick mode does not schedule loaded latency")
            }
            SpeedMode::Full
                if self.download_loaded_latency_ms.is_none()
                    || self.upload_loaded_latency_ms.is_none() =>
            {
                Err("full mode requires both loaded latency values")
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpeedTestResult {
    pub provider: String,
    pub mode: SpeedMode,
    pub metrics: SpeedMetrics,
    pub used_bytes: u64,
    pub traffic_decision: TrafficDecision,
}

fn serialize_sanitized_controller<S>(
    controller: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if is_sanitized_controller_label(controller.as_deref()) {
        controller.serialize(serializer)
    } else {
        Err(<S::Error as serde::ser::Error>::custom(
            "controller must be a sanitized state label",
        ))
    }
}

fn deserialize_sanitized_controller<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let controller = Option::<String>::deserialize(deserializer)?;
    if is_sanitized_controller_label(controller.as_deref()) {
        Ok(controller)
    } else {
        Err(<D::Error as serde::de::Error>::custom(
            "controller must be a sanitized state label",
        ))
    }
}

fn is_sanitized_controller_label(controller: Option<&str>) -> bool {
    matches!(
        controller,
        None | Some("auto_unix" | "manual_loopback" | "unavailable")
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyKind {
    Direct,
    Http,
    Https,
    Socks,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyDecision {
    pub kind: ProxyKind,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub bypass_reason: Option<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteInfo {
    pub destination: IpAddr,
    pub gateway: Option<IpAddr>,
    pub interface: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpObservation {
    pub status: Option<u16>,
    pub final_url: String,
    pub elapsed_ms: u64,
    pub error_code: Option<String>,
    pub peer_endpoint: Option<PeerEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEndpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl From<SocketAddr> for PeerEndpoint {
    fn from(endpoint: SocketAddr) -> Self {
        Self {
            ip: endpoint.ip(),
            port: endpoint.port(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceTargetKind {
    ActualDestination,
    ActualProxy,
    ReferenceDestination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceTarget {
    pub kind: TraceTargetKind,
    pub ip: IpAddr,
}

fn serialize_trace_rtts<S>(rtts: &Vec<f64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if rtts.iter().any(|rtt| !rtt.is_finite() || *rtt < 0.0) {
        return Err(<S::Error as serde::ser::Error>::custom(
            "rtts_ms must contain finite non-negative values",
        ));
    }
    rtts.serialize(serializer)
}

fn deserialize_trace_rtts<'de, D>(deserializer: D) -> Result<Vec<f64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let rtts = Vec::<f64>::deserialize(deserializer)?;
    if rtts.iter().any(|rtt| !rtt.is_finite() || *rtt < 0.0) {
        return Err(<D::Error as serde::de::Error>::custom(
            "rtts_ms must contain finite non-negative values",
        ));
    }
    Ok(rtts)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceHop {
    pub index: u8,
    pub address: Option<IpAddr>,
    #[serde(
        serialize_with = "serialize_trace_rtts",
        deserialize_with = "deserialize_trace_rtts"
    )]
    pub rtts_ms: Vec<f64>,
    pub level: EvidenceLevel,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteTraceResult {
    pub target: TraceTarget,
    pub hops: Vec<TraceHop>,
    pub reached_target: bool,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conclusion {
    pub title: String,
    pub summary: String,
    pub level: EvidenceLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlDiagnosticResult {
    pub id: Uuid,
    pub requested_url: String,
    pub normalized_url: String,
    pub resolved_ips: Vec<IpAddr>,
    pub proxy: ProxyDecision,
    pub route: Option<RouteInfo>,
    pub http: HttpObservation,
    pub traffic_decision: TrafficDecision,
    pub conclusion: Conclusion,
    pub evidence: Vec<Evidence>,
}
