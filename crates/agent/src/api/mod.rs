mod assets;
mod mihomo_settings;
mod network_overview;
mod route_traces;
mod runs;
mod security;
mod speed_tests;

pub use crate::speed::{SpeedSnapshot, SpeedStatus, SpeedStore};
pub use network_overview::NetworkOverviewResponse;

use crate::{
    diagnostics::url::UrlDiagnosticService,
    domain::UrlDiagnosticResult,
    error::DiagnosticError,
    platform::macos::traceroute::MacRouteTracer,
    ports::{
        EgressProvider, NetworkOverviewProvider, ProgressSink, RequestPathPlanner, RouteTracer,
        TrafficDecisionProvider, WebProbe,
    },
    speed::{SpeedCoordinator, SpeedTestService},
    traffic::NoopTrafficDecisionProvider,
    traffic::mihomo::MihomoControllerManager,
};
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::StatusCode,
    middleware,
    response::{
        IntoResponse, Response,
        sse::{Event, Sse},
    },
    routing::{get, post, put},
};
use futures_util::{FutureExt, StreamExt, stream};
use hyper::{Request as HyperRequest, body::Incoming};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ConnectionBuilder,
    service::TowerToHyperService,
};
pub use route_traces::{TraceSnapshot, TraceStatus, TraceStore};
pub use runs::RunStore;
use runs::{RunFailure, RunProgress};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    convert::Infallible,
    future::Future,
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower::ServiceExt as TowerServiceExt;
use uuid::Uuid;

const BODY_LIMIT: usize = 8 * 1024;
const REQUEST_BODY_READ_TIMEOUT: Duration = Duration::from_secs(1);
const GRACEFUL_CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_CONCURRENT_RUNS: usize = 20;

#[async_trait]
pub trait UrlRunner: Send + Sync {
    async fn run(
        &self,
        input: &str,
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError>;

    async fn shutdown(&self) {}
}

#[async_trait]
impl<Q, W, T> UrlRunner for UrlDiagnosticService<Q, W, T>
where
    Q: RequestPathPlanner,
    W: WebProbe,
    T: TrafficDecisionProvider + Clone + 'static,
{
    async fn run(
        &self,
        input: &str,
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        UrlDiagnosticService::run(self, input, progress).await
    }

    async fn shutdown(&self) {
        UrlDiagnosticService::shutdown(self).await;
    }
}

#[derive(Clone)]
pub struct AppState {
    runner: Arc<dyn UrlRunner>,
    store: RunStore,
    session_token: Arc<str>,
    port: u16,
    permits: Arc<Semaphore>,
    url_job_admission: Arc<Mutex<()>>,
    url_job_shutdown: CancellationToken,
    url_job_tasks: TaskTracker,
    active_connection_tasks: Arc<AtomicUsize>,
    mihomo_manager: Option<Arc<MihomoControllerManager>>,
    network_overview_provider: Option<Arc<dyn NetworkOverviewProvider>>,
    egress_provider: Option<Arc<dyn EgressProvider>>,
    pub(crate) route_tracer: Arc<dyn RouteTracer>,
    pub(crate) trace_store: route_traces::TraceStore,
    pub(crate) trace_permits: Arc<Semaphore>,
    pub(crate) trace_job_admission: Arc<Mutex<()>>,
    pub(crate) trace_job_shutdown: CancellationToken,
    pub(crate) trace_job_tasks: TaskTracker,
    pub(crate) speed_service: Arc<dyn SpeedTestService>,
}

impl AppState {
    pub fn new(port: u16, session_token: impl Into<String>, runner: Arc<dyn UrlRunner>) -> Self {
        Self {
            runner,
            store: RunStore::new(),
            session_token: Arc::from(session_token.into()),
            port,
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_RUNS)),
            url_job_admission: Arc::new(Mutex::new(())),
            url_job_shutdown: CancellationToken::new(),
            url_job_tasks: TaskTracker::new(),
            active_connection_tasks: Arc::new(AtomicUsize::new(0)),
            mihomo_manager: None,
            network_overview_provider: None,
            egress_provider: None,
            route_tracer: Arc::new(MacRouteTracer::new()),
            trace_store: route_traces::TraceStore::new(),
            trace_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_RUNS)),
            trace_job_admission: Arc::new(Mutex::new(())),
            trace_job_shutdown: CancellationToken::new(),
            trace_job_tasks: TaskTracker::new(),
            speed_service: Arc::new(SpeedCoordinator::new(NoopTrafficDecisionProvider)),
        }
    }

    pub fn with_route_tracer(mut self, tracer: Arc<dyn RouteTracer>) -> Self {
        self.route_tracer = tracer;
        self
    }

    pub fn with_trace_store(mut self, store: route_traces::TraceStore) -> Self {
        self.trace_store = store;
        self
    }

    pub fn with_mihomo_manager(mut self, manager: Arc<MihomoControllerManager>) -> Self {
        self.mihomo_manager = Some(manager);
        self
    }

    pub fn with_network_overview(
        mut self,
        local: Arc<dyn NetworkOverviewProvider>,
        egress: Arc<dyn EgressProvider>,
    ) -> Self {
        self.network_overview_provider = Some(local);
        self.egress_provider = Some(egress);
        self
    }

    pub fn with_speed_service(mut self, service: Arc<dyn SpeedTestService>) -> Self {
        self.speed_service = service;
        self
    }

    pub async fn shutdown(&self) {
        self.speed_service.shutdown().await;
        {
            let _admission = self.trace_job_admission.lock().await;
            self.trace_job_shutdown.cancel();
            self.trace_job_tasks.close();
            self.trace_store.cancel_running();
        }
        self.trace_job_tasks.wait().await;
        {
            let _admission = self.url_job_admission.lock().await;
            self.url_job_shutdown.cancel();
            self.url_job_tasks.close();
        }
        self.url_job_tasks.wait().await;
        self.runner.shutdown().await;
        if let Some(egress) = &self.egress_provider {
            egress.shutdown().await;
        }
        if let Some(manager) = &self.mihomo_manager {
            manager.shutdown().await;
        }
    }

    pub fn active_connection_tasks(&self) -> usize {
        self.active_connection_tasks.load(Ordering::Acquire)
    }

    async fn start_url_job(&self, url: String, permit: OwnedSemaphorePermit) -> Option<Uuid> {
        let _admission = self.url_job_admission.lock().await;
        if self.url_job_shutdown.is_cancelled() || self.url_job_tasks.is_closed() {
            return None;
        }
        let id = self.store.create();
        let runner = Arc::clone(&self.runner);
        let store = self.store.clone();
        let shutdown = self.url_job_shutdown.child_token();
        self.url_job_tasks.spawn(async move {
            let _permit = permit;
            let progress = RunProgress::new(store.clone(), id);
            let run = std::panic::AssertUnwindSafe(runner.run(&url, &progress)).catch_unwind();
            tokio::pin!(run);
            let outcome = tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    store.fail(id, RunFailure::diagnostic_failed());
                    return;
                }
                outcome = &mut run => outcome,
            };
            match outcome {
                Ok(Ok(result)) => store.complete(id, result),
                Ok(Err(DiagnosticError::InvalidUrl)) => store.fail(id, RunFailure::invalid_url()),
                Ok(Err(DiagnosticError::DnsFailed)) => store.fail(id, RunFailure::dns_failed()),
                Ok(Err(_)) | Err(_) => store.fail(id, RunFailure::diagnostic_failed()),
            }
        });
        Some(id)
    }

    fn expected_host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn expected_origin(&self) -> String {
        format!("http://{}", self.expected_host())
    }

    fn session_token(&self) -> &str {
        &self.session_token
    }
}

pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/url-diagnostics", post(start_diagnostic))
        .route("/v1/runs/{id}", get(run_snapshot))
        .route("/v1/runs/{id}/events", get(run_events))
        .route(
            "/v1/runs/{id}/route-trace",
            post(route_traces::start)
                .get(route_traces::snapshot)
                .delete(route_traces::cancel),
        )
        .route(
            "/v1/runs/{id}/route-trace/events",
            get(route_traces::events),
        )
        .route(
            "/v1/network-overview",
            get(network_overview::network_overview),
        )
        .route(
            "/v1/mihomo-controller",
            put(mihomo_settings::set_mihomo_controller)
                .delete(mihomo_settings::reset_mihomo_controller),
        )
        .route("/v1/speed-tests", post(speed_tests::start))
        .route(
            "/v1/speed-tests/{id}",
            get(speed_tests::snapshot).delete(speed_tests::cancel),
        )
        .route("/v1/speed-tests/{id}/events", get(speed_tests::events))
        .route("/v1/speed-tests/{id}/samples", post(speed_tests::samples))
        .route("/v1/speed-tests/{id}/complete", post(speed_tests::complete))
        .fallback(api_not_found)
        .method_not_allowed_fallback(api_method_not_allowed)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security::require_local_session,
        ))
        .with_state(state);

    Router::new().nest("/api", api).fallback(assets::serve)
}

pub async fn bind_listener() -> std::io::Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await
}

pub async fn serve_application<S>(
    listener: TcpListener,
    app: Router,
    state: AppState,
    shutdown_signal: S,
) -> std::io::Result<()>
where
    S: Future<Output = ()> + Send,
{
    run_owned_server(listener, app, state, shutdown_signal).await
}

#[async_trait]
trait ConnectionListener: Send + Sync {
    async fn accept(&self) -> std::io::Result<tokio::net::TcpStream>;
}

#[async_trait]
impl ConnectionListener for TcpListener {
    async fn accept(&self) -> std::io::Result<tokio::net::TcpStream> {
        TcpListener::accept(self).await.map(|(stream, _)| stream)
    }
}

enum ServerStop {
    Graceful,
    AcceptError(std::io::Error),
}

struct ActiveConnectionTask {
    count: Arc<AtomicUsize>,
}

impl ActiveConnectionTask {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self { count }
    }
}

impl Drop for ActiveConnectionTask {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn run_owned_server<L, S>(
    listener: L,
    app: Router,
    state: AppState,
    shutdown_signal: S,
) -> std::io::Result<()>
where
    L: ConnectionListener,
    S: Future<Output = ()> + Send,
{
    tokio::pin!(shutdown_signal);
    let connection_shutdown = CancellationToken::new();
    let mut connections = JoinSet::new();
    let stop = loop {
        tokio::select! {
            biased;
            _ = &mut shutdown_signal => break ServerStop::Graceful,
            accepted = listener.accept() => match accepted {
                Ok(stream) => spawn_connection(
                    &mut connections,
                    stream,
                    app.clone(),
                    connection_shutdown.clone(),
                    Arc::clone(&state.active_connection_tasks),
                ),
                Err(error) => break ServerStop::AcceptError(error),
            },
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    };
    drop(listener);

    state.shutdown().await;
    connection_shutdown.cancel();
    if tokio::time::timeout(
        GRACEFUL_CONNECTION_DRAIN_TIMEOUT,
        drain_connections(&mut connections),
    )
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }

    match stop {
        ServerStop::Graceful => Ok(()),
        ServerStop::AcceptError(error) => Err(error),
    }
}

fn spawn_connection(
    connections: &mut JoinSet<()>,
    stream: tokio::net::TcpStream,
    app: Router,
    shutdown: CancellationToken,
    active_tasks: Arc<AtomicUsize>,
) {
    let active = ActiveConnectionTask::new(active_tasks);
    connections.spawn(async move {
        let _active = active;
        let service = app.map_request(|request: HyperRequest<Incoming>| request.map(Body::new));
        let service = TowerToHyperService::new(service);
        let builder = ConnectionBuilder::new(TokioExecutor::new());
        let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
        tokio::pin!(connection);
        tokio::select! {
            _ = &mut connection => {}
            _ = shutdown.cancelled() => {
                connection.as_mut().graceful_shutdown();
                let _ = connection.await;
            }
        }
    });
}

async fn drain_connections(connections: &mut JoinSet<()>) {
    while connections.join_next().await.is_some() {}
}

async fn capabilities() -> Json<Capabilities> {
    Json(Capabilities {
        platform: "macos",
        url_diagnostics: true,
        app_diagnostics: false,
        route_hops: false,
        ip_intelligence: false,
        network_overview: true,
        egress_ip: true,
        mihomo_manual_controller: true,
        route_trace: true,
        speed_tests: true,
        speed_provider: "cloudflare",
    })
}

async fn start_diagnostic(State(state): State<AppState>, request: Request) -> Response {
    let request: StartDiagnosticRequest = match read_json_body(request).await {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let permit = match Arc::clone(&state.permits).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return ApiError::too_many_runs().into_response(),
    };
    let Some(id) = state.start_url_job(request.url, permit).await else {
        return ApiError::shutting_down().into_response();
    };
    (
        StatusCode::ACCEPTED,
        Json(StartDiagnosticResponse { run_id: id }),
    )
        .into_response()
}

async fn read_json_body<T>(request: Request) -> Result<T, ApiError>
where
    T: DeserializeOwned,
{
    let body = match tokio::time::timeout(
        REQUEST_BODY_READ_TIMEOUT,
        to_bytes(request.into_body(), BODY_LIMIT),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => return Err(ApiError::payload_too_large()),
        Err(_) => return Err(ApiError::request_timeout()),
    };
    serde_json::from_slice(&body).map_err(|_| ApiError::invalid_request())
}

async fn run_snapshot(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match parse_id(&id).and_then(|id| state.store.snapshot(id)) {
        Some(snapshot) => Json(snapshot).into_response(),
        None => ApiError::run_not_found().into_response(),
    }
}

async fn run_events(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(id) = parse_id(&id) else {
        return ApiError::run_not_found().into_response();
    };
    let Some(subscription) = state.store.subscribe(id) else {
        return ApiError::run_not_found().into_response();
    };
    let last_sequence = subscription.history.last().map(|event| event.sequence);
    let history = stream::iter(subscription.history.into_iter().map(stage_response));
    if subscription.terminal {
        return Sse::new(history).into_response();
    }
    let live = stream::unfold(
        (subscription.receiver, last_sequence, false),
        |(mut receiver, last_sequence, terminal)| async move {
            if terminal {
                return None;
            }
            loop {
                match receiver.recv().await {
                    Ok(event) if last_sequence.is_none_or(|last| event.sequence > last) => {
                        let terminal = matches!(event.stage.as_str(), "completed" | "failed");
                        return Some((
                            stage_response(event.clone()),
                            (receiver, Some(event.sequence), terminal),
                        ));
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    );
    Sse::new(history.chain(live)).into_response()
}

fn stage_response(event: runs::RunStageEvent) -> Result<Event, Infallible> {
    Ok(Event::default()
        .event("stage")
        .data(serde_json::to_string(&event).expect("stage events serialize")))
}

fn parse_id(value: &str) -> Option<Uuid> {
    value.parse().ok()
}

async fn api_not_found() -> Response {
    ApiError::run_not_found().into_response()
}

async fn api_method_not_allowed() -> Response {
    ApiError::method_not_allowed().into_response()
}

#[derive(Deserialize)]
struct StartDiagnosticRequest {
    url: String,
}

#[derive(Serialize)]
struct StartDiagnosticResponse {
    run_id: Uuid,
}

#[derive(Serialize)]
struct Capabilities {
    platform: &'static str,
    url_diagnostics: bool,
    app_diagnostics: bool,
    route_hops: bool,
    ip_intelligence: bool,
    network_overview: bool,
    egress_ip: bool,
    mihomo_manual_controller: bool,
    route_trace: bool,
    speed_tests: bool,
    speed_provider: &'static str,
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: &'static str,
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "本地会话已失效，请重新启动工具",
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: "请求必须来自本机工具页面",
        }
    }

    fn payload_too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "payload_too_large",
            message: "请求体超过 8 KiB 限制",
        }
    }

    fn invalid_request() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: "请求格式无效",
        }
    }

    fn request_timeout() -> Self {
        Self {
            status: StatusCode::REQUEST_TIMEOUT,
            code: "request_timeout",
            message: "请求体读取超时，请重试",
        }
    }

    fn too_many_runs() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "too_many_runs",
            message: "当前诊断任务过多，请稍后重试",
        }
    }

    fn shutting_down() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "shutting_down",
            message: "诊断服务正在关闭，请重新启动工具",
        }
    }

    fn run_not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "run_not_found",
            message: "未找到诊断任务",
        }
    }

    fn method_not_allowed() -> Self {
        Self {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: "method_not_allowed",
            message: "不支持此请求方法",
        }
    }

    fn overview_unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "network_overview_unavailable",
            message: "网络概览暂时不可用，请稍后重试",
        }
    }

    fn mihomo_unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "mihomo_unavailable",
            message: "Clash 控制服务暂时不可用",
        }
    }

    fn run_not_ready() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "run_not_ready",
            message: "网址诊断尚未完成，请稍后重试",
        }
    }

    fn trace_target_unavailable() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "trace_target_unavailable",
            message: "当前网址没有可确认的实际跳点目标",
        }
    }

    fn trace_already_started() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "trace_already_started",
            message: "该网址的跳点探测已启动",
        }
    }

    fn trace_not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "trace_not_found",
            message: "未找到网络跳点探测任务",
        }
    }

    fn too_many_traces() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "too_many_traces",
            message: "当前跳点探测任务过多，请稍后重试",
        }
    }

    fn too_many_speed_tests() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "too_many_speed_tests",
            message: "当前测速任务过多，请稍后重试",
        }
    }

    fn speed_test_not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "speed_test_not_found",
            message: "未找到测速任务",
        }
    }

    fn speed_invalid_request() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "speed_invalid_request",
            message: "测速请求参数无效",
        }
    }

    fn speed_not_ready() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "speed_not_ready",
            message: "测速采样尚未满足完成条件",
        }
    }

    fn speed_already_finished() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "speed_already_finished",
            message: "测速任务已经结束",
        }
    }

    fn speed_timeout() -> Self {
        Self {
            status: StatusCode::REQUEST_TIMEOUT,
            code: "speed_timeout",
            message: "测速超过时间上限，已停止",
        }
    }

    fn speed_cancelled() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "speed_cancelled",
            message: "测速已取消",
        }
    }

    fn speed_unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "speed_unavailable",
            message: "测速观察服务暂时不可用，请稍后重试",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                code: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::pending, sync::Mutex as StdMutex};

    struct PendingRunner {
        started: Arc<tokio::sync::Notify>,
        order: Arc<StdMutex<Vec<&'static str>>>,
    }

    struct JobDrop(Arc<StdMutex<Vec<&'static str>>>);

    struct FailingListener {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl ConnectionListener for FailingListener {
        async fn accept(&self) -> std::io::Result<tokio::net::TcpStream> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "controlled accept failure",
            ))
        }
    }

    impl Drop for JobDrop {
        fn drop(&mut self) {
            self.0.lock().unwrap().push("api_job_cancelled");
        }
    }

    #[async_trait]
    impl UrlRunner for PendingRunner {
        async fn run(
            &self,
            _input: &str,
            _progress: &dyn ProgressSink,
        ) -> Result<UrlDiagnosticResult, DiagnosticError> {
            let _drop = JobDrop(Arc::clone(&self.order));
            self.started.notify_one();
            pending().await
        }

        async fn shutdown(&self) {
            self.order.lock().unwrap().push("url_workers_drained");
        }
    }

    #[tokio::test]
    async fn accept_error_is_returned_once_after_ordered_cleanup_without_retrying() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let order = Arc::new(StdMutex::new(Vec::new()));
        let started = Arc::new(tokio::sync::Notify::new());
        let manager = Arc::new(MihomoControllerManager::new());
        let state = AppState::new(
            8765,
            "token",
            Arc::new(PendingRunner {
                started: Arc::clone(&started),
                order: Arc::clone(&order),
            }),
        )
        .with_mihomo_manager(Arc::clone(&manager));
        let permit = Arc::clone(&state.permits).acquire_owned().await.unwrap();
        state
            .start_url_job("https://example.com".into(), permit)
            .await
            .unwrap();
        started.notified().await;

        let result = run_owned_server(
            FailingListener {
                calls: Arc::clone(&calls),
            },
            Router::new(),
            state,
            pending(),
        )
        .await;

        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            &*order.lock().unwrap(),
            &["api_job_cancelled", "url_workers_drained"]
        );
        let target = crate::ports::TrafficProbeTarget::new(
            crate::ports::TrafficProbeScheme::Https,
            "example.com",
            443,
            Vec::new(),
            42,
        );
        assert!(manager.begin(&target).await.is_err());
    }
}
