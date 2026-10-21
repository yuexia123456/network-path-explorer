use network_path_agent::{
    api::{AppState, bind_listener, build_router, serve_application},
    diagnostics::url::UrlDiagnosticService,
    network::{
        egress::IpifyEgressProvider, http::ReqwestWebProbe, path::SystemRequestPathPlanner,
        resolver::TokioResolver,
    },
    platform::macos::{
        network::MacNetworkOverviewProvider, proxy::MacProxyInspector, route::MacRouteInspector,
    },
    ports::TrafficDecisionProvider,
    speed::{SpeedCoordinator, SpeedTestService},
    startup::{launch_url, open_browser, session_token},
    traffic::mihomo::MihomoControllerManager,
};
use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = bind_listener().await?;
    let listener_address = listener.local_addr()?;
    let port = listener_address.port();
    let token = session_token();
    let launch_url = launch_url(listener_address, &token);
    let mihomo_manager = Arc::new(MihomoControllerManager::new());
    let initial_mihomo_runtime = match tokio::time::timeout(
        Duration::from_secs(1),
        TrafficDecisionProvider::runtime(mihomo_manager.as_ref()),
    )
    .await
    {
        Ok(runtime) => runtime,
        Err(_) => mihomo_manager.runtime().await,
    };
    let request_path_planner = Arc::new(SystemRequestPathPlanner::new(
        MacProxyInspector,
        TokioResolver,
        MacRouteInspector,
    ));
    let runner = Arc::new(UrlDiagnosticService::from_planner(
        Arc::clone(&request_path_planner),
        ReqwestWebProbe,
        Arc::clone(&mihomo_manager),
    ));
    let local_overview = Arc::new(MacNetworkOverviewProvider::new(initial_mihomo_runtime));
    let egress = Arc::new(IpifyEgressProvider::new(
        Arc::clone(&request_path_planner),
        Arc::clone(&mihomo_manager),
    ));
    let speed_service: Arc<dyn SpeedTestService> =
        Arc::new(SpeedCoordinator::new(Arc::clone(&mihomo_manager)));
    let state = AppState::new(port, token, runner)
        .with_mihomo_manager(Arc::clone(&mihomo_manager))
        .with_network_overview(local_overview, egress)
        .with_speed_service(speed_service);
    let app = build_router(state.clone());

    open_browser(&launch_url);
    serve_application(listener, app, state, shutdown_signal()).await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
