#[derive(Debug, thiserror::Error)]
pub enum DiagnosticError {
    #[error("请输入有效的网址")]
    InvalidUrl,
    #[error("暂时无法把网址转换成 IP")]
    DnsFailed,
    #[error("系统网络信息读取失败: {0}")]
    System(String),
    #[error("连接测试失败: {0}")]
    Http(String),
    #[error("网络跳点探测失败")]
    RouteTraceFailed,
    #[error("网络跳点探测超时")]
    RouteTraceTimeout,
    #[error("网络跳点探测已取消")]
    RouteTraceCancelled,
}
