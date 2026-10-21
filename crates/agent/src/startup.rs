use std::{
    io::{self, Write},
    net::SocketAddr,
    process::{Command, ExitStatus},
};
use uuid::Uuid;

pub fn session_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub fn launch_url(listener_address: SocketAddr, token: &str) -> String {
    format!(
        "http://127.0.0.1:{}/#token={token}",
        listener_address.port()
    )
}

pub fn open_browser(launch_url: &str) {
    let mut fallback = io::stderr().lock();
    open_browser_with(launch_url, |mut command| command.status(), &mut fallback);
}

pub fn open_browser_with<F, W>(launch_url: &str, run_command: F, fallback: &mut W)
where
    F: FnOnce(Command) -> io::Result<ExitStatus>,
    W: Write,
{
    match run_command(browser_command(launch_url)) {
        Ok(status) if status.success() => {}
        Ok(_) | Err(_) => {
            let _ = writeln!(fallback, "Open this URL manually: {launch_url}");
        }
    }
}

fn browser_command(launch_url: &str) -> Command {
    let mut command = Command::new("/usr/bin/open");
    command.arg(launch_url);
    command
}
