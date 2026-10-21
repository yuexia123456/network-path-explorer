use super::{ControllerConfig, MihomoEndpoint};
use std::{fs, os::unix::fs::FileTypeExt, path::Path};

pub fn discover_clash_verge_controller() -> Option<ControllerConfig> {
    let path = MihomoEndpoint::clash_verge_socket_path();
    is_unix_socket(path).then(|| ControllerConfig::new(MihomoEndpoint::clash_verge_unix(), None))
}

fn is_unix_socket(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::is_unix_socket;
    use std::fs;

    #[test]
    fn discovery_ignores_a_regular_file_at_the_candidate_path() {
        let path = std::env::temp_dir().join(format!(
            "network-path-agent-mihomo-regular-file-{}",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, b"not a socket").unwrap();

        let discovered = is_unix_socket(&path);

        fs::remove_file(path).unwrap();
        assert!(!discovered);
    }
}
