use std::ffi::OsStr;

pub(crate) const RUN_DIR_PREFIX: &str = "run-";

pub(crate) fn owned_run_prefix() -> String {
    format!("{RUN_DIR_PREFIX}{}-", std::process::id())
}

pub(crate) fn owner_pid(name: &OsStr) -> Option<libc::pid_t> {
    let remainder = name.to_str()?.strip_prefix(RUN_DIR_PREFIX)?;
    let pid = remainder.split_once('-')?.0.parse::<i64>().ok()?;
    if pid <= 0 || pid > i64::from(libc::pid_t::MAX) {
        return None;
    }
    Some(pid as libc::pid_t)
}

pub(crate) fn is_process_alive(pid: libc::pid_t) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        let zombie = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("State:"))
                    .and_then(|state| state.split_whitespace().next())
                    .map(|state| state == "Z")
            })
            .unwrap_or(false);
        return !zombie;
    }
    !matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    )
}
