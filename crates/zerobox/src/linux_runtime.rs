use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tempfile::TempDir;
use zerobox_sandboxing::landlock::ZEROBOX_LINUX_SANDBOX_ARG0;

const MAX_UNIX_SOCKET_PATH_BYTES: usize = 107;

/// Owner-only, per-execution state that must not live below the sandboxed
/// workspace. The contained paths are intentionally short for AF_UNIX users.
pub(crate) struct LinuxRuntime {
    _root: TempDir,
    parent: PathBuf,
    helper: PathBuf,
    env_root: PathBuf,
    views_root: PathBuf,
    proxy_root: PathBuf,
    docker_root: PathBuf,
}

impl LinuxRuntime {
    pub(crate) fn create(
        cwd: &Path,
        writable_roots: &[PathBuf],
        helper_source: &Path,
    ) -> Result<Self> {
        let uid = unsafe { libc::geteuid() };
        let candidates = runtime_parent_candidates(uid);
        Self::create_from_candidates(cwd, writable_roots, helper_source, uid, &candidates)
    }

    fn create_from_candidates(
        cwd: &Path,
        writable_roots: &[PathBuf],
        helper_source: &Path,
        uid: u32,
        candidates: &[PathBuf],
    ) -> Result<Self> {
        let cwd = absolute_path(cwd, cwd);
        let writable_roots = writable_roots
            .iter()
            .map(|root| absolute_path(root, &cwd))
            .collect::<Vec<_>>();
        let mut failures = Vec::new();

        for candidate in candidates {
            if paths_overlap(candidate, &cwd)
                || writable_roots
                    .iter()
                    .any(|writable| paths_overlap(candidate, writable))
            {
                failures.push(format!(
                    "{} overlaps sandbox policy roots",
                    candidate.display()
                ));
                continue;
            }

            match Self::create_in(candidate, helper_source, uid) {
                Ok(runtime) => return Ok(runtime),
                Err(error) => failures.push(format!("{}: {error:#}", candidate.display())),
            }
        }

        bail!(
            "no safe private Linux runtime root is available ({})",
            failures.join("; ")
        )
    }

    fn create_in(parent: &Path, helper_source: &Path, uid: u32) -> Result<Self> {
        create_private_runtime_parent(parent, uid)?;
        validate_runtime_socket_budget(parent)?;

        let root = tempfile::Builder::new()
            .prefix(&format!("r-{}-", std::process::id()))
            .tempdir_in(parent)
            .with_context(|| {
                format!(
                    "failed to allocate private Linux runtime under {}",
                    parent.display()
                )
            })?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        validate_private_directory(root.path(), uid)?;

        let helper_dir = create_private_subdirectory(root.path(), "h", uid)?;
        let env_root = create_private_subdirectory(root.path(), "e", uid)?;
        let views_root = create_private_subdirectory(root.path(), "v", uid)?;
        let proxy_root = create_private_subdirectory(root.path(), "p", uid)?;
        let docker_root = create_private_subdirectory(root.path(), "d", uid)?;
        let helper = helper_dir.join(ZEROBOX_LINUX_SANDBOX_ARG0);
        stage_helper(helper_source, &helper, uid)?;

        Ok(Self {
            _root: root,
            parent: parent.to_path_buf(),
            helper,
            env_root,
            views_root,
            proxy_root,
            docker_root,
        })
    }

    pub(crate) fn parent(&self) -> &Path {
        &self.parent
    }

    pub(crate) fn helper(&self) -> &Path {
        &self.helper
    }

    pub(crate) fn env_root(&self) -> &Path {
        &self.env_root
    }

    pub(crate) fn views_root(&self) -> &Path {
        &self.views_root
    }

    pub(crate) fn proxy_root(&self) -> &Path {
        &self.proxy_root
    }

    pub(crate) fn docker_root(&self) -> &Path {
        &self.docker_root
    }

    #[cfg(test)]
    fn root(&self) -> &Path {
        self._root.path()
    }
}

fn runtime_parent_candidates(uid: u32) -> [PathBuf; 2] {
    [
        PathBuf::from(format!("/run/user/{uid}/zbx")),
        PathBuf::from(format!("/var/tmp/zbx-{uid}")),
    ]
}

fn absolute_path(path: &Path, cwd: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    absolute.canonicalize().unwrap_or(absolute)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn create_private_runtime_parent(path: &Path, uid: u32) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path, uid),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(path).with_context(|| {
                format!("failed to create Linux runtime root {}", path.display())
            })?;
            validate_private_directory(path, uid)
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect Linux runtime root {}", path.display())),
    }
}

fn create_private_subdirectory(parent: &Path, name: &str, uid: u32) -> Result<PathBuf> {
    let path = parent.join(name);
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&path)
        .with_context(|| format!("failed to create private runtime path {}", path.display()))?;
    validate_private_directory(&path, uid)?;
    Ok(path)
}

fn validate_private_directory(path: &Path, uid: u32) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private runtime path {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        bail!(
            "private Linux runtime path must be a non-symlink owner directory with mode 0700: {}",
            path.display()
        );
    }
    Ok(())
}

fn validate_runtime_socket_budget(parent: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let worst_case = parent.join(format!(
        "r-{}-XXXXXXXXXXXX/d/zerobox-run-{}-XXXXXXXXXXXXXXXX/broker.sock",
        u32::MAX,
        u32::MAX
    ));
    if worst_case.as_os_str().as_bytes().len() > MAX_UNIX_SOCKET_PATH_BYTES {
        bail!(
            "private Linux runtime root is too long for AF_UNIX sockets: {}",
            parent.display()
        );
    }
    Ok(())
}

pub(crate) fn stage_helper(source: &Path, destination: &Path, uid: u32) -> Result<()> {
    let source = source
        .canonicalize()
        .with_context(|| format!("failed to resolve Linux helper {}", source.display()))?;
    let source_metadata = std::fs::metadata(&source)
        .with_context(|| format!("failed to inspect Linux helper {}", source.display()))?;
    if !source_metadata.is_file() {
        bail!(
            "Linux helper source is not a regular file: {}",
            source.display()
        );
    }

    let source_mode = source_metadata.permissions().mode() & 0o777;
    if source_mode == 0o500 && std::fs::hard_link(&source, destination).is_ok() {
        validate_staged_helper(destination, uid)?;
        return Ok(());
    }

    let temporary = destination.with_extension(format!("tmp-{}", std::process::id()));
    let copy_result = (|| -> Result<()> {
        let mut input = File::open(&source)
            .with_context(|| format!("failed to open Linux helper {}", source.display()))?;
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o500)
            .open(&temporary)
            .with_context(|| {
                format!(
                    "failed to create staged Linux helper {}",
                    temporary.display()
                )
            })?;
        let mut buffer = [0u8; 128 * 1024];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            output.write_all(&buffer[..read])?;
        }
        output.sync_all()?;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o500))?;
        std::fs::rename(&temporary, destination)?;
        File::open(destination.parent().expect("helper destination parent"))?.sync_all()?;
        Ok(())
    })();
    if let Err(error) = copy_result {
        let _ = std::fs::remove_file(&temporary);
        return Err(error).context("failed to stage private Linux helper");
    }

    validate_staged_helper(destination, uid)
}

fn validate_staged_helper(path: &Path, uid: u32) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect staged Linux helper {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != 0o500
    {
        bail!(
            "staged Linux helper must be an owner-only regular executable: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executable(path: &Path) {
        std::fs::write(path, b"helper").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn selector_skips_workspace_candidate_and_uses_safe_fallback() {
        let workspace = tempfile::tempdir().unwrap();
        let safe = tempfile::tempdir().unwrap();
        let helper = safe.path().join("source");
        executable(&helper);
        let candidates = [workspace.path().join("zbx"), safe.path().join("zbx")];

        let runtime = LinuxRuntime::create_from_candidates(
            workspace.path(),
            &[workspace.path().to_path_buf()],
            &helper,
            unsafe { libc::geteuid() },
            &candidates,
        )
        .unwrap();

        assert!(runtime.root().starts_with(&candidates[1]));
        let metadata = std::fs::symlink_metadata(runtime.helper()).unwrap();
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o500);
        let runtime_path = runtime.root().to_path_buf();
        drop(runtime);
        assert!(!runtime_path.exists());
    }

    #[test]
    fn selector_rejects_symlink_and_wrong_owner_roots() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        let link = temp.path().join("link");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(validate_private_directory(&link, unsafe { libc::geteuid() }).is_err());
        assert!(validate_private_directory(&real, unsafe { libc::geteuid() } + 1).is_err());
    }

    #[test]
    fn selector_fails_when_every_candidate_overlaps_policy_roots() {
        let workspace = tempfile::tempdir().unwrap();
        let helper = workspace.path().join("source");
        executable(&helper);
        let candidates = [workspace.path().join("one"), workspace.path().join("two")];

        let error = LinuxRuntime::create_from_candidates(
            workspace.path(),
            &[],
            &helper,
            unsafe { libc::geteuid() },
            &candidates,
        )
        .err()
        .expect("all overlapping candidates must fail");

        assert!(
            error
                .to_string()
                .contains("no safe private Linux runtime root")
        );
    }

    #[test]
    fn socket_budget_rejects_long_runtime_roots() {
        let long = PathBuf::from(format!("/var/tmp/{}", "x".repeat(90)));
        assert!(validate_runtime_socket_budget(&long).is_err());
    }
}
