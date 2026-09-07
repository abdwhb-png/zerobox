use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use fuser::{
    AccessFlags, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, LockOwner, MountOption, OpenFlags, RenameFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
    ReplyWrite, Request, TimeOrNow, WriteFlags,
};
use globset::{GlobBuilder, GlobMatcher};
use zerobox_protocol::permissions::FileSystemSandboxPolicy;

use crate::process_owner::{is_process_alive, owned_run_prefix, owner_pid};

const GLOB_META: [char; 6] = ['*', '?', '[', ']', '{', '}'];
// FUSE exposes this kernel-internal bit on opens originating from execve(2).
// It is not a userspace O_* flag and must not be forwarded to openat2(2).
const FMODE_EXEC: i32 = 0x20;

#[derive(Debug, Clone)]
struct CompiledPattern {
    matcher: GlobMatcher,
    mount_root: PathBuf,
    mount_destination: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct DynamicDenyPolicy {
    deny_read: Vec<CompiledPattern>,
    deny_write: Vec<CompiledPattern>,
    mount_roots: Vec<PathBuf>,
    mount_destinations: Vec<PathBuf>,
    base_policy: FileSystemSandboxPolicy,
    cwd: PathBuf,
    access_cache: Arc<Mutex<HashMap<PathBuf, (bool, bool)>>>,
}

impl DynamicDenyPolicy {
    #[cfg(test)]
    pub(crate) fn compile(
        cwd: &Path,
        deny_read: &[String],
        deny_write: &[String],
    ) -> Result<Option<Self>> {
        Self::compile_with_base_policy(
            cwd,
            deny_read,
            deny_write,
            FileSystemSandboxPolicy::unrestricted(),
        )
    }

    fn compile_with_base_policy(
        cwd: &Path,
        deny_read: &[String],
        deny_write: &[String],
        base_policy: FileSystemSandboxPolicy,
    ) -> Result<Option<Self>> {
        if deny_read.is_empty() && deny_write.is_empty() {
            return Ok(None);
        }
        if !cwd.is_absolute() {
            bail!("dynamic deny glob root must be absolute: {}", cwd.display());
        }

        let canonical_cwd = std::fs::canonicalize(cwd).with_context(|| {
            format!("failed to canonicalize dynamic deny root {}", cwd.display())
        })?;
        let deny_read = deny_read
            .iter()
            .map(|pattern| compile_pattern(cwd, &canonical_cwd, pattern))
            .collect::<Result<Vec<_>>>()?;
        let deny_write = deny_write
            .iter()
            .map(|pattern| compile_pattern(cwd, &canonical_cwd, pattern))
            .collect::<Result<Vec<_>>>()?;
        let mut mount_roots = deny_read
            .iter()
            .chain(&deny_write)
            .map(|pattern| {
                (
                    pattern.mount_root.clone(),
                    pattern.mount_destination.clone(),
                )
            })
            .collect::<Vec<_>>();
        mount_roots.sort_by_key(|(path, _)| path.components().count());
        let mut minimal_roots = Vec::<(PathBuf, PathBuf)>::new();
        for (root, destination) in mount_roots {
            if minimal_roots
                .iter()
                .any(|(existing_root, existing_destination)| {
                    root.starts_with(existing_root) && destination.starts_with(existing_destination)
                })
            {
                continue;
            }
            minimal_roots.push((root, destination));
        }
        let (mount_roots, mount_destinations) = minimal_roots.into_iter().unzip();

        Ok(Some(Self {
            deny_read,
            deny_write,
            mount_roots,
            mount_destinations,
            base_policy,
            cwd: canonical_cwd,
            access_cache: Arc::new(Mutex::new(HashMap::new())),
        }))
    }

    pub(crate) fn mount_roots(&self) -> &[PathBuf] {
        &self.mount_roots
    }

    pub(crate) fn is_read_denied(&self, requested: &Path, resolved: Option<&Path>) -> bool {
        self.path_access(requested).0 || resolved.is_some_and(|path| self.path_access(path).0)
    }

    pub(crate) fn is_write_denied(&self, requested: &Path, resolved: Option<&Path>) -> bool {
        self.path_access(requested).1 || resolved.is_some_and(|path| self.path_access(path).1)
    }

    fn path_access(&self, path: &Path) -> (bool, bool) {
        // Cache only the immutable policy's answer for a lexical path. Never
        // cache inode metadata, data, existence, or a symlink/FD resolution:
        // every operation still supplies its freshly resolved destination.
        const MAX_CACHED_PATHS: usize = 8192;
        if let Some(access) = self
            .access_cache
            .lock()
            .expect("policy cache poisoned")
            .get(path)
        {
            return *access;
        }
        let read_denied = !self.base_policy.can_read_path_with_cwd(path, &self.cwd)
            || matches_any(&self.deny_read, path);
        let write_denied = read_denied
            || !self.base_policy.can_write_path_with_cwd(path, &self.cwd)
            || matches_any(&self.deny_write, path);
        let access = (read_denied, write_denied);
        let mut cache = self.access_cache.lock().expect("policy cache poisoned");
        if cache.len() >= MAX_CACHED_PATHS {
            cache.clear();
        }
        cache.insert(path.to_path_buf(), access);
        access
    }
}

pub(crate) fn dynamic_deny_mount_roots(
    cwd: &Path,
    deny_read: &[String],
    deny_write: &[String],
) -> Result<Vec<PathBuf>> {
    if deny_read.is_empty() && deny_write.is_empty() {
        return Ok(Vec::new());
    }
    if !cwd.is_absolute() {
        bail!("dynamic deny glob root must be absolute: {}", cwd.display());
    }
    let canonical_cwd = std::fs::canonicalize(cwd)
        .with_context(|| format!("failed to canonicalize dynamic deny root {}", cwd.display()))?;
    let mut roots = deny_read
        .iter()
        .chain(deny_write)
        .map(|pattern| compile_pattern(cwd, &canonical_cwd, pattern).map(|entry| entry.mount_root))
        .collect::<Result<Vec<_>>>()?;
    roots.sort_by_key(|path| path.components().count());
    roots.dedup();
    Ok(roots)
}

fn compile_pattern(cwd: &Path, canonical_cwd: &Path, source: &str) -> Result<CompiledPattern> {
    if source.is_empty() {
        bail!("dynamic deny glob must not be empty");
    }
    if source.as_bytes().contains(&0) {
        bail!("dynamic deny glob must not contain NUL");
    }

    let expanded = expand_home(source)?;
    if has_parent_component(Path::new(&expanded)) {
        bail!("dynamic deny glob must not contain '..': {source:?}");
    }
    let relative = !Path::new(&expanded).is_absolute();
    let anchored = if relative {
        let pattern = if expanded.contains('/') {
            expanded
        } else {
            format!("**/{expanded}")
        };
        canonical_cwd.join(pattern)
    } else {
        PathBuf::from(expanded)
    };
    let mut anchored = normalize_pattern_path(&anchored)?;
    let (mount_root, mount_destination) = if relative {
        (canonical_cwd.to_path_buf(), cwd.to_path_buf())
    } else {
        let destination = safe_static_prefix(&anchored)?;
        let mount_root = std::fs::canonicalize(&destination).with_context(|| {
            format!(
                "failed to canonicalize dynamic deny prefix {}",
                destination.display()
            )
        })?;
        let suffix = anchored.strip_prefix(&destination).map_err(|_| {
            anyhow::anyhow!("dynamic deny glob prefix mismatch: {}", anchored.display())
        })?;
        anchored = mount_root.join(suffix);
        (mount_root, destination)
    };
    let pattern = anchored.to_string_lossy().into_owned();

    let matcher = GlobBuilder::new(&pattern)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
        .with_context(|| format!("invalid dynamic deny glob {source:?}"))?
        .compile_matcher();

    Ok(CompiledPattern {
        matcher,
        mount_root,
        mount_destination,
    })
}

fn expand_home(source: &str) -> Result<String> {
    if source == "~" || source.starts_with("~/") {
        let home = dirs::home_dir().context("cannot expand '~' without a home directory")?;
        if source == "~" {
            return Ok(home.to_string_lossy().into_owned());
        }
        return Ok(home.join(&source[2..]).to_string_lossy().into_owned());
    }
    Ok(source.to_string())
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| component == Component::ParentDir)
}

fn normalize_pattern_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized.parent().is_none() || !normalized.pop() {
                    bail!("dynamic deny glob escapes its root: {}", path.display());
                }
            }
        }
    }
    Ok(normalized)
}

fn safe_static_prefix(pattern: &Path) -> Result<PathBuf> {
    let mut prefix = PathBuf::new();
    let mut found_meta = false;
    for component in pattern.components() {
        let text = component.as_os_str().to_string_lossy();
        if text.chars().any(|character| GLOB_META.contains(&character)) {
            found_meta = true;
            break;
        }
        prefix.push(component.as_os_str());
    }
    if !found_meta {
        prefix.pop();
    }
    while prefix != Path::new("/") && !prefix.is_dir() {
        prefix.pop();
    }
    if prefix == Path::new("/") || prefix.as_os_str().is_empty() {
        bail!(
            "dynamic deny glob has no safe static prefix below '/': {}",
            pattern.display()
        );
    }
    Ok(prefix)
}

fn matches_any(patterns: &[CompiledPattern], path: &Path) -> bool {
    path.ancestors().any(|candidate| {
        patterns.iter().any(|pattern| {
            pattern.matcher.is_match(candidate) || {
                let mut directory = candidate.as_os_str().to_os_string();
                directory.push("/");
                pattern.matcher.is_match(Path::new(&directory))
            }
        })
    })
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DynamicBindMount {
    pub(crate) source: PathBuf,
    pub(crate) destination: PathBuf,
}

pub(crate) struct DynamicDenyMounts {
    _sessions: Vec<fuser::BackgroundSession>,
    _root: tempfile::TempDir,
    binds: Vec<DynamicBindMount>,
    #[cfg(test)]
    policy: Arc<DynamicDenyPolicy>,
}

impl DynamicDenyMounts {
    pub(crate) fn prepare_in(
        cwd: &Path,
        deny_read: &[String],
        deny_write: &[String],
        base_policy: &FileSystemSandboxPolicy,
        parent: &Path,
    ) -> Result<Option<Self>> {
        let Some(policy) = DynamicDenyPolicy::compile_with_base_policy(
            cwd,
            deny_read,
            deny_write,
            base_policy.clone(),
        )?
        else {
            return Ok(None);
        };
        ensure_fuse_available()?;
        create_private_directory(parent)?;
        cleanup_stale_view_roots(parent)?;
        let root = tempfile::Builder::new()
            .prefix(&owned_run_prefix())
            .tempdir_in(parent)
            .with_context(|| {
                format!(
                    "failed to create private dynamic filesystem root under {}",
                    parent.display()
                )
            })?;
        set_mode(root.path(), 0o700)?;
        let policy = Arc::new(policy);
        let mut sessions = Vec::new();
        let mut binds = Vec::new();

        for (index, (lower_root, destination)) in policy
            .mount_roots()
            .iter()
            .zip(&policy.mount_destinations)
            .enumerate()
        {
            let mountpoint = root.path().join(format!("view-{index}"));
            std::fs::create_dir(&mountpoint).with_context(|| {
                format!("failed to create FUSE mountpoint {}", mountpoint.display())
            })?;
            set_mode(&mountpoint, 0o700)?;
            let filesystem = GuardedPassthroughFs::new(lower_root, Arc::clone(&policy))?;
            let mut config = Config::default();
            config.mount_options.extend([
                MountOption::FSName("zerobox-dynamic-deny".to_string()),
                MountOption::DefaultPermissions,
                MountOption::NoDev,
                MountOption::NoSuid,
                MountOption::RW,
            ]);
            config.n_threads = Some(4);
            config.clone_fd = true;
            let session =
                fuser::spawn_mount(filesystem, &mountpoint, &config).with_context(|| {
                    format!(
                        "failed to mount guarded FUSE view at {}",
                        mountpoint.display()
                    )
                })?;
            sessions.push(session);
            binds.push(DynamicBindMount {
                source: mountpoint,
                destination: destination.clone(),
            });
        }

        Ok(Some(Self {
            #[cfg(test)]
            policy,
            _sessions: sessions,
            _root: root,
            binds,
        }))
    }

    pub(crate) fn binds(&self) -> &[DynamicBindMount] {
        &self.binds
    }

    #[cfg(test)]
    fn root(&self) -> &Path {
        self._root.path()
    }
}

fn ensure_fuse_available() -> Result<()> {
    let metadata = std::fs::metadata("/dev/fuse")
        .context("dynamic deny globs require an accessible /dev/fuse")?;
    if !metadata.file_type().is_char_device() {
        bail!("dynamic deny globs require /dev/fuse to be a character device");
    }
    if find_in_path("fusermount3").is_none() {
        bail!("dynamic deny globs require fusermount3 on PATH");
    }
    Ok(())
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

fn create_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("failed to create private directory {}", path.display()))?;
    set_mode(path, 0o700)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "private path must be a non-symlink directory: {}",
            path.display()
        );
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to restrict {}", path.display()))
}

fn cleanup_stale_view_roots(parent: &Path) -> Result<()> {
    let mountpoints = current_mountpoints()?;
    cleanup_stale_view_roots_with(parent, &mountpoints, |path| {
        let fusermount = find_in_path("fusermount3")
            .context("cannot unmount stale FUSE view without fusermount3")?;
        let status = std::process::Command::new(fusermount)
            .args(["-u", "-z", "--"])
            .arg(path)
            .status()
            .with_context(|| format!("failed to invoke fusermount3 for {}", path.display()))?;
        if !status.success() {
            bail!("fusermount3 rejected stale FUSE view {}", path.display());
        }
        Ok(())
    })
}

fn cleanup_stale_view_roots_with(
    parent: &Path,
    mountpoints: &[PathBuf],
    mut unmount: impl FnMut(&Path) -> Result<()>,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    for entry in std::fs::read_dir(parent)
        .with_context(|| format!("failed to inspect dynamic view root {}", parent.display()))?
    {
        let entry = entry?;
        let Some(_pid) = owner_pid(&entry.file_name()).filter(|pid| !is_process_alive(*pid)) else {
            continue;
        };
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            continue;
        }
        let mut stale_mounts = mountpoints
            .iter()
            .filter(|mountpoint| mountpoint.as_path() == path || mountpoint.starts_with(&path))
            .cloned()
            .collect::<Vec<_>>();
        stale_mounts.sort_by_key(|mountpoint| std::cmp::Reverse(mountpoint.components().count()));
        for mountpoint in stale_mounts {
            unmount(&mountpoint).with_context(|| {
                format!("failed to unmount stale FUSE view {}", mountpoint.display())
            })?;
        }
        std::fs::remove_dir_all(&path)
            .with_context(|| format!("failed to remove stale FUSE root {}", path.display()))?;
    }
    Ok(())
}

fn current_mountpoints() -> Result<Vec<PathBuf>> {
    let mountinfo = std::fs::read("/proc/self/mountinfo")
        .context("failed to inspect current mounts before FUSE cleanup")?;
    mountinfo
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let mountpoint = line
                .split(|byte| byte.is_ascii_whitespace())
                .nth(4)
                .context("invalid /proc/self/mountinfo entry")?;
            decode_mountinfo_path(mountpoint)
        })
        .collect()
}

fn decode_mountinfo_path(encoded: &[u8]) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] == b'\\' && index + 3 < encoded.len() {
            let digits = &encoded[index + 1..index + 4];
            if digits.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
                let value = (digits[0] - b'0') * 64 + (digits[1] - b'0') * 8 + (digits[2] - b'0');
                decoded.push(value);
                index += 4;
                continue;
            }
        }
        decoded.push(encoded[index]);
        index += 1;
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(decoded)))
}

#[derive(Debug)]
struct OpenHandle {
    file: File,
    path: PathBuf,
}

#[derive(Debug)]
struct FuseState {
    path_by_inode: HashMap<u64, PathBuf>,
    inode_by_path: HashMap<PathBuf, u64>,
    handles: HashMap<u64, OpenHandle>,
    next_inode: u64,
    next_handle: u64,
}

impl FuseState {
    fn new() -> Self {
        Self {
            path_by_inode: HashMap::from([(INodeNo::ROOT.0, PathBuf::new())]),
            inode_by_path: HashMap::from([(PathBuf::new(), INodeNo::ROOT.0)]),
            handles: HashMap::new(),
            next_inode: INodeNo::ROOT.0 + 1,
            next_handle: 1,
        }
    }

    fn inode_for_path(&mut self, path: &Path) -> INodeNo {
        if let Some(inode) = self.inode_by_path.get(path) {
            return INodeNo(*inode);
        }
        let inode = self.next_inode;
        self.next_inode = self.next_inode.saturating_add(1);
        let path = path.to_path_buf();
        self.path_by_inode.insert(inode, path.clone());
        self.inode_by_path.insert(path, inode);
        INodeNo(inode)
    }

    fn insert_handle(&mut self, file: File, path: PathBuf) -> FileHandle {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(1);
        self.handles.insert(handle, OpenHandle { file, path });
        FileHandle(handle)
    }

    fn remove_path_tree(&mut self, path: &Path) {
        let paths = self
            .inode_by_path
            .keys()
            .filter(|candidate| candidate.as_path() == path || candidate.starts_with(path))
            .cloned()
            .collect::<Vec<_>>();
        for candidate in paths {
            if let Some(inode) = self.inode_by_path.remove(&candidate) {
                self.path_by_inode.remove(&inode);
            }
        }
    }

    fn rename_path_tree(&mut self, old: &Path, new: &Path) {
        let paths = self
            .inode_by_path
            .keys()
            .filter(|candidate| candidate.as_path() == old || candidate.starts_with(old))
            .cloned()
            .collect::<Vec<_>>();
        for old_path in paths {
            let Some(inode) = self.inode_by_path.remove(&old_path) else {
                continue;
            };
            let suffix = old_path.strip_prefix(old).unwrap_or(Path::new(""));
            let new_path = new.join(suffix);
            self.path_by_inode.insert(inode, new_path.clone());
            self.inode_by_path.insert(new_path, inode);
        }
        for handle in self.handles.values_mut() {
            if handle.path == old || handle.path.starts_with(old) {
                let suffix = handle.path.strip_prefix(old).unwrap_or(Path::new(""));
                handle.path = new.join(suffix);
            }
        }
    }
}

#[derive(Debug)]
struct GuardedPassthroughFs {
    lower_root: PathBuf,
    lower_fd: OwnedFd,
    policy: Arc<DynamicDenyPolicy>,
    state: Mutex<FuseState>,
}

impl GuardedPassthroughFs {
    fn new(lower_root: &Path, policy: Arc<DynamicDenyPolicy>) -> Result<Self> {
        let lower_root = std::fs::canonicalize(lower_root).with_context(|| {
            format!(
                "failed to canonicalize FUSE lower root {}",
                lower_root.display()
            )
        })?;
        let lower_fd = open_path(
            libc::AT_FDCWD,
            &lower_root,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
            0,
        )
        .with_context(|| format!("failed to open FUSE lower root {}", lower_root.display()))?;
        Ok(Self {
            lower_root,
            lower_fd,
            policy,
            state: Mutex::new(FuseState::new()),
        })
    }

    fn state(&self) -> MutexGuard<'_, FuseState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn path_for_inode(&self, inode: INodeNo) -> io::Result<PathBuf> {
        self.state()
            .path_by_inode
            .get(&inode.0)
            .cloned()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
    }

    fn child_path(&self, parent: INodeNo, name: &OsStr) -> io::Result<PathBuf> {
        validate_name(name)?;
        Ok(self.path_for_inode(parent)?.join(name))
    }

    fn absolute_path(&self, relative: &Path) -> PathBuf {
        self.lower_root.join(relative)
    }

    fn open_relative(&self, path: &Path, flags: i32, mode: u32) -> io::Result<OwnedFd> {
        open_path(
            self.lower_fd.as_raw_fd(),
            path,
            flags | libc::O_CLOEXEC,
            mode,
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS,
        )
    }

    fn resolved_for_fd(fd: RawFd) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/self/fd/{fd}"))
            .ok()
            .filter(|path| path.is_absolute())
    }

    fn check_read(&self, relative: &Path, resolved: Option<&Path>) -> io::Result<()> {
        let requested = self.absolute_path(relative);
        if self.policy.is_read_denied(&requested, resolved) {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        Ok(())
    }

    fn check_write(&self, relative: &Path, resolved: Option<&Path>) -> io::Result<()> {
        let requested = self.absolute_path(relative);
        if self.policy.is_write_denied(&requested, resolved) {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        Ok(())
    }

    fn open_checked(&self, path: &Path, flags: i32, mode: u32) -> io::Result<OwnedFd> {
        let write = flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & (libc::O_TRUNC | libc::O_APPEND | libc::O_CREAT) != 0;
        if write {
            self.check_write(path, None)?;
            self.check_existing_resolved_write(path)?;
        }
        let resolve = libc::RESOLVE_BENEATH
            | libc::RESOLVE_NO_MAGICLINKS
            | if write { libc::RESOLVE_NO_SYMLINKS } else { 0 };
        let fd = open_path(
            self.lower_fd.as_raw_fd(),
            path,
            flags | libc::O_CLOEXEC,
            mode,
            resolve,
        )?;
        let resolved = Self::resolved_for_fd(fd.as_raw_fd());
        if write {
            self.check_write(path, resolved.as_deref())?;
        } else {
            self.check_read(path, resolved.as_deref())?;
        }
        Ok(fd)
    }

    fn check_existing_resolved_write(&self, path: &Path) -> io::Result<()> {
        match self.open_relative(path, libc::O_PATH, 0) {
            Ok(fd) => self.check_write(path, Self::resolved_for_fd(fd.as_raw_fd()).as_deref()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn stat_path(&self, path: &Path) -> io::Result<libc::stat> {
        let fd = self.open_metadata_checked(path)?;
        fstat(fd.as_raw_fd())
    }

    fn open_metadata_checked(&self, path: &Path) -> io::Result<OwnedFd> {
        self.check_read(path, None)?;
        let fd = self.open_relative(path, libc::O_PATH | libc::O_NOFOLLOW, 0)?;
        let stat = fstat(fd.as_raw_fd())?;
        let resolved = Self::resolved_for_fd(fd.as_raw_fd());
        self.check_read(path, resolved.as_deref())?;
        if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
            let target = readlink_fd(fd.as_raw_fd())?;
            let link = resolved.unwrap_or_else(|| self.absolute_path(path));
            let target = resolve_symlink_target(&link, &target)?;
            self.check_read(path, Some(&target))?;
        }
        Ok(fd)
    }

    fn readlink_path(&self, path: &Path) -> io::Result<PathBuf> {
        let fd = self.open_metadata_checked(path)?;
        readlink_fd(fd.as_raw_fd())
    }

    fn access_path(&self, path: &Path, mask: AccessFlags) -> io::Result<()> {
        let write = mask.contains(AccessFlags::W_OK);
        if write {
            self.check_write(path, None)?;
        } else {
            self.check_read(path, None)?;
        }
        let fd = self.open_relative(path, libc::O_PATH, 0)?;
        let resolved = Self::resolved_for_fd(fd.as_raw_fd());
        if write {
            self.check_write(path, resolved.as_deref())?;
        } else {
            self.check_read(path, resolved.as_deref())?;
        }
        faccessat_empty(fd.as_raw_fd(), mask.bits())
    }

    fn attr_for_path(&self, path: &Path, inode: INodeNo) -> io::Result<FileAttr> {
        Ok(file_attr(inode, &self.stat_path(path)?))
    }

    fn open_parent(&self, path: &Path) -> io::Result<(OwnedFd, CString)> {
        let parent = path.parent().unwrap_or(Path::new(""));
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let fd = self.open_relative(parent, libc::O_PATH | libc::O_DIRECTORY, 0)?;
        Ok((fd, cstring(name)?))
    }

    fn open_parent_for_write(&self, path: &Path) -> io::Result<(OwnedFd, CString)> {
        self.check_write(path, None)?;
        let (parent, name) = self.open_parent(path)?;
        let resolved = Self::resolved_for_fd(parent.as_raw_fd())
            .map(|path| path.join(OsStr::from_bytes(name.as_bytes())));
        self.check_write(path, resolved.as_deref())?;
        self.check_existing_resolved_write(path)?;
        Ok((parent, name))
    }

    fn reply_entry(&self, path: &Path, reply: ReplyEntry) {
        match self.stat_path(path) {
            Ok(stat) => {
                let inode = self.state().inode_for_path(path);
                reply.entry(&Duration::ZERO, &file_attr(inode, &stat), Generation(0));
            }
            Err(error) => reply.error(errno(error)),
        }
    }
}

impl Filesystem for GuardedPassthroughFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.child_path(parent, name) {
            Ok(path) => self.reply_entry(&path, reply),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn getattr(&self, _req: &Request, inode: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let result = self
            .path_for_inode(inode)
            .and_then(|path| self.attr_for_path(&path, inode));
        match result {
            Ok(attr) => reply.attr(&Duration::ZERO, &attr),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn readlink(&self, _req: &Request, inode: INodeNo, reply: ReplyData) {
        let result = (|| {
            let path = self.path_for_inode(inode)?;
            self.readlink_path(&path)
        })();
        match result {
            Ok(target) => reply.data(target.as_os_str().as_bytes()),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn open(&self, _req: &Request, inode: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let result = (|| {
            let path = self.path_for_inode(inode)?;
            let flags = flags.0 & !(libc::O_CREAT | libc::O_EXCL | FMODE_EXEC);
            let fd = self.open_checked(&path, flags, 0)?;
            let file = File::from(fd);
            Ok(self.state().insert_handle(file, path))
        })();
        match result {
            Ok(handle) => reply.opened(handle, FopenFlags::FOPEN_DIRECT_IO),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _inode: INodeNo,
        handle: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let state = self.state();
        let result = state
            .handles
            .get(&handle.0)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
            .and_then(|open| {
                self.check_read(
                    &open.path,
                    Self::resolved_for_fd(open.file.as_raw_fd()).as_deref(),
                )?;
                let mut data = vec![0_u8; size as usize];
                let count = pread(open.file.as_raw_fd(), &mut data, offset)?;
                data.truncate(count);
                Ok(data)
            });
        match result {
            Ok(data) => reply.data(&data),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _inode: INodeNo,
        handle: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let state = self.state();
        let result = state
            .handles
            .get(&handle.0)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
            .and_then(|open| {
                self.check_write(
                    &open.path,
                    Self::resolved_for_fd(open.file.as_raw_fd()).as_deref(),
                )?;
                pwrite(open.file.as_raw_fd(), data, offset)
            });
        match result {
            Ok(count) => reply.written(count as u32),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _inode: INodeNo,
        handle: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        if self.state().handles.contains_key(&handle.0) {
            reply.ok();
        } else {
            reply.error(Errno::EBADF);
        }
    }

    fn release(
        &self,
        _req: &Request,
        _inode: INodeNo,
        handle: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.state().handles.remove(&handle.0);
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _inode: INodeNo,
        handle: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let state = self.state();
        let result = state
            .handles
            .get(&handle.0)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
            .and_then(|open| sync_fd(open.file.as_raw_fd(), datasync));
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn opendir(&self, _req: &Request, inode: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let result = self.path_for_inode(inode).and_then(|path| {
            self.check_read(&path, None)?;
            let fd = self.open_relative(&path, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            self.check_read(&path, Self::resolved_for_fd(fd.as_raw_fd()).as_deref())?;
            Ok(())
        });
        match result {
            Ok(()) => reply.opened(FileHandle(0), FopenFlags::empty()),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        inode: INodeNo,
        _handle: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let result = (|| {
            let path = self.path_for_inode(inode)?;
            self.check_read(&path, None)?;
            let fd = self.open_relative(&path, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            let resolved_directory = Self::resolved_for_fd(fd.as_raw_fd());
            self.check_read(&path, resolved_directory.as_deref())?;
            let proc_path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
            let mut children = std::fs::read_dir(proc_path)?.collect::<io::Result<Vec<_>>>()?;
            children.sort_by_key(|entry| entry.file_name());
            let parent_path = path.parent().unwrap_or(Path::new(""));
            let parent_inode = self.state().inode_for_path(parent_path);
            let entries = [
                (inode, FileType::Directory, OsStr::new(".").to_os_string()),
                (
                    parent_inode,
                    FileType::Directory,
                    OsStr::new("..").to_os_string(),
                ),
            ];
            for (index, (entry_inode, kind, name)) in
                entries.into_iter().enumerate().skip(offset as usize)
            {
                if reply.add(entry_inode, (index + 1) as u64, kind, name) {
                    return Ok(());
                }
            }
            // Directory cookies refer to the unfiltered sorted names. Apply
            // the offset before policy/metadata work, and stop when the kernel
            // page is full. Rechecking all children on every page is quadratic
            // for large package directories. No filesystem state is cached.
            for (index, child) in children
                .into_iter()
                .enumerate()
                .skip(offset.saturating_sub(2) as usize)
            {
                let child_path = path.join(child.file_name());
                let resolved_child = resolved_directory
                    .as_ref()
                    .map(|directory| directory.join(child.file_name()));
                if self
                    .policy
                    .is_read_denied(&self.absolute_path(&child_path), resolved_child.as_deref())
                {
                    continue;
                }
                let kind = FileType::from_std(child.file_type()?)
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
                let child_inode = self.state().inode_for_path(&child_path);
                if reply.add(child_inode, (index + 3) as u64, kind, child.file_name()) {
                    break;
                }
            }
            Ok::<_, io::Error>(())
        })();

        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let result = (|| {
            let path = self.child_path(parent, name)?;
            let (parent_fd, name) = self.open_parent_for_write(&path)?;
            let fd = open_path(
                parent_fd.as_raw_fd(),
                Path::new(OsStr::from_bytes(name.as_bytes())),
                flags | libc::O_CREAT | libc::O_CLOEXEC,
                mode & !umask & 0o7777,
                libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_SYMLINKS,
            )?;
            self.check_write(&path, Self::resolved_for_fd(fd.as_raw_fd()).as_deref())?;
            let stat = fstat(fd.as_raw_fd())?;
            let inode = self.state().inode_for_path(&path);
            let handle = self.state().insert_handle(File::from(fd), path);
            Ok((file_attr(inode, &stat), handle))
        })();
        match result {
            Ok((attr, handle)) => reply.created(
                &Duration::ZERO,
                &attr,
                Generation(0),
                handle,
                FopenFlags::FOPEN_DIRECT_IO,
            ),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let result = (|| {
            let path = self.child_path(parent, name)?;
            let (parent_fd, name) = self.open_parent_for_write(&path)?;
            cvt(unsafe { libc::mkdirat(parent_fd.as_raw_fd(), name.as_ptr(), mode & !umask) })?;
            Ok(path)
        })();
        match result {
            Ok(path) => self.reply_entry(&path, reply),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        let result = (|| {
            let path = self.child_path(parent, name)?;
            let (parent_fd, name) = self.open_parent_for_write(&path)?;
            cvt(unsafe {
                libc::mknodat(
                    parent_fd.as_raw_fd(),
                    name.as_ptr(),
                    mode & !umask,
                    rdev as libc::dev_t,
                )
            })?;
            Ok(path)
        })();
        match result {
            Ok(path) => self.reply_entry(&path, reply),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        self.remove(parent, name, 0, reply);
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        self.remove(parent, name, libc::AT_REMOVEDIR, reply);
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        new_parent: INodeNo,
        new_name: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let result = (|| {
            let old = self.child_path(parent, name)?;
            let new = self.child_path(new_parent, new_name)?;
            let (old_parent, old_name) = self.open_parent_for_write(&old)?;
            let (new_parent, new_name) = self.open_parent_for_write(&new)?;
            cvt(unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    old_parent.as_raw_fd(),
                    old_name.as_ptr(),
                    new_parent.as_raw_fd(),
                    new_name.as_ptr(),
                    flags.bits(),
                ) as i32
            })?;
            self.state().rename_path_tree(&old, &new);
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let result = (|| {
            let path = self.child_path(parent, link_name)?;
            let (parent_fd, name) = self.open_parent_for_write(&path)?;
            let target = cstring(target.as_os_str())?;
            cvt(unsafe { libc::symlinkat(target.as_ptr(), parent_fd.as_raw_fd(), name.as_ptr()) })?;
            Ok(path)
        })();
        match result {
            Ok(path) => self.reply_entry(&path, reply),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn link(
        &self,
        _req: &Request,
        inode: INodeNo,
        new_parent: INodeNo,
        new_name: &OsStr,
        reply: ReplyEntry,
    ) {
        let result = (|| {
            let old = self.path_for_inode(inode)?;
            let new = self.child_path(new_parent, new_name)?;
            let (old_parent, old_name) = self.open_parent_for_write(&old)?;
            let (new_parent, new_name) = self.open_parent_for_write(&new)?;
            cvt(unsafe {
                libc::linkat(
                    old_parent.as_raw_fd(),
                    old_name.as_ptr(),
                    new_parent.as_raw_fd(),
                    new_name.as_ptr(),
                    0,
                )
            })?;
            Ok(new)
        })();
        match result {
            Ok(path) => self.reply_entry(&path, reply),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        inode: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let result = (|| {
            let path = self.path_for_inode(inode)?;
            let (parent, name) = self.open_parent_for_write(&path)?;
            if let Some(mode) = mode {
                cvt(unsafe {
                    libc::fchmodat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        mode,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                })?;
            }
            if uid.is_some() || gid.is_some() {
                cvt(unsafe {
                    libc::fchownat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        uid.unwrap_or(u32::MAX),
                        gid.unwrap_or(u32::MAX),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                })?;
            }
            if let Some(size) = size {
                let fd = self.open_checked(&path, libc::O_WRONLY, 0)?;
                cvt(unsafe { libc::ftruncate(fd.as_raw_fd(), size as libc::off_t) })?;
            }
            if atime.is_some() || mtime.is_some() {
                let times = [
                    timespec(atime.unwrap_or(TimeOrNow::Now))?,
                    timespec(mtime.unwrap_or(TimeOrNow::Now))?,
                ];
                cvt(unsafe {
                    libc::utimensat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        times.as_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                })?;
            }
            self.attr_for_path(&path, inode)
        })();
        match result {
            Ok(attr) => reply.attr(&Duration::ZERO, &attr),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn access(&self, _req: &Request, inode: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        let result = (|| {
            let path = self.path_for_inode(inode)?;
            self.access_path(&path, mask)
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(errno(error)),
        }
    }

    fn statfs(&self, _req: &Request, _inode: INodeNo, reply: ReplyStatfs) {
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        let result = cvt(unsafe { libc::fstatvfs(self.lower_fd.as_raw_fd(), stat.as_mut_ptr()) })
            .map(|_| unsafe { stat.assume_init() });
        match result {
            Ok(stat) => reply.statfs(
                stat.f_blocks,
                stat.f_bfree,
                stat.f_bavail,
                stat.f_files,
                stat.f_ffree,
                stat.f_bsize as u32,
                stat.f_namemax as u32,
                stat.f_frsize as u32,
            ),
            Err(error) => reply.error(errno(error)),
        }
    }
}

impl GuardedPassthroughFs {
    fn remove(&self, parent: INodeNo, name: &OsStr, flags: i32, reply: ReplyEmpty) {
        let result = (|| {
            let path = self.child_path(parent, name)?;
            let (parent, name) = self.open_parent_for_write(&path)?;
            cvt(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) })?;
            self.state().remove_path_tree(&path);
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(errno(error)),
        }
    }
}

fn open_path(
    dirfd: RawFd,
    path: &Path,
    flags: i32,
    mode: u32,
    resolve: u64,
) -> io::Result<OwnedFd> {
    let path = if path.as_os_str().is_empty() {
        OsStr::new(".")
    } else {
        path.as_os_str()
    };
    let path = cstring(path)?;
    let mut how = unsafe { std::mem::zeroed::<libc::open_how>() };
    how.flags = flags as u64;
    how.mode = mode as u64;
    how.resolve = resolve;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        ) as i32
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn validate_name(name: &OsStr) -> io::Result<()> {
    if name.is_empty()
        || name == OsStr::new(".")
        || name == OsStr::new("..")
        || name.as_bytes().contains(&b'/')
        || name.as_bytes().contains(&0)
    {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(())
}

fn cstring(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    cvt(unsafe { libc::fstat(fd, stat.as_mut_ptr()) })?;
    Ok(unsafe { stat.assume_init() })
}

fn pread(fd: RawFd, data: &mut [u8], offset: u64) -> io::Result<usize> {
    let count = unsafe {
        libc::pread(
            fd,
            data.as_mut_ptr().cast(),
            data.len(),
            offset as libc::off_t,
        )
    };
    if count < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(count as usize)
    }
}

fn pwrite(fd: RawFd, data: &[u8], offset: u64) -> io::Result<usize> {
    let count =
        unsafe { libc::pwrite(fd, data.as_ptr().cast(), data.len(), offset as libc::off_t) };
    if count < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(count as usize)
    }
}

fn readlink_fd(fd: RawFd) -> io::Result<PathBuf> {
    let path = CString::new("").expect("empty path contains no NUL");
    let mut data = vec![0_u8; 4096];
    let count =
        unsafe { libc::readlinkat(fd, path.as_ptr(), data.as_mut_ptr().cast(), data.len()) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    data.truncate(count as usize);
    Ok(PathBuf::from(OsStr::from_bytes(&data)))
}

fn resolve_symlink_target(link: &Path, target: &Path) -> io::Result<PathBuf> {
    let unresolved = if target.is_absolute() {
        target.to_path_buf()
    } else {
        link.parent().unwrap_or(Path::new("/")).join(target)
    };
    let normalized = normalize_pattern_path(&unresolved)
        .map_err(|_| io::Error::from_raw_os_error(libc::EACCES))?;
    canonicalize_existing_prefix(&normalized)
}

fn canonicalize_existing_prefix(path: &Path) -> io::Result<PathBuf> {
    let mut prefix = path.to_path_buf();
    let mut suffix = Vec::new();
    loop {
        match std::fs::canonicalize(&prefix) {
            Ok(mut canonical) => {
                for component in suffix.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOENT) | Some(libc::ENOTDIR)
                ) =>
            {
                let Some(name) = prefix.file_name() else {
                    return Err(error);
                };
                suffix.push(name.to_os_string());
                if !prefix.pop() {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn faccessat_empty(fd: RawFd, mask: i32) -> io::Result<()> {
    let path = CString::new("").expect("empty path contains no NUL");
    let result = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            fd,
            path.as_ptr(),
            mask,
            libc::AT_EMPTY_PATH,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn sync_fd(fd: RawFd, datasync: bool) -> io::Result<()> {
    let result = if datasync {
        unsafe { libc::fdatasync(fd) }
    } else {
        unsafe { libc::fsync(fd) }
    };
    cvt(result).map(drop)
}

fn cvt(result: i32) -> io::Result<i32> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn errno(error: io::Error) -> Errno {
    Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO))
}

fn system_time(seconds: i64, nanos: i64) -> SystemTime {
    if seconds >= 0 {
        UNIX_EPOCH + Duration::new(seconds as u64, nanos.max(0) as u32)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::new(seconds.unsigned_abs(), nanos.max(0) as u32))
            .unwrap_or(UNIX_EPOCH)
    }
}

fn file_attr(inode: INodeNo, stat: &libc::stat) -> FileAttr {
    let kind = match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => FileType::RegularFile,
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFBLK => FileType::BlockDevice,
        _ => FileType::RegularFile,
    };
    FileAttr {
        ino: inode,
        size: stat.st_size.max(0) as u64,
        blocks: stat.st_blocks.max(0) as u64,
        atime: system_time(stat.st_atime, stat.st_atime_nsec),
        mtime: system_time(stat.st_mtime, stat.st_mtime_nsec),
        ctime: system_time(stat.st_ctime, stat.st_ctime_nsec),
        crtime: UNIX_EPOCH,
        kind,
        perm: (stat.st_mode & 0o7777) as u16,
        nlink: stat.st_nlink.min(u32::MAX as u64) as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
        rdev: stat.st_rdev.min(u32::MAX as u64) as u32,
        blksize: stat.st_blksize.max(0).min(u32::MAX as i64) as u32,
        flags: 0,
    }
}

fn timespec(value: TimeOrNow) -> io::Result<libc::timespec> {
    let time = match value {
        TimeOrNow::SpecificTime(time) => time,
        TimeOrNow::Now => SystemTime::now(),
    };
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    Ok(libc::timespec {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_nsec: duration.subsec_nanos() as libc::c_long,
    })
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn policy(root: &Path, read: &[&str], write: &[&str]) -> DynamicDenyPolicy {
        DynamicDenyPolicy::compile(
            root,
            &read
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>(),
            &write
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>(),
        )
        .expect("compile policy")
        .expect("non-empty policy")
    }

    #[test]
    fn memoized_policy_answers_stay_bounded_and_check_fresh_destinations() {
        let root = TempDir::new().unwrap();
        let policy = policy(root.path(), &["*.pem"], &["*/node_modules/*"]);
        let visible = root.path().join("visible");
        for _ in 0..100 {
            assert!(!policy.is_read_denied(&visible, None));
        }
        assert_eq!(policy.access_cache.lock().unwrap().len(), 1);
        assert!(policy.is_read_denied(&visible, Some(&root.path().join("secret.pem"))));
        assert!(policy.is_write_denied(
            &visible,
            Some(&root.path().join("package/node_modules/file"))
        ));
        for i in 0..9000 {
            policy.is_read_denied(&root.path().join(format!("file-{i}")), None);
        }
        assert!(policy.access_cache.lock().unwrap().len() <= 8192);
    }

    #[test]
    fn basename_patterns_match_at_every_project_depth() {
        let root = TempDir::new().unwrap();
        let policy = policy(root.path(), &["*.pem"], &[]);

        assert!(policy.is_read_denied(&root.path().join("root.pem"), None));
        assert!(policy.is_read_denied(&root.path().join("a/b/key.pem"), None));
        assert!(!policy.is_read_denied(&root.path().join("key.pem.txt"), None));
    }

    #[test]
    fn relative_paths_with_slashes_are_project_anchored() {
        let root = TempDir::new().unwrap();
        let policy = policy(root.path(), &["config/*.pem"], &[]);

        assert!(policy.is_read_denied(&root.path().join("config/key.pem"), None));
        assert!(!policy.is_read_denied(&root.path().join("nested/config/key.pem"), None));
    }

    #[test]
    fn a_matching_directory_denies_all_descendants() {
        let root = TempDir::new().unwrap();
        let policy = policy(root.path(), &["private"], &[]);

        assert!(policy.is_read_denied(&root.path().join("a/private/key.txt"), None));
    }

    #[test]
    fn deny_read_also_denies_writes_but_deny_write_preserves_reads() {
        let root = TempDir::new().unwrap();
        let policy = policy(root.path(), &["secret/**"], &["generated/**"]);

        assert!(policy.is_write_denied(&root.path().join("secret/key"), None));
        assert!(policy.is_write_denied(&root.path().join("generated/out"), None));
        assert!(!policy.is_read_denied(&root.path().join("generated/out"), None));
    }

    #[test]
    fn base_policy_is_not_weakened_by_the_fuse_overlay() {
        use zerobox_protocol::permissions::{
            FileSystemAccessMode, FileSystemPath, FileSystemSandboxEntry, FileSystemSpecialPath,
        };

        let root = TempDir::new().unwrap();
        let base = FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Read,
        }]);
        let policy = DynamicDenyPolicy::compile_with_base_policy(
            root.path(),
            &["*.pem".to_string()],
            &[],
            base,
        )
        .unwrap()
        .unwrap();

        assert!(policy.is_write_denied(&root.path().join("visible.txt"), None));
        assert!(!policy.is_read_denied(&root.path().join("visible.txt"), None));
    }

    #[test]
    fn resolved_symlink_targets_are_checked() {
        let root = TempDir::new().unwrap();
        let policy = policy(root.path(), &["secret/**"], &[]);

        assert!(policy.is_read_denied(
            &root.path().join("public/link"),
            Some(&root.path().join("secret/key")),
        ));
    }

    #[test]
    fn metadata_via_symlinked_ancestor_checks_the_resolved_path() {
        let lower = TempDir::new().unwrap();
        std::fs::create_dir(lower.path().join("secret")).unwrap();
        std::fs::write(lower.path().join("secret/token"), "secret").unwrap();
        std::os::unix::fs::symlink("secret", lower.path().join("public")).unwrap();
        let policy = Arc::new(policy(lower.path(), &["secret/**"], &[]));
        let filesystem = GuardedPassthroughFs::new(lower.path(), policy).unwrap();

        assert_eq!(
            filesystem
                .stat_path(Path::new("public/token"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            filesystem
                .access_path(Path::new("public/token"), AccessFlags::R_OK)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn broad_absolute_patterns_are_rejected() {
        let root = TempDir::new().unwrap();
        let error = DynamicDenyPolicy::compile(root.path(), &["/**/*.pem".to_string()], &[])
            .expect_err("root-wide glob must fail");

        assert!(error.to_string().contains("safe static prefix"));
    }

    #[test]
    fn absolute_patterns_use_their_safe_existing_prefix() {
        let root = TempDir::new().unwrap();
        let area = root.path().join("area");
        std::fs::create_dir(&area).unwrap();
        let pattern = format!("{}/future/**/*.key", area.display());
        let policy = policy(root.path(), &[&pattern], &[]);

        assert_eq!(policy.mount_roots(), &[area]);
    }

    #[test]
    fn symlinked_cwd_patterns_match_the_canonical_lower_root() {
        let parent = TempDir::new().unwrap();
        let real = parent.path().join("real");
        let link = parent.path().join("project-link");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let policy = policy(&link, &["**/*.pem"], &["generated/**"]);

        assert!(policy.is_read_denied(&real.join("nested/key.pem"), None));
        assert!(policy.is_write_denied(&real.join("generated/out.txt"), None));
        assert_eq!(policy.mount_roots(), &[real]);
    }

    #[test]
    fn absolute_patterns_canonicalize_a_symlinked_static_prefix() {
        let parent = TempDir::new().unwrap();
        let real = parent.path().join("real");
        let link = parent.path().join("area-link");
        std::fs::create_dir_all(real.join("private")).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let pattern = format!("{}/private/**/*.pem", link.display());

        let policy = policy(parent.path(), &[&pattern], &[]);

        assert!(policy.is_read_denied(&real.join("private/nested/key.pem"), None));
        assert_eq!(policy.mount_roots(), &[real.join("private")]);
    }

    #[test]
    fn absolute_patterns_reject_parent_components_after_symlinks() {
        let parent = TempDir::new().unwrap();
        let real = parent.path().join("real");
        let link = parent.path().join("area-link");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let pattern = format!("{}/../secret/**", link.display());

        let error = DynamicDenyPolicy::compile(parent.path(), &[pattern], &[])
            .expect_err("absolute deny globs with '..' must fail closed");

        assert!(error.to_string().contains("must not contain '..'"));
    }

    #[test]
    fn dangling_symlink_targets_are_checked_against_read_denies() {
        let lower = TempDir::new().unwrap();
        std::fs::create_dir(lower.path().join("secret")).unwrap();
        std::os::unix::fs::symlink("secret/missing", lower.path().join("public")).unwrap();
        let policy = Arc::new(policy(lower.path(), &["secret/**"], &[]));
        let filesystem = GuardedPassthroughFs::new(lower.path(), policy).unwrap();

        assert_eq!(
            filesystem
                .readlink_path(Path::new("public"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn empty_policy_skips_dynamic_filesystem_setup() {
        assert!(
            DynamicDenyPolicy::compile(Path::new("/work"), &[], &[])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn janitor_removes_only_dead_owned_view_directories() {
        let parent = TempDir::new().unwrap();
        let dead = parent.path().join(format!("run-{}-dead", libc::pid_t::MAX));
        let alive = parent
            .path()
            .join(format!("run-{}-alive", std::process::id()));
        let legacy = parent.path().join("run-unattributed");
        let unrelated = parent.path().join("keep-me");
        for path in [&dead, &alive, &legacy, &unrelated] {
            std::fs::create_dir(path).unwrap();
        }

        cleanup_stale_view_roots(parent.path()).unwrap();

        assert!(!dead.exists());
        assert!(alive.exists());
        assert!(legacy.exists());
        assert!(unrelated.exists());
    }

    #[test]
    fn janitor_unmounts_dead_owned_views_before_removal() {
        let parent = TempDir::new().unwrap();
        let dead = parent.path().join(format!("run-{}-dead", libc::pid_t::MAX));
        let view = dead.join("view-0");
        std::fs::create_dir_all(&view).unwrap();
        let unmounted = Mutex::new(Vec::new());

        cleanup_stale_view_roots_with(parent.path(), &[view.clone()], |path| {
            unmounted.lock().unwrap().push(path.to_path_buf());
            Ok(())
        })
        .unwrap();

        assert_eq!(*unmounted.lock().unwrap(), vec![view]);
        assert!(!dead.exists());
    }

    #[test]
    fn janitor_preserves_a_dead_view_when_unmount_fails() {
        let parent = TempDir::new().unwrap();
        let dead = parent.path().join(format!("run-{}-dead", libc::pid_t::MAX));
        let view = dead.join("view-0");
        std::fs::create_dir_all(&view).unwrap();

        let error = cleanup_stale_view_roots_with(parent.path(), &[view], |_| {
            Err(io::Error::from_raw_os_error(libc::EBUSY).into())
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("failed to unmount stale FUSE view")
        );
        assert!(dead.exists());
    }

    #[test]
    fn globset_operators_follow_literal_separator_semantics() {
        let root = TempDir::new().unwrap();
        let policy = policy(
            root.path(),
            &["secrets/**/key?.{pem,key}", "certs/[ab].crt"],
            &[],
        );

        assert!(policy.is_read_denied(&root.path().join("secrets/team/deep/key1.pem"), None,));
        assert!(policy.is_read_denied(&root.path().join("certs/a.crt"), None));
        assert!(!policy.is_read_denied(&root.path().join("certs/c.crt"), None));
        assert!(!policy.is_read_denied(&root.path().join("nested/certs/a.crt"), None,));
    }

    #[test]
    fn invalid_patterns_fail_closed_during_compilation() {
        let root = TempDir::new().unwrap();

        assert!(DynamicDenyPolicy::compile(root.path(), &["[broken".to_string()], &[]).is_err());
    }

    #[test]
    fn mounted_view_enforces_dynamic_read_and_write_denies() {
        use std::fs::OpenOptions;

        let lower = TempDir::new().unwrap();
        let private = TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("generated")).unwrap();
        std::fs::create_dir_all(lower.path().join("private/nested")).unwrap();
        std::fs::create_dir_all(lower.path().join("secret")).unwrap();
        std::fs::create_dir_all(lower.path().join("swap")).unwrap();
        std::fs::write(lower.path().join("visible.txt"), "visible").unwrap();
        std::fs::write(lower.path().join("secret.pem"), "secret").unwrap();
        std::fs::write(lower.path().join("private/nested/value.txt"), "private").unwrap();
        std::fs::write(lower.path().join("generated/out.txt"), "generated").unwrap();
        std::fs::write(lower.path().join("secret/token"), "secret token").unwrap();
        std::fs::write(lower.path().join("swap/visible"), "visible").unwrap();
        std::os::unix::fs::symlink("secret.pem", lower.path().join("alias.txt")).unwrap();
        std::os::unix::fs::symlink("secret", lower.path().join("public")).unwrap();
        std::fs::hard_link(
            lower.path().join("secret.pem"),
            lower.path().join("named-hardlink.txt"),
        )
        .unwrap();

        let mounts = DynamicDenyMounts::prepare_in(
            lower.path(),
            &[
                "*.pem".to_string(),
                "private".to_string(),
                "secret/**".to_string(),
            ],
            &["generated/**".to_string()],
            &FileSystemSandboxPolicy::unrestricted(),
            private.path(),
        )
        .expect("mount guarded view")
        .expect("dynamic policy creates a view");
        let view = &mounts.binds()[0].source;

        assert_eq!(
            std::fs::read_to_string(view.join("visible.txt")).unwrap(),
            "visible"
        );
        assert_eq!(
            std::fs::read_to_string(view.join("secret.pem"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::read_to_string(view.join("alias.txt"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::metadata(view.join("secret.pem"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::read_to_string(view.join("private/nested/value.txt"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::read_link(view.join("public")).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::read_dir(view.join("public")).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::metadata(view.join("public/token"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::read_to_string(view.join("named-hardlink.txt")).unwrap(),
            "secret"
        );
        assert_eq!(
            std::fs::read_to_string(view.join("generated/out.txt")).unwrap(),
            "generated"
        );
        assert_eq!(
            std::fs::write(view.join("generated/out.txt"), "changed")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(view.join("generated/out.txt"))
                .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(lower.path().join("generated/out.txt")).unwrap(),
            "generated"
        );
        assert!(std::fs::remove_file(view.join("secret.pem")).is_err());
        assert!(std::fs::remove_file(view.join("generated/out.txt")).is_err());
        assert!(std::fs::write(view.join("generated/new.txt"), "new").is_err());
        assert!(!lower.path().join("generated/new.txt").exists());
        assert!(std::fs::rename(view.join("generated/out.txt"), view.join("moved.txt")).is_err());
        assert!(lower.path().join("generated/out.txt").exists());

        std::fs::metadata(view.join("swap")).unwrap();
        std::fs::rename(lower.path().join("swap"), lower.path().join("old-swap")).unwrap();
        std::os::unix::fs::symlink("secret", lower.path().join("swap")).unwrap();
        assert_eq!(
            std::fs::read_dir(view.join("swap")).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::metadata(view.join("swap/token"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        std::fs::write(lower.path().join("created.pem"), "late secret").unwrap();
        assert_eq!(
            std::fs::read_to_string(view.join("created.pem"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(mounts.root().is_dir());
    }

    #[test]
    fn reading_one_directory_page_does_not_check_the_entire_directory() {
        let lower = TempDir::new().unwrap();
        let private = TempDir::new().unwrap();
        for i in 0..2000 {
            std::fs::write(
                lower
                    .path()
                    .join(format!("entry-{i:04}-{}", "x".repeat(80))),
                "",
            )
            .unwrap();
        }
        std::fs::write(lower.path().join("hidden.pem"), "secret").unwrap();
        let mounts = DynamicDenyMounts::prepare_in(
            lower.path(),
            &["*.pem".to_string()],
            &[],
            &FileSystemSandboxPolicy::unrestricted(),
            private.path(),
        )
        .unwrap()
        .unwrap();
        let view = &mounts.binds()[0].source;
        let mut entries = std::fs::read_dir(view).unwrap();
        assert!(entries.next().unwrap().is_ok());
        assert!(
            mounts.policy.access_cache.lock().unwrap().len() < 2000,
            "first directory page eagerly evaluated every child"
        );
        drop(entries);
        let mut names = std::fs::read_dir(view)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 2000);
        assert!(!names.iter().any(|name| name == "hidden.pem"));
    }

    #[test]
    fn mounted_view_observes_external_edits_and_directory_type_changes() {
        let lower = TempDir::new().unwrap();
        let private = TempDir::new().unwrap();
        std::fs::create_dir(lower.path().join("changing")).unwrap();
        std::fs::create_dir(lower.path().join("destination")).unwrap();
        std::fs::write(lower.path().join("visible.txt"), "old").unwrap();
        let mounts = DynamicDenyMounts::prepare_in(
            lower.path(),
            &["*.pem".to_string()],
            &[],
            &FileSystemSandboxPolicy::unrestricted(),
            private.path(),
        )
        .unwrap()
        .unwrap();
        let view = &mounts.binds()[0].source;
        assert!(std::fs::metadata(view.join("changing")).unwrap().is_dir());
        assert_eq!(
            std::fs::read_to_string(view.join("visible.txt")).unwrap(),
            "old"
        );
        std::fs::write(lower.path().join("visible.txt"), "new-content").unwrap();
        assert_eq!(
            std::fs::read_to_string(view.join("visible.txt")).unwrap(),
            "new-content"
        );
        std::fs::remove_dir(lower.path().join("changing")).unwrap();
        std::os::unix::fs::symlink("destination", lower.path().join("changing")).unwrap();
        assert!(
            std::fs::symlink_metadata(view.join("changing"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_link(view.join("changing")).unwrap(),
            PathBuf::from("destination")
        );
    }

    #[test]
    fn mounted_view_enforces_globs_from_a_symlinked_cwd() {
        let parent = TempDir::new().unwrap();
        let private = TempDir::new().unwrap();
        let real = parent.path().join("real");
        let link = parent.path().join("project-link");
        std::fs::create_dir_all(real.join("generated")).unwrap();
        std::fs::write(real.join("secret.pem"), "secret").unwrap();
        std::fs::write(real.join("generated/out.txt"), "generated").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let mounts = DynamicDenyMounts::prepare_in(
            &link,
            &["**/*.pem".to_string()],
            &["generated/**".to_string()],
            &FileSystemSandboxPolicy::unrestricted(),
            private.path(),
        )
        .unwrap()
        .unwrap();
        let bind = &mounts.binds()[0];

        assert_eq!(bind.destination, link);
        assert_eq!(
            std::fs::read_to_string(bind.source.join("secret.pem"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::write(bind.source.join("generated/out.txt"), "changed")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn mounted_view_enforces_absolute_globs_with_a_symlinked_prefix() {
        let parent = TempDir::new().unwrap();
        let private = TempDir::new().unwrap();
        let real = parent.path().join("real");
        let link = parent.path().join("area-link");
        std::fs::create_dir_all(real.join("private/generated")).unwrap();
        std::fs::write(real.join("private/key.pem"), "secret").unwrap();
        std::fs::write(real.join("private/generated/out.txt"), "generated").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let deny_read = format!("{}/private/**/*.pem", link.display());
        let deny_write = format!("{}/private/generated/**", link.display());

        let mounts = DynamicDenyMounts::prepare_in(
            parent.path(),
            &[deny_read],
            &[deny_write],
            &FileSystemSandboxPolicy::unrestricted(),
            private.path(),
        )
        .unwrap()
        .unwrap();
        let bind = mounts
            .binds()
            .iter()
            .find(|bind| bind.destination == link.join("private"))
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(bind.source.join("key.pem"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::write(bind.source.join("generated/out.txt"), "changed")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
