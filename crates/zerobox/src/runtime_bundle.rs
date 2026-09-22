use std::fs;
use std::io::Read;
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub(crate) const RUNTIME_ROOT: &str = "/__zerobox/runtime";
pub(crate) const ANALYSIS_ROOT: &str = "/__zerobox/analysis";
pub(crate) const INNER_HELPER_PATH: &str = "/__zerobox/runtime/libexec/zerobox-linux-sandbox";
pub(crate) const SHELL_PATH: &str = "/__zerobox/runtime/bin";
const MANIFEST_NAME: &str = "manifest.json";
const TARGET: &str = "x86_64-unknown-linux-gnu";

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RuntimeComponent {
    Shell,
    Analysis,
}

impl RuntimeComponent {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::Analysis => "analysis",
        }
    }
}

#[derive(Debug)]
pub(crate) struct RuntimeBundle {
    pub(crate) root: PathBuf,
    pub(crate) component: RuntimeComponent,
    pub(crate) shell_root: PathBuf,
    pub(crate) component_root: PathBuf,
    pub(crate) helper: PathBuf,
    pub(crate) manifest_sha256: String,
    pub(crate) helper_sha256: String,
    pub(crate) version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    target: String,
    version: String,
    components: Components,
    helper: ManifestHelper,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Components {
    shell: ComponentTree,
    analysis: ComponentTree,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentTree {
    root: PathBuf,
    files: Vec<TreeEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestHelper {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeEntry {
    path: PathBuf,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    symlink: Option<String>,
}

impl RuntimeBundle {
    pub(crate) fn load(root: &Path, component: RuntimeComponent) -> Result<Self> {
        if !root.is_absolute() {
            bail!("runtime bundle path must be absolute: {}", root.display());
        }
        let input_metadata = fs::symlink_metadata(root)
            .with_context(|| format!("inspect runtime bundle {}", root.display()))?;
        if input_metadata.file_type().is_symlink() || !input_metadata.is_dir() {
            bail!(
                "runtime bundle root must be a non-symlink directory: {}",
                root.display()
            );
        }
        let root = root
            .canonicalize()
            .with_context(|| format!("resolve runtime bundle {}", root.display()))?;
        let root_metadata = fs::symlink_metadata(&root)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            bail!(
                "runtime bundle root must be a non-symlink directory: {}",
                root.display()
            );
        }
        let manifest_path = root.join(MANIFEST_NAME);
        let manifest_bytes = fs::read(&manifest_path)
            .with_context(|| format!("read runtime manifest {}", manifest_path.display()))?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .with_context(|| format!("decode runtime manifest {}", manifest_path.display()))?;
        if manifest.schema != 1 || manifest.target != TARGET || manifest.version.is_empty() {
            bail!("runtime manifest has unsupported schema, target, or version");
        }
        let shell_root = resolve_bundle_path(&root, &manifest.components.shell.root, "shell root")?;
        validate_component_tree(&shell_root, &manifest.components.shell.files)?;
        validate_regular_executable(&shell_root.join("bin/bash"), "runtime shell bash")?;
        validate_regular_executable(&shell_root.join("bin/env"), "runtime shell env")?;
        let tree = match component {
            RuntimeComponent::Shell => &manifest.components.shell,
            RuntimeComponent::Analysis => &manifest.components.analysis,
        };
        let component_root = if component == RuntimeComponent::Shell {
            shell_root.clone()
        } else {
            let root = resolve_bundle_path(&root, &tree.root, "analysis root")?;
            validate_component_tree(&root, &tree.files)?;
            root
        };
        let helper = resolve_bundle_path(&root, &manifest.helper.path, "helper")?;
        validate_regular_executable(&helper, "runtime helper")?;
        let helper_sha256 = hash_file(&helper)?;
        if !valid_digest(&manifest.helper.sha256) || helper_sha256 != manifest.helper.sha256 {
            bail!("runtime helper digest mismatch");
        }
        Ok(Self {
            root,
            component,
            shell_root,
            component_root,
            helper,
            manifest_sha256: hex_digest(&manifest_bytes),
            helper_sha256,
            version: manifest.version,
        })
    }
}

fn validate_component_tree(root: &Path, files: &[TreeEntry]) -> Result<()> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect runtime component root {}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "runtime component root must be a non-symlink directory: {}",
            root.display()
        );
    }
    let mut declared = std::collections::BTreeSet::new();
    for entry in files {
        let path = resolve_bundle_path(root, &entry.path, "component entry")?;
        if !declared.insert(entry.path.clone()) {
            bail!(
                "runtime manifest declares a component entry twice: {}",
                entry.path.display()
            );
        }
        match (&entry.sha256, &entry.symlink) {
            (Some(expected), None) => {
                validate_regular_executable_or_file(&path, "runtime component file")?;
                if !valid_digest(expected) || hash_file(&path)? != *expected {
                    bail!(
                        "runtime component file digest mismatch: {}",
                        entry.path.display()
                    );
                }
            }
            (None, Some(target)) => {
                let metadata = fs::symlink_metadata(&path)
                    .with_context(|| format!("inspect runtime symlink {}", entry.path.display()))?;
                if !metadata.file_type().is_symlink() || !is_relative_safe_symlink(target) {
                    bail!("invalid runtime symlink: {}", entry.path.display());
                }
                if fs::read_link(&path)?.as_os_str() != std::ffi::OsStr::new(target) {
                    bail!("runtime symlink target mismatch: {}", entry.path.display());
                }
            }
            _ => bail!("runtime entry must declare exactly one of sha256 or symlink"),
        }
    }
    let mut actual = std::collections::BTreeSet::new();
    collect_component_files(root, root, &mut actual)?;
    if actual != declared {
        bail!("runtime component tree differs from its manifest");
    }
    Ok(())
}

fn collect_component_files(
    root: &Path,
    directory: &Path,
    files: &mut std::collections::BTreeSet<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .expect("component path stays rooted")
            .to_path_buf();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            collect_component_files(root, &path, files)?;
        } else if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            files.insert(relative);
        } else {
            bail!(
                "runtime component contains a non-file entry: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn resolve_bundle_path(root: &Path, relative: &Path, description: &str) -> Result<PathBuf> {
    if relative.is_absolute()
        || relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("{description} must be a non-empty relative path");
    }
    let mut ancestor = root.to_path_buf();
    for part in relative
        .components()
        .take_while(|part| matches!(part, Component::Normal(_)))
    {
        let Component::Normal(part) = part else {
            unreachable!("validated path contains only normal components")
        };
        ancestor.push(part);
        if ancestor != root.join(relative) {
            let metadata = fs::symlink_metadata(&ancestor).with_context(|| {
                format!("inspect {description} ancestor {}", ancestor.display())
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!(
                    "{description} ancestor must be a non-symlink directory: {}",
                    ancestor.display()
                );
            }
        }
    }
    Ok(root.join(relative))
}

fn is_relative_safe_symlink(target: &str) -> bool {
    let target = Path::new(target);
    !target.as_os_str().is_empty()
        && !target.is_absolute()
        && target
            .components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
}

fn validate_regular_executable(path: &Path, description: &str) -> Result<()> {
    validate_regular_executable_or_file(path, description)?;
    use std::os::unix::fs::PermissionsExt;
    if fs::metadata(path)?.permissions().mode() & 0o111 == 0 {
        bail!("{description} is not executable: {}", path.display());
    }
    Ok(())
}

fn validate_regular_executable_or_file(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {description} {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_block_device()
        || metadata.file_type().is_char_device()
    {
        bail!(
            "{description} must be a regular non-symlink file: {}",
            path.display()
        );
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut bytes = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            return Ok(format!("{:x}", digest.finalize()));
        }
        digest.update(&bytes[..count]);
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn sha256(bytes: &[u8]) -> String {
        hex_digest(bytes)
    }

    pub(crate) fn fixture(
        component_symlink: Option<&str>,
        helper_digest: Option<String>,
    ) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let shell = root.path().join("components/shell/bin");
        let analysis = root.path().join("components/analysis");
        let helper = root.path().join("helper");
        fs::create_dir_all(&shell).unwrap();
        fs::create_dir_all(&analysis).unwrap();
        fs::create_dir(&helper).unwrap();
        let bash = shell.join("bash");
        let env = shell.join("env");
        let helper_path = helper.join("zerobox-linux-sandbox");
        fs::write(&bash, b"bash").unwrap();
        fs::write(&env, b"env").unwrap();
        fs::set_permissions(&bash, fs::Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(&env, fs::Permissions::from_mode(0o500)).unwrap();
        fs::write(&helper_path, b"helper").unwrap();
        fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o500)).unwrap();
        if let Some(link) = component_symlink {
            std::os::unix::fs::symlink(link, shell.join("sh")).unwrap();
        }
        let shell_files = if component_symlink.is_some() {
            format!(
                r#"[{{"path":"bin/bash","sha256":"{}"}},{{"path":"bin/env","sha256":"{}"}},{{"path":"bin/sh","symlink":"{}"}}]"#,
                sha256(b"bash"),
                sha256(b"env"),
                component_symlink.unwrap()
            )
        } else {
            format!(
                r#"[{{"path":"bin/bash","sha256":"{}"}},{{"path":"bin/env","sha256":"{}"}}]"#,
                sha256(b"bash"),
                sha256(b"env")
            )
        };
        let helper_digest = helper_digest.unwrap_or_else(|| sha256(b"helper"));
        fs::write(root.path().join(MANIFEST_NAME), format!(r#"{{"schema":1,"target":"{TARGET}","version":"test","components":{{"shell":{{"root":"components/shell","files":{shell_files}}},"analysis":{{"root":"components/analysis","files":[]}}}},"helper":{{"path":"helper/zerobox-linux-sandbox","sha256":"{helper_digest}"}}}}"#)).unwrap();
        root
    }

    #[test]
    fn runtime_bundle_accepts_the_declared_extracted_shell_tree() {
        let fixture = fixture(Some("bash"), None);
        let bundle = RuntimeBundle::load(fixture.path(), RuntimeComponent::Shell).unwrap();
        assert_eq!(
            bundle.component_root,
            fixture.path().join("components/shell")
        );
        assert_eq!(bundle.component, RuntimeComponent::Shell);
        assert_eq!(bundle.version, "test");
    }

    #[test]
    fn runtime_bundle_rejects_external_component_symlink() {
        let fixture = fixture(Some("../../outside"), None);
        let error = RuntimeBundle::load(fixture.path(), RuntimeComponent::Shell).unwrap_err();
        assert!(error.to_string().contains("invalid runtime symlink"));
    }

    #[test]
    fn runtime_bundle_rejects_helper_digest_mismatch() {
        let fixture = fixture(None, Some("0".repeat(64)));
        let error = RuntimeBundle::load(fixture.path(), RuntimeComponent::Shell).unwrap_err();
        assert!(error.to_string().contains("runtime helper digest mismatch"));
    }

    #[test]
    fn runtime_bundle_rejects_unlisted_component_file() {
        let fixture = fixture(None, None);
        fs::write(
            fixture.path().join("components/shell/bin/unlisted"),
            b"unexpected",
        )
        .unwrap();
        let error = RuntimeBundle::load(fixture.path(), RuntimeComponent::Shell).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("runtime component tree differs from its manifest")
        );
    }

    #[test]
    fn runtime_bundle_rejects_symlinked_entry_ancestor() {
        let fixture = fixture(None, None);
        let bin = fixture.path().join("components/shell/bin");
        let replacement = fixture.path().join("outside");
        fs::create_dir(&replacement).unwrap();
        fs::rename(&bin, &replacement).unwrap();
        std::os::unix::fs::symlink("../../outside", &bin).unwrap();
        let error = RuntimeBundle::load(fixture.path(), RuntimeComponent::Shell).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ancestor must be a non-symlink directory")
        );
    }
}
