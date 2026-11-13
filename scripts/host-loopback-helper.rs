use zerobox_protocol::host_loopback::{ACK, ADDRESS, MAGIC};
// Canonical helper source, imported by upstream-host-loopback.patch.
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

fn system_tool(name: &str) -> io::Result<PathBuf> {
    for directory in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let candidate = Path::new(directory).join(name);
        if !candidate.exists() {
            continue;
        }
        let path = fs::canonicalize(candidate)?;
        let mut ancestor = Some(path.as_path());
        while let Some(current) = ancestor {
            let metadata = fs::metadata(current)?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(io::Error::other(format!(
                    "untrusted host loopback setup tool: {}",
                    current.display()
                )));
            }
            ancestor = current.parent();
        }
        if !fs::metadata(&path)?.is_file() {
            return Err(io::Error::other("setup tool is not a regular file"));
        }
        return Ok(path);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("host loopback requires installed system {name}"),
    ))
}

fn setup_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    // The setup namespace maps the original non-root UID. Retain only the
    // network capability across exec of these trusted setup tools.
    unsafe {
        command.pre_exec(|| {
            #[repr(C)]
            struct Header {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            #[derive(Clone, Copy)]
            struct Data {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let header = Header {
                version: 0x20080522,
                pid: 0,
            };
            let mut data = [Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            }; 2];
            if libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            data[0].inheritable = 1 << 12;
            data[1].inheritable = 0;
            if libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ) != 0
                || libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0
                || libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, 12, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

pub(crate) fn setup_tools() -> io::Result<(PathBuf, PathBuf)> {
    Ok((system_tool("ip")?, system_tool("nft")?))
}

pub(crate) fn prepare(
    broker_path: &Path,
    namespace_ready: bool,
    tools: &(PathBuf, PathBuf),
) -> io::Result<()> {
    let (ip, nft) = tools;
    if !namespace_ready {
        crate::mediated_direct::enter_setup_namespaces()?;
    }
    crate::proxy_routing::ensure_loopback_interface_up()?;
    let address = std::net::Ipv4Addr::from(ADDRESS).to_string();
    let subnet = format!("{address}/32");
    let status = setup_command(&ip)
        .args(["address", "add", &subnet, "dev", "lo"])
        .status()?;
    if !status.success() {
        return Err(io::Error::other("host loopback address setup failed"));
    }
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let rules = format!(
        "table ip zerobox_host_loopback {{ chain output {{ type nat hook output priority dstnat; policy accept; ip daddr {address} meta l4proto tcp redirect to :{port} }} }}\n"
    );
    let mut command = setup_command(&nft)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()?;
    command
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing nft input"))?
        .write_all(rules.as_bytes())?;
    if !command.wait()?.success() {
        return Err(io::Error::other(
            "host loopback requires namespace-local nftables NAT support",
        ));
    }
    let mut broker = UnixStream::connect(broker_path)?;
    broker.set_read_timeout(Some(Duration::from_secs(5)))?;
    broker.set_write_timeout(Some(Duration::from_secs(5)))?;
    let payload = *MAGIC;
    let descriptor = listener.as_raw_fd();
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let length = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as _) } as usize;
    // usize storage supplies the alignment required by cmsghdr.
    let mut control = vec![0usize; length.div_ceil(std::mem::size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = length;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err(io::Error::other("missing listener control buffer"));
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as usize;
        libc::CMSG_DATA(header).cast::<i32>().write(descriptor);
    }
    if unsafe { libc::sendmsg(broker.as_raw_fd(), &message, libc::MSG_NOSIGNAL) } != 4 {
        return Err(io::Error::other("host loopback listener transfer failed"));
    }
    let mut ack = [0];
    broker.read_exact(&mut ack)?;
    if ack != [ACK] {
        return Err(io::Error::other("host loopback broker refused listener"));
    }
    Ok(())
}
