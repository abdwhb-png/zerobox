use anyhow::Context;
use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::task::{JoinHandle, JoinSet};
use zerobox_network_proxy::NetworkProxyState;

use zerobox_network_proxy::HOST_LOOPBACK_ALIAS as HOST_ALIAS;
use zerobox_protocol::host_loopback::{ACK, ADDRESS, MAGIC};
const HOST_ADDRESS: Ipv4Addr = Ipv4Addr::new(ADDRESS[0], ADDRESS[1], ADDRESS[2], ADDRESS[3]);

async fn allowed(policy: &NetworkProxyState, port: u16) -> anyhow::Result<bool> {
    Ok(port != 0 && policy.is_host_domain_route(HOST_ALIAS, port).await?)
}

pub(crate) struct HostLoopbackBroker {
    socket: PathBuf,
    hosts: PathBuf,
    task: JoinHandle<()>,
}
impl HostLoopbackBroker {
    pub(crate) fn start(root: &Path, policy: Arc<NetworkProxyState>) -> anyhow::Result<Self> {
        let socket = root.join("h.sock");
        let hosts = root.join("host-loopback.hosts");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&hosts)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(
            format!("127.0.0.1 localhost\n::1 localhost\n{HOST_ADDRESS} {HOST_ALIAS}\n").as_bytes(),
        )?;
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let uid = unsafe { libc::geteuid() };
        let task = tokio::spawn(async move {
            let result = async {
                let (stream, _) = listener.accept().await?;
                if stream.peer_cred()?.uid() != uid { anyhow::bail!("host loopback broker peer UID mismatch"); }
                let standard = stream.into_std()?;
                standard.set_nonblocking(false)?;
                let listener = tokio::task::spawn_blocking(move || receive_listener(standard)).await??;
                listener.set_nonblocking(true)?;
                let listener = TcpListener::from_std(listener)?;
                let mut connections = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (stream, _) = accepted?;
                            if connections.len() >= 64 {
                                eprintln!("zerobox: host loopback connection refused: relay capacity reached");
                                drop(stream);
                                continue;
                            }
                            let policy = policy.clone();
                            connections.spawn(async move { forward(stream, policy).await });
                        }
                        completed = connections.join_next(), if !connections.is_empty() => {
                            match completed {
                                Some(Ok(Ok(()))) => {},
                                Some(Ok(Err(error))) => eprintln!("zerobox: host loopback connection refused or failed: {error:#}"),
                                Some(Err(error)) => eprintln!("zerobox: host loopback relay task failed: {error}"),
                                None => {},
                            }
                        }
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            }.await;
            if let Err(error) = result {
                eprintln!("zerobox: host loopback broker stopped: {error:#}");
            }
        });
        Ok(Self {
            socket,
            hosts,
            task,
        })
    }
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket
    }
    pub(crate) fn hosts_path(&self) -> &Path {
        &self.hosts
    }
}
impl Drop for HostLoopbackBroker {
    fn drop(&mut self) {
        self.task.abort();
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_file(&self.hosts);
    }
}

fn receive_listener(
    mut stream: std::os::unix::net::UnixStream,
) -> io::Result<std::net::TcpListener> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut payload = [0u8; 4];
    let length = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as _) } as usize;
    let mut control = vec![0usize; length.div_ceil(std::mem::size_of::<usize>())];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = length;
    let received =
        unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut descriptors = Vec::new();
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let base = libc::CMSG_LEN(0) as usize;
                if (*header).cmsg_len < base {
                    return Err(io::Error::other("invalid descriptor control message"));
                }
                let count = ((*header).cmsg_len - base) / std::mem::size_of::<i32>();
                for index in 0..count {
                    descriptors.push(OwnedFd::from_raw_fd(
                        libc::CMSG_DATA(header).cast::<i32>().add(index).read(),
                    ));
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if received != 4
        || payload != *MAGIC
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || descriptors.len() != 1
    {
        return Err(io::Error::other("invalid host loopback listener transfer"));
    }
    let listener = std::net::TcpListener::from(
        descriptors
            .pop()
            .ok_or_else(|| io::Error::other("missing listener"))?,
    );
    if listener.local_addr()?.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(io::Error::other(
            "host loopback listener must bind private IPv4 loopback",
        ));
    }
    stream.write_all(&[ACK])?;
    Ok(listener)
}

async fn forward(mut client: TcpStream, policy: Arc<NetworkProxyState>) -> anyhow::Result<()> {
    let mut original: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&original) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            client.as_raw_fd(),
            libc::SOL_IP,
            80,
            (&mut original as *mut libc::sockaddr_in).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("read original host loopback destination");
    }
    if length as usize != std::mem::size_of_val(&original)
        || original.sin_family != libc::AF_INET as u16
        || Ipv4Addr::from(original.sin_addr.s_addr.to_ne_bytes()) != HOST_ADDRESS
    {
        anyhow::bail!("host loopback original destination mismatch");
    }
    let port = u16::from_be(original.sin_port);
    if !allowed(&policy, port).await? {
        anyhow::bail!("host loopback policy denied {HOST_ALIAS}:{port}");
    }
    let mut upstream = match tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)),
    )
    .await?
    {
        Ok(stream) => stream,
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            tokio::time::timeout(
                Duration::from_secs(5),
                TcpStream::connect(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)),
            )
            .await??
        }
        Err(error) => return Err(error.into()),
    };
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerobox_network_proxy::{NetworkProxyConfig, NetworkProxyConstraints, build_config_state};

    #[tokio::test]
    async fn arbitrary_host_alias_ports_retain_explicit_denials() {
        let mut config = NetworkProxyConfig::default();
        config.network.enabled = true;
        config
            .network
            .set_allowed_host_domains(vec![HOST_ALIAS.to_string()]);
        config.network.set_denied_domains(vec![
            "localhost:3216".to_string(),
            "host.localhost:5173".to_string(),
        ]);
        let state = NetworkProxyState::with_reloader(
            build_config_state(config, NetworkProxyConstraints::default()).unwrap(),
            Arc::new(crate::proxy::StaticReloader),
        );
        assert!(allowed(&state, 40001).await.unwrap());
        assert!(allowed(&state, 65000).await.unwrap());
        assert!(!allowed(&state, 3216).await.unwrap());
        assert!(!allowed(&state, 5173).await.unwrap());
        assert!(!allowed(&state, 0).await.unwrap());
    }
}
