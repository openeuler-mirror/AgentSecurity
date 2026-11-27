//! Data-plane listener and Linux original-destination lookup.
//!
//! The transparent listener is the only data-plane ingress. Each accepted
//! connection is served with the runtime snapshot current at accept time; when
//! no CA exists the connection is closed (fail-closed) instead of forwarded.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;

use tokio::net::TcpListener;

use crate::proxy::{handle_transparent_conn, Transparent};
use crate::runtime::Shared;

pub async fn run_transparent(listener: TcpListener, shared: Shared, ingress: &'static str) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{ingress}: accept failed: {e}");
                continue;
            }
        };
        tokio::spawn(handle_transparent_conn(
            stream,
            peer,
            Transparent {
                shared: shared.clone(),
                ingress,
            },
        ));
    }
}

/// Linux netfilter original destination (`SO_ORIGINAL_DST` is not in libc).
pub fn original_dst(fd: RawFd) -> io::Result<SocketAddr> {
    const SOL_IP: libc::c_int = 0;
    const SO_ORIGINAL_DST: libc::c_int = 80;
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            &mut storage as *mut libc::sockaddr_storage as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe {
                &*(&storage as *const libc::sockaddr_storage as *const libc::sockaddr_in)
            };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Ok(SocketAddr::new(IpAddr::V4(ip), u16::from_be(sin.sin_port)))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe {
                &*(&storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6)
            };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Ok(SocketAddr::new(
                IpAddr::V6(ip),
                u16::from_be(sin6.sin6_port),
            ))
        }
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected SO_ORIGINAL_DST family {family}"),
        )),
    }
}
