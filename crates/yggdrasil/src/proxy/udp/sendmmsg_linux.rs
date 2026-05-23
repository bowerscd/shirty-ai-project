//! Linux batch send via `libc::sendmmsg`, driven by `tokio::io::unix::AsyncFd`.
//!
//! Sibling to [`super::recvmmsg_linux`]. Same `AsyncFd`-over-`RawFd`
//! pattern, same `MSG_DONTWAIT` semantics on the syscall, same
//! fallback model: a caller that hits `ENOSYS` / `EPERM` should fall
//! back to per-datagram [`tokio::net::UdpSocket::send`].
//!
//! Use case: per-flow upstream-to-client return path. A single flow's
//! [`super::upstream_to_client_loop`] drains the upstream via
//! `recvmmsg` and then forwards each datagram to one fixed client
//! address. Calling `sendmmsg` with that single address cuts the send
//! syscall count from N to 1 per batch.

#![cfg(target_os = "linux")]

use std::io;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::net::UdpSocket;

const EINTR_RETRIES: usize = 3;

/// Send-side analogue of [`super::recvmmsg_linux::BatchReader`].
/// Created from a `UdpSocket` (typically the per-rule frontend
/// socket) so the caller can `sendmmsg` a burst of datagrams in one
/// syscall.
pub struct BatchSender {
    fd: AsyncFd<RawFd>,
    _owned_fd: Option<OwnedFd>,
}

impl BatchSender {
    pub fn from_udp_socket(sock: &UdpSocket) -> io::Result<Self> {
        match AsyncFd::with_interest(sock.as_raw_fd(), Interest::WRITABLE) {
            Ok(fd) => Ok(Self {
                fd,
                _owned_fd: None,
            }),
            Err(err) if is_already_registered(&err) => {
                // The same `UdpSocket` is already registered with tokio's
                // reactor (typically the rule's frontend, which tokio
                // registers when it constructs the socket). Duplicating
                // the fd gives us a fresh kernel-level descriptor pointing
                // at the same open file description, which we can register
                // independently. Owned via `OwnedFd` so the dup closes when
                // the sender drops.
                let owned_fd = duplicate_fd(sock.as_raw_fd())?;
                let fd = AsyncFd::with_interest(owned_fd.as_raw_fd(), Interest::WRITABLE)?;
                Ok(Self {
                    fd,
                    _owned_fd: Some(owned_fd),
                })
            }
            Err(err) => Err(err),
        }
    }

    /// Send up to `payloads.len()` datagrams to `addr` in one syscall.
    /// Returns the number of datagrams the kernel reports as
    /// transmitted. Short writes (kernel reporting fewer than the
    /// requested count) are possible under buffer pressure; the
    /// caller is expected to re-issue the remainder.
    ///
    /// `EAGAIN` is automatically retried via `AsyncFd::writable`.
    /// `ENOSYS` / `EPERM` propagate up so the caller can fall back
    /// to per-datagram `send_to`.
    pub async fn send_batch(&self, payloads: &[&[u8]], addr: SocketAddr) -> io::Result<usize> {
        if payloads.is_empty() {
            return Ok(0);
        }
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| do_sendmmsg(inner.as_raw_fd(), payloads, addr)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

fn do_sendmmsg(fd: RawFd, payloads: &[&[u8]], addr: SocketAddr) -> io::Result<usize> {
    // Stack-storage for the typical small batch.
    const STACK_BATCH: usize = 32;
    if payloads.len() <= STACK_BATCH {
        let mut iovecs: [libc::iovec; STACK_BATCH] = std::array::from_fn(|_| empty_iovec());
        let mut msgs: [libc::mmsghdr; STACK_BATCH] = std::array::from_fn(|_| zeroed_mmsghdr());
        send_with_headers(
            fd,
            payloads,
            addr,
            &mut iovecs[..payloads.len()],
            &mut msgs[..payloads.len()],
        )
    } else {
        let mut iovecs: Vec<libc::iovec> = (0..payloads.len()).map(|_| empty_iovec()).collect();
        let mut msgs: Vec<libc::mmsghdr> = (0..payloads.len()).map(|_| zeroed_mmsghdr()).collect();
        send_with_headers(fd, payloads, addr, &mut iovecs, &mut msgs)
    }
}

fn send_with_headers(
    fd: RawFd,
    payloads: &[&[u8]],
    addr: SocketAddr,
    iovecs: &mut [libc::iovec],
    msgs: &mut [libc::mmsghdr],
) -> io::Result<usize> {
    debug_assert_eq!(iovecs.len(), payloads.len());
    debug_assert_eq!(msgs.len(), payloads.len());

    // `socket2::SockAddr` owns the storage so we keep it alive for the
    // duration of the syscall — each `msghdr` points into the same
    // address. `sendmmsg` does not retain pointers past the call.
    let sa = socket2::SockAddr::from(addr);
    for (i, payload) in payloads.iter().enumerate() {
        iovecs[i] = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        msgs[i].msg_hdr.msg_name = sa.as_ptr() as *mut libc::c_void;
        msgs[i].msg_hdr.msg_namelen = sa.len();
        msgs[i].msg_hdr.msg_iov = &mut iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = ptr::null_mut();
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }

    sendmmsg_with_retry(fd, msgs)
}

fn sendmmsg_with_retry(fd: RawFd, msgs: &mut [libc::mmsghdr]) -> io::Result<usize> {
    let batch = libc::c_uint::try_from(msgs.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "sendmmsg batch exceeds c_uint::MAX",
        )
    })?;

    let mut eintr_count = 0;
    loop {
        // SAFETY: FFI call into Linux `sendmmsg`. `msgs` is a live mutable
        // slice of initialized `mmsghdr` values; each entry's `msg_iov`,
        // `msg_name`, and `msg_namelen` were filled by `send_with_headers`.
        // The kernel does not retain pointers past the syscall.
        let n = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), batch, libc::MSG_DONTWAIT) };

        if n >= 0 {
            return Ok(n as usize);
        }

        let err = io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(libc::EIO);

        if errno == libc::EINTR && eintr_count < EINTR_RETRIES {
            eintr_count += 1;
            continue;
        }
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "sendmmsg would block",
            ));
        }
        if errno == libc::ENOSYS || errno == libc::EPERM {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("sendmmsg syscall unavailable (errno={errno})"),
            ));
        }
        return Err(err);
    }
}

fn empty_iovec() -> libc::iovec {
    libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }
}

fn zeroed_mmsghdr() -> libc::mmsghdr {
    // SAFETY: `mmsghdr` is a plain C header struct. A zeroed value
    // represents null optional pointers, zero lengths, zero flags, and
    // zero payload length; all fields that must be non-null are filled
    // before passing it to the kernel.
    unsafe { MaybeUninit::<libc::mmsghdr>::zeroed().assume_init() }
}

fn is_already_registered(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::AlreadyExists || err.raw_os_error() == Some(libc::EEXIST)
}

fn duplicate_fd(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` is called with a raw descriptor
    // borrowed from the caller. On success it returns a new descriptor
    // referring to the same open file description; ownership of that new
    // descriptor is transferred into `OwnedFd` below. The borrowed input
    // descriptor is not closed or otherwise modified by this call.
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `duplicated` is a freshly returned file descriptor from a
    // successful `fcntl(F_DUPFD_CLOEXEC)` call, so no other Rust value
    // owns it. Wrapping in `OwnedFd` gives it exactly one owner that
    // will close it when the `BatchSender` is dropped.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn single_send_round_trip() {
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let sender = BatchSender::from_udp_socket(&send_sock).unwrap();
        let n = sender.send_batch(&[b"hello"], recv_addr).await.unwrap();
        assert_eq!(n, 1);
        let mut buf = [0u8; 16];
        let (sz, _) = recv_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..sz], b"hello");
    }

    #[tokio::test]
    async fn multi_send_arrives_intact() {
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let sender = BatchSender::from_udp_socket(&send_sock).unwrap();

        let payloads: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 64]).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(|v| v.as_slice()).collect();
        let n = sender.send_batch(&refs, recv_addr).await.unwrap();
        assert!((1..=8).contains(&n), "got n={n}");

        // Drain whatever arrived.
        let mut received = 0usize;
        let mut buf = vec![0u8; 256];
        while received < n {
            let r = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                recv_sock.recv_from(&mut buf),
            )
            .await;
            match r {
                Ok(Ok(_)) => received += 1,
                _ => break,
            }
        }
        assert!(received >= 1);
    }

    #[tokio::test]
    async fn empty_batch_returns_zero() {
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = BatchSender::from_udp_socket(&send_sock).unwrap();
        let n = sender
            .send_batch(&[], "127.0.0.1:9".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(n, 0);
    }
}
