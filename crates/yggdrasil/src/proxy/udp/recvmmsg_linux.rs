//! Linux batch receive via `libc::recvmmsg`, driven by `tokio::io::unix::AsyncFd`.
//!
//! Provides [`BatchReader`] and [`BatchBuf`] for pulling multiple UDP datagrams
//! per syscall. Used by the per-rule UDP worker loops to amortise syscall cost
//! under high pps. On non-Linux targets the module does not exist; callers
//! must gate `use proxy::udp::recvmmsg_linux::*` behind their own
//! `#[cfg(target_os = "linux")]` or go through [`super::batch_recv`], which
//! is the cross-platform abstraction (Linux: this module's `recvmmsg`;
//! non-Linux: per-datagram `tokio::net::UdpSocket::recv_from`).
//!
//! The receive path uses `MSG_DONTWAIT` (we have already awaited readiness
//! via `AsyncFd`; the syscall must never block). On `ENOSYS` / `EPERM`
//! (kernel too old or seccomp filter blocking recvmmsg), the caller should
//! fall back permanently to per-datagram recv.

#![cfg(target_os = "linux")]

use std::io;
use std::mem::{self, MaybeUninit};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::net::UdpSocket;

pub const DEFAULT_BATCH: usize = 32;
pub const MAX_DATAGRAM: usize = 65_535;
const EINTR_RETRIES: usize = 3;

pub struct Datagram<'a> {
    pub payload: &'a [u8],
    pub from: SocketAddr,
}

pub struct BatchBuf {
    storage: Vec<u8>,
    lens: Vec<u32>,
    addrs: Vec<libc::sockaddr_storage>,
    addr_lens: Vec<libc::socklen_t>,
    batch: usize,
}

impl BatchBuf {
    /// Panics on `batch == 0` (a zero-batch buffer is never valid).
    pub fn new(batch: usize) -> Self {
        assert!(batch >= 1, "BatchBuf::new requires batch >= 1");

        let storage = vec![0u8; batch * MAX_DATAGRAM];
        let lens = vec![0u32; batch];
        let addrs = (0..batch).map(|_| zeroed_sockaddr_storage()).collect();
        let addr_lens = vec![sockaddr_storage_len(); batch];

        Self {
            storage,
            lens,
            addrs,
            addr_lens,
            batch,
        }
    }

    pub fn batch_size(&self) -> usize {
        self.batch
    }

    /// Stash one (payload, from) pair into the first slot so callers can
    /// reuse the `iter_received` machinery in the Linux fallback path.
    /// Panics if `payload.len() > MAX_DATAGRAM`.
    pub(crate) fn write_single(&mut self, payload: &[u8], from: SocketAddr) {
        assert!(payload.len() <= MAX_DATAGRAM);
        self.storage[..payload.len()].copy_from_slice(payload);
        self.lens[0] = payload.len() as u32;

        let sa = socket2::SockAddr::from(from);
        // SAFETY: `SockAddr` points to a valid socket address with `len()`
        // initialized bytes. Slot 0 of `addrs` is live sockaddr_storage, and
        // the source length is bounded by the destination storage size.
        unsafe {
            let dest_ptr = &mut self.addrs[0] as *mut libc::sockaddr_storage as *mut u8;
            let src_ptr = sa.as_ptr() as *const u8;
            let len = sa.len() as usize;
            assert!(len <= mem::size_of::<libc::sockaddr_storage>());
            ptr::copy_nonoverlapping(src_ptr, dest_ptr, len);
            self.addr_lens[0] = sa.len();
        }
    }
}

pub struct BatchReader {
    fd: AsyncFd<RawFd>,
    _owned_fd: Option<OwnedFd>,
}

impl BatchReader {
    pub fn from_udp_socket(sock: &UdpSocket) -> io::Result<Self> {
        match AsyncFd::with_interest(sock.as_raw_fd(), Interest::READABLE) {
            Ok(fd) => Ok(Self {
                fd,
                _owned_fd: None,
            }),
            Err(err) if is_already_registered(&err) => {
                let owned_fd = duplicate_fd(sock.as_raw_fd())?;
                let fd = AsyncFd::with_interest(owned_fd.as_raw_fd(), Interest::READABLE)?;
                Ok(Self {
                    fd,
                    _owned_fd: Some(owned_fd),
                })
            }
            Err(err) => Err(err),
        }
    }

    pub async fn recv_batch(&self, buf: &mut BatchBuf) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| do_recvmmsg(inner.as_raw_fd(), buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

pub fn iter_received<'a>(buf: &'a BatchBuf, n: usize) -> impl Iterator<Item = Datagram<'a>> + 'a {
    (0..n).map(move |i| {
        let start = i * MAX_DATAGRAM;
        let end = start + buf.lens[i] as usize;
        Datagram {
            payload: &buf.storage[start..end],
            from: sockaddr_to_socket_addr(&buf.addrs[i], buf.addr_lens[i]),
        }
    })
}

fn is_already_registered(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::AlreadyExists || err.raw_os_error() == Some(libc::EEXIST)
}

fn duplicate_fd(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` is called with a raw descriptor borrowed
    // from the caller. On success it returns a new descriptor referring to the
    // same open file description; ownership of that new descriptor is
    // transferred below into `OwnedFd`. The borrowed input descriptor is not
    // closed or otherwise modified by this call.
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `duplicated` is a freshly returned file descriptor from a
    // successful `fcntl(F_DUPFD_CLOEXEC)` call, so no other Rust value owns it.
    // Wrapping it in `OwnedFd` gives it exactly one owner that will close it
    // when the fallback `BatchReader` is dropped.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn do_recvmmsg(fd: RawFd, buf: &mut BatchBuf) -> io::Result<usize> {
    if buf.batch <= DEFAULT_BATCH {
        let mut iovecs: [libc::iovec; DEFAULT_BATCH] = std::array::from_fn(|_| empty_iovec());
        let mut msgs: [libc::mmsghdr; DEFAULT_BATCH] = std::array::from_fn(|_| zeroed_mmsghdr());
        recv_with_headers(fd, buf, &mut iovecs[..buf.batch], &mut msgs[..buf.batch])
    } else {
        let mut iovecs: Vec<libc::iovec> = (0..buf.batch).map(|_| empty_iovec()).collect();
        let mut msgs: Vec<libc::mmsghdr> = (0..buf.batch).map(|_| zeroed_mmsghdr()).collect();
        recv_with_headers(fd, buf, &mut iovecs, &mut msgs)
    }
}

fn recv_with_headers(
    fd: RawFd,
    buf: &mut BatchBuf,
    iovecs: &mut [libc::iovec],
    msgs: &mut [libc::mmsghdr],
) -> io::Result<usize> {
    debug_assert_eq!(iovecs.len(), buf.batch);
    debug_assert_eq!(msgs.len(), buf.batch);

    prepare_headers(buf, iovecs, msgs);
    let n = recvmmsg_with_retry(fd, msgs, iovecs)?;

    for (i, msg) in msgs.iter().take(n).enumerate() {
        buf.lens[i] = msg.msg_len;
        buf.addr_lens[i] = msg.msg_hdr.msg_namelen;
    }

    Ok(n)
}

fn prepare_headers(buf: &mut BatchBuf, iovecs: &mut [libc::iovec], msgs: &mut [libc::mmsghdr]) {
    for i in 0..buf.batch {
        let storage_offset = i * MAX_DATAGRAM;
        iovecs[i] = libc::iovec {
            iov_base: buf.storage[storage_offset..]
                .as_mut_ptr()
                .cast::<libc::c_void>(),
            iov_len: MAX_DATAGRAM,
        };

        buf.addr_lens[i] = sockaddr_storage_len();
        msgs[i].msg_hdr.msg_name = (&mut buf.addrs[i] as *mut libc::sockaddr_storage).cast();
        msgs[i].msg_hdr.msg_namelen = sockaddr_storage_len();
        msgs[i].msg_hdr.msg_iov = &mut iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = ptr::null_mut();
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }
}

fn recvmmsg_with_retry(
    fd: RawFd,
    msgs: &mut [libc::mmsghdr],
    _iovecs: &mut [libc::iovec],
) -> io::Result<usize> {
    let batch = libc::c_uint::try_from(msgs.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "recvmmsg batch exceeds c_uint::MAX",
        )
    })?;

    let mut eintr_count = 0;
    loop {
        // SAFETY: FFI call into Linux `recvmmsg`. `msgs` is a live mutable
        // slice of initialized `mmsghdr` values, and each header was prepared
        // immediately before this call. Its `msg_iov` pointer targets the
        // parallel `_iovecs` slice and each `iovec` targets a disjoint window
        // of `BatchBuf::storage`; `msg_name` targets the matching disjoint
        // `BatchBuf::addrs` slot. Those allocations are kept alive and are not
        // accessed through Rust references while the kernel may write through
        // the raw pointers. The kernel does not retain the pointers after the
        // syscall returns, so aliasing is limited to this FFI call's duration.
        let n = unsafe {
            libc::recvmmsg(
                fd,
                msgs.as_mut_ptr(),
                batch,
                libc::MSG_DONTWAIT,
                ptr::null_mut(),
            )
        };

        if n >= 0 {
            return Ok(n as usize);
        }

        let err = io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(libc::EIO);

        if errno == libc::EINTR && eintr_count < EINTR_RETRIES {
            eintr_count += 1;
            continue;
        }

        return map_recvmmsg_error(errno, err);
    }
}

fn map_recvmmsg_error(errno: i32, err: io::Error) -> io::Result<usize> {
    if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "recvmmsg would block",
        ));
    }

    if errno == libc::ENOSYS || errno == libc::EPERM {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("recvmmsg syscall unavailable (errno={errno})"),
        ));
    }

    if errno == err.raw_os_error().unwrap_or(libc::EIO) {
        Err(err)
    } else {
        Err(io::Error::from_raw_os_error(errno))
    }
}

fn sockaddr_to_socket_addr(addr: &libc::sockaddr_storage, len: libc::socklen_t) -> SocketAddr {
    // `addr` and `len` come from the kernel-populated `msg_name` and
    // `msg_namelen` fields for a successfully received datagram. Copy the
    // storage into socket2's `SockAddrStorage` and hand it to `SockAddr::new`
    // with `len`, the exact initialized socket-address length reported by the
    // kernel for that storage.
    let mut storage = socket2::SockAddrStorage::zeroed();
    debug_assert!(
        len as usize <= mem::size_of::<libc::sockaddr_storage>(),
        "kernel-reported msg_namelen exceeds sockaddr_storage",
    );
    // SAFETY: on Unix, `SockAddrStorage` is `repr(transparent)` over
    // `libc::sockaddr_storage`, so viewing it as that type and overwriting it
    // with the kernel-populated value is sound.
    unsafe {
        *storage.view_as::<libc::sockaddr_storage>() = *addr;
    }
    // SAFETY: `storage` now holds the kernel-populated address whose
    // `ss_family` and initialized length (`len`) match, as required.
    unsafe { socket2::SockAddr::new(storage, len) }
        .as_socket()
        .expect("recvmmsg returned a non-IP socket address")
}

fn sockaddr_storage_len() -> libc::socklen_t {
    mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t
}

fn empty_iovec() -> libc::iovec {
    libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }
}

fn zeroed_mmsghdr() -> libc::mmsghdr {
    // SAFETY: `mmsghdr` is a plain C header struct. A zeroed value represents
    // null optional pointers, zero lengths, zero flags, and zero payload length;
    // all fields that must be non-null are filled before passing it to the
    // kernel.
    unsafe { MaybeUninit::<libc::mmsghdr>::zeroed().assume_init() }
}

fn zeroed_sockaddr_storage() -> libc::sockaddr_storage {
    // SAFETY: `sockaddr_storage` is an opaque plain C storage struct. Zeroing is
    // valid because the kernel overwrites the prefix indicated by `msg_namelen`
    // before the value is interpreted.
    unsafe { mem::zeroed() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn single_datagram_round_trip() {
        let recv_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let reader = BatchReader::from_udp_socket(&recv_sock).unwrap();
        let mut buf = BatchBuf::new(8);
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        send_sock.send_to(b"hello", recv_addr).await.unwrap();
        let n = reader.recv_batch(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        let dgrams: Vec<_> = iter_received(&buf, n).collect();
        assert_eq!(dgrams[0].payload, b"hello");
        assert_eq!(dgrams[0].from, send_sock.local_addr().unwrap());
    }

    #[tokio::test]
    async fn multi_datagram_batch() {
        let recv_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let reader = BatchReader::from_udp_socket(&recv_sock).unwrap();
        let mut buf = BatchBuf::new(16);
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for i in 0..8u8 {
            send_sock.send_to(&[i; 64], recv_addr).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let n = reader.recv_batch(&mut buf).await.unwrap();
        assert!((1..=8).contains(&n), "got n={n}");
        let payloads: Vec<u8> = iter_received(&buf, n).map(|d| d.payload[0]).collect();
        // Order may differ; just assert each byte was one we sent and all are unique.
        let mut sorted = payloads.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), n, "duplicate payloads in batch");
        for v in &sorted {
            assert!(*v < 8, "unexpected payload byte {v}");
        }
    }

    #[tokio::test]
    async fn ipv6_round_trip() {
        let recv_sock = UdpSocket::bind("[::1]:0").await.unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let reader = BatchReader::from_udp_socket(&recv_sock).unwrap();
        let mut buf = BatchBuf::new(4);
        let send_sock = UdpSocket::bind("[::1]:0").await.unwrap();
        send_sock.send_to(b"v6", recv_addr).await.unwrap();
        let n = reader.recv_batch(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        let dgrams: Vec<_> = iter_received(&buf, n).collect();
        assert_eq!(dgrams[0].payload, b"v6");
        assert!(dgrams[0].from.is_ipv6());
    }

    #[tokio::test]
    async fn payload_lengths_preserved() {
        let recv_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let reader = BatchReader::from_udp_socket(&recv_sock).unwrap();
        let mut buf = BatchBuf::new(8);
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        send_sock.send_to(&[1u8; 10], recv_addr).await.unwrap();
        send_sock.send_to(&[2u8; 100], recv_addr).await.unwrap();
        send_sock.send_to(&[3u8; 1000], recv_addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let n = reader.recv_batch(&mut buf).await.unwrap();
        let dgrams: Vec<_> = iter_received(&buf, n).collect();
        let mut lens: Vec<usize> = dgrams.iter().map(|d| d.payload.len()).collect();
        lens.sort();
        assert!(lens.starts_with(&[10, 100, 1000][..n.min(3)]));
    }

    #[test]
    fn write_single_round_trips_through_iterator() {
        let mut buf = BatchBuf::new(1);
        let from: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        buf.write_single(b"fallback", from);

        let dgrams: Vec<_> = iter_received(&buf, 1).collect();
        assert_eq!(dgrams[0].payload, b"fallback");
        assert_eq!(dgrams[0].from, from);
    }

    #[test]
    #[should_panic(expected = "BatchBuf::new requires batch >= 1")]
    fn empty_batch_panics() {
        let _ = BatchBuf::new(0);
    }
}
