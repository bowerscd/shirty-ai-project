//! Cross-platform UDP batch-receive shim.
//!
//! On Linux, uses `recvmmsg` via [`super::recvmmsg_linux`] to pull up to
//! [`DEFAULT_BATCH`] datagrams per syscall. On non-Linux, or when the
//! Linux syscall returns `ENOSYS` / `EPERM` at runtime, falls back to
//! per-datagram `tokio::net::UdpSocket::recv_from`.
//!
//! The `BatchRecv::recv` API yields a borrowed iterator of
//! `(payload, source)` pairs. The caller drains the iterator before the
//! next `recv` (the borrow keeps the buffer pinned in place).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

#[cfg(target_os = "linux")]
use super::recvmmsg_linux::{BatchBuf, BatchReader, DEFAULT_BATCH, MAX_DATAGRAM};

#[cfg(not(target_os = "linux"))]
const DEFAULT_BATCH: usize = 1;
#[cfg(not(target_os = "linux"))]
const MAX_DATAGRAM: usize = 65_535;

/// One received datagram view.
pub struct Datagram<'a> {
    pub payload: &'a [u8],
    pub from: SocketAddr,
}

/// Owned scratch buffer for a single batch. Re-use across calls.
pub struct BatchScratch {
    #[cfg(target_os = "linux")]
    linux: BatchBuf,
    #[cfg(not(target_os = "linux"))]
    fallback_buf: Vec<u8>,
    #[cfg(not(target_os = "linux"))]
    fallback_addr: Option<SocketAddr>,
    #[cfg(not(target_os = "linux"))]
    fallback_len: usize,
}

impl BatchScratch {
    pub fn new() -> Self {
        Self::with_batch(DEFAULT_BATCH)
    }

    pub fn with_batch(batch: usize) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                linux: BatchBuf::new(batch.max(1)),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = batch;
            Self {
                fallback_buf: vec![0u8; MAX_DATAGRAM],
                fallback_addr: None,
                fallback_len: 0,
            }
        }
    }
}

impl Default for BatchScratch {
    fn default() -> Self {
        Self::new()
    }
}

/// Wraps a frontend socket and dispatches batch recvs.
pub struct BatchRecv {
    sock: Arc<UdpSocket>,
    #[cfg(target_os = "linux")]
    reader: Option<BatchReader>,
}

impl BatchRecv {
    pub fn new(sock: Arc<UdpSocket>) -> Self {
        #[cfg(target_os = "linux")]
        {
            let reader = BatchReader::from_udp_socket(&sock).ok();
            Self { sock, reader }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self { sock }
        }
    }

    /// Receive up to [`DEFAULT_BATCH`] datagrams. Returns the count of
    /// datagrams populated in `scratch`; iterate via [`Self::iter`].
    pub async fn recv(&mut self, scratch: &mut BatchScratch) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            if let Some(reader) = &self.reader {
                match reader.recv_batch(&mut scratch.linux).await {
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                        tracing::warn!(
                            error = %e,
                            "recvmmsg syscall unavailable at runtime; falling back to recv_from for this worker"
                        );
                        self.reader = None;
                    }
                    Err(e) => return Err(e),
                }
            }

            let mut buf = vec![0u8; MAX_DATAGRAM];
            let (n, from) = self.sock.recv_from(&mut buf).await?;
            scratch.linux.write_single(&buf[..n], from);
            Ok(1)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let (n, from) = self.sock.recv_from(&mut scratch.fallback_buf).await?;
            scratch.fallback_addr = Some(from);
            scratch.fallback_len = n;
            Ok(1)
        }
    }

    /// Iterate over the datagrams populated by the most recent `recv` call.
    /// `n` MUST be the value returned by that call.
    pub fn iter<'a>(
        &self,
        scratch: &'a BatchScratch,
        n: usize,
    ) -> Box<dyn Iterator<Item = Datagram<'a>> + 'a> {
        #[cfg(target_os = "linux")]
        {
            Box::new(
                super::recvmmsg_linux::iter_received(&scratch.linux, n).map(|d| Datagram {
                    payload: d.payload,
                    from: d.from,
                }),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            if n == 0 {
                Box::new(std::iter::empty())
            } else {
                let payload = &scratch.fallback_buf[..scratch.fallback_len];
                let from = scratch.fallback_addr.expect("addr set by recv on n>=1");
                Box::new(std::iter::once(Datagram { payload, from }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_single_datagram() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let mut recv = BatchRecv::new(Arc::clone(&sock));
        let mut scratch = BatchScratch::new();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"hello", addr).await.unwrap();

        let n = recv.recv(&mut scratch).await.unwrap();
        assert!(n >= 1);
        let dgrams: Vec<_> = recv
            .iter(&scratch, n)
            .map(|d| (d.payload.to_vec(), d.from))
            .collect();
        assert_eq!(&dgrams[0].0, b"hello");
        assert_eq!(dgrams[0].1, client.local_addr().unwrap());
    }
}
