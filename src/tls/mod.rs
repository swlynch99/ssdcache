//! TLS 1.3 termination: rustls handshake on the control thread, then kernel TLS.
//!
//! After [`handshake_and_install`] returns, the socket is a kTLS socket: plain
//! `recv`/`send`/`sendmsg` carry application data and the kernel encrypts and
//! decrypts. A plain `recv` returns `-EIO` when the next record is not
//! application data; read it with [`recv_control_record`] and act on
//! [`classify`].
//!
//! The handshake is record-exact: it reads a 5-byte record header, then exactly
//! the record body, and stops after the client Finished. Application data that
//! the client pipelines behind its Finished stays in the kernel socket queue and
//! is decrypted by kTLS RX (record sequence 0).

mod ktls;

use std::fs::File;
use std::io::{self, BufReader};
use std::os::fd::RawFd;
use std::path::Path;
use std::sync::Arc;

use rustls::server::{NoServerSessionStorage, UnbufferedServerConnection};
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};

pub use ktls::{CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_HANDSHAKE};

/// Largest TLSCiphertext body (RFC 8446 §5.2): 2^14 + 256.
const MAX_RECORD_BODY: usize = 16384 + 256;
const RECORD_HEADER: usize = 5;
/// Upper bound on buffered, not-yet-complete handshake data (a handshake
/// message can span records; rustls joins them in our input buffer).
const MAX_HS_BUFFER: usize = 64 * 1024;

/// Build the server config: TLS 1.3 only, aws-lc-rs, suites
/// AES-128-GCM > AES-256-GCM > ChaCha20-Poly1305 (server order wins; suites
/// the kernel cannot install in kTLS are left out, see [`probe_ktls_ciphers`]),
/// secret extraction on, no tickets, no resumption, no 0-RTT.
pub fn load_server_config(
    cert_pem_path: &Path,
    key_pem_path: &Path,
) -> io::Result<Arc<rustls::ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(cert_pem_path)?))
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(invalid(format!(
            "no certificates in {}",
            cert_pem_path.display()
        )));
    }
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key_pem_path)?))?
        .ok_or_else(|| invalid(format!("no private key in {}", key_pem_path.display())))?;

    use rustls::crypto::aws_lc_rs::{self as provider, cipher_suite as cs};
    let support = probe_ktls_ciphers()?;
    let mut p = provider::default_provider();
    p.cipher_suites = [
        (support.aes128_gcm, cs::TLS13_AES_128_GCM_SHA256),
        (support.aes256_gcm, cs::TLS13_AES_256_GCM_SHA384),
        (
            support.chacha20_poly1305,
            cs::TLS13_CHACHA20_POLY1305_SHA256,
        ),
    ]
    .into_iter()
    .filter_map(|(ok, s)| ok.then_some(s))
    .collect();
    if p.cipher_suites.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "kernel supports no kTLS TLS 1.3 cipher",
        ));
    }
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_err)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(tls_err)?;
    cfg.enable_secret_extraction = true;
    cfg.send_tls13_tickets = 0;
    cfg.max_early_data_size = 0;
    cfg.session_storage = Arc::new(NoServerSessionStorage {});
    cfg.ignore_client_order = true; // server order wins
    Ok(Arc::new(cfg))
}

/// Which TLS 1.3 AEADs the running kernel can do in kTLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KtlsCipherSupport {
    pub aes128_gcm: bool,
    pub aes256_gcm: bool,
    pub chacha20_poly1305: bool,
}

/// Probe kTLS cipher support (three throwaway loopback connections).
/// `Err` if kTLS is unavailable altogether (no "tls" ULP).
/// [`load_server_config`] calls this and only offers suites the kernel can
/// install, so a handshake never succeeds on a suite kTLS then rejects.
pub fn probe_ktls_ciphers() -> io::Result<KtlsCipherSupport> {
    Ok(KtlsCipherSupport {
        aes128_gcm: ktls::probe_cipher(ktls::TLS_CIPHER_AES_GCM_128)?,
        aes256_gcm: ktls::probe_cipher(ktls::TLS_CIPHER_AES_GCM_256)?,
        chacha20_poly1305: ktls::probe_cipher(ktls::TLS_CIPHER_CHACHA20_POLY1305)?,
    })
}

/// What was installed on the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KtlsInfo {
    /// IANA-style suite name, e.g. `TLS13_AES_128_GCM_SHA256`.
    pub cipher: &'static str,
    /// Whether `TLS_RX_EXPECT_NO_PAD` was accepted by the kernel.
    pub rx_no_pad: bool,
}

/// Blocking, record-exact handshake on a connected TCP socket `fd` (caller set
/// SO_RCVTIMEO/SO_SNDTIMEO as the handshake deadline), then install kTLS TX+RX.
/// On success the fd is a kTLS socket.
///
/// On error the caller must close the fd (it may be half-configured: e.g. the
/// "tls" ULP attached but no keys). A timeout surfaces as `ErrorKind::TimedOut`.
pub fn handshake_and_install(fd: RawFd, cfg: &Arc<rustls::ServerConfig>) -> io::Result<KtlsInfo> {
    let mut conn = UnbufferedServerConnection::new(cfg.clone()).map_err(tls_err)?;

    let mut inbuf: Vec<u8> = vec![0; RECORD_HEADER + MAX_RECORD_BODY];
    let mut inlen = 0usize;
    let mut outbuf: Vec<u8> = vec![0; 4096];
    let mut outlen = 0usize;

    loop {
        let UnbufferedStatus { discard, state } = conn.process_tls_records(&mut inbuf[..inlen]);
        let need_read = match state.map_err(tls_err)? {
            ConnectionState::EncodeTlsData(mut enc) => {
                loop {
                    match enc.encode(&mut outbuf[outlen..]) {
                        Ok(n) => {
                            outlen += n;
                            break;
                        }
                        Err(EncodeError::InsufficientSize(e)) => {
                            outbuf.resize(outlen + e.required_size, 0);
                        }
                        Err(e) => return Err(invalid(format!("TLS encode: {e}"))),
                    }
                }
                false
            }
            ConnectionState::TransmitTlsData(tx) => {
                send_all(fd, &outbuf[..outlen])?;
                outlen = 0;
                tx.done();
                false
            }
            // The server may send (0.5-RTT) once its Finished is out, but the
            // handshake is not complete until the client Finished is processed.
            ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_) => true,
            ConnectionState::ReadTraffic(_) | ConnectionState::ReadEarlyData(_) => {
                // Impossible with record-exact reads that stop at Finished, and
                // 0-RTT is disabled.
                return Err(invalid("application data during handshake".into()));
            }
            ConnectionState::PeerClosed | ConnectionState::Closed => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "peer closed during handshake",
                ));
            }
            other => return Err(invalid(format!("unexpected TLS state {other:?}"))),
        };

        if discard > 0 {
            inbuf.copy_within(discard..inlen, 0);
            inlen -= discard;
        }

        if need_read {
            if !conn.is_handshaking() {
                break;
            }
            read_one_record(fd, &mut inbuf, &mut inlen)?;
        }
    }

    // Any pending handshake bytes were sent by the TransmitTlsData arm; rustls
    // also refuses the conversion if it still has records queued.
    debug_assert_eq!(outlen, 0);
    if inlen != 0 {
        // Bytes we read but rustls did not consume. Cannot happen with
        // record-exact reads (Finished is the last handshake message).
        return Err(invalid(format!("{inlen} unconsumed bytes after handshake")));
    }

    // dangerous_into_kernel_connection gives (seq, secrets) per direction with
    // the sequence numbers from rustls's record layer (0/0 after a TLS 1.3
    // handshake with no tickets). The KernelConnection is what a future kTLS
    // rekey (6.14+) would keep to derive the next traffic secrets.
    let (secrets, _kernel_conn) = conn.dangerous_into_kernel_connection().map_err(tls_err)?;
    let (tx_seq, tx) = &secrets.tx;
    let (rx_seq, rx) = &secrets.rx;
    let tx_info = ktls::CryptoInfo::from_secrets(*tx_seq, tx)?;
    let rx_info = ktls::CryptoInfo::from_secrets(*rx_seq, rx)?;
    drop(secrets);

    ktls::set_ulp_tls(fd)?;
    tx_info.install(fd, ktls::TLS_TX)?;
    rx_info.install(fd, ktls::TLS_RX)?;
    let rx_no_pad = ktls::set_rx_expect_no_pad(fd);

    Ok(KtlsInfo {
        cipher: tx_info.cipher_name(),
        rx_no_pad,
    })
}

/// For a kTLS socket: read one pending non-application record with recvmsg +
/// cmsg (SOL_TLS, TLS_GET_RECORD_TYPE). Called after a plain recv returned
/// -EIO. Returns (record_type, bytes) into `buf`.
///
/// `buf` should hold at least 256 bytes. If application data is next instead,
/// it returns type 23 and the data (it does not fail).
pub fn recv_control_record(fd: RawFd, buf: &mut [u8]) -> io::Result<(u8, usize)> {
    ktls::recvmsg_record(fd, buf)
}

/// Send a TLS alert record (close_notify = [1, 0]) via sendmsg with a
/// TLS_SET_RECORD_TYPE=21 cmsg.
pub fn send_close_notify(fd: RawFd) -> io::Result<()> {
    ktls::sendmsg_record(fd, CONTENT_ALERT, &[1, 0])
}

/// A non-application-data record read from a kTLS socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRecord {
    /// Alert (type 21). `level` 1 = warning, 2 = fatal; `desc` 0 = close_notify.
    Alert { level: u8, desc: u8 },
    /// TLS 1.3 KeyUpdate (handshake type 24). `request_update` = update_requested.
    KeyUpdate { request_update: bool },
    /// Anything else (e.g. NewSessionTicket, malformed records).
    Other,
}

impl ControlRecord {
    pub fn is_close_notify(&self) -> bool {
        matches!(self, ControlRecord::Alert { desc: 0, .. })
    }
}

/// Classify a control record: Alert{level, desc}, KeyUpdate{request_update}, Other.
pub fn classify(record_type: u8, data: &[u8]) -> ControlRecord {
    match (record_type, data) {
        (CONTENT_ALERT, &[level, desc]) => ControlRecord::Alert { level, desc },
        // msg_type 24 (key_update), length 1, KeyUpdateRequest 0|1.
        (CONTENT_HANDSHAKE, &[24, 0, 0, 1, req, ..]) if req <= 1 => ControlRecord::KeyUpdate {
            request_update: req == 1,
        },
        _ => ControlRecord::Other,
    }
}

// --- helpers ------------------------------------------------------------------

/// Append exactly one TLS record (header + body) to `buf[*len..]`.
fn read_one_record(fd: RawFd, buf: &mut Vec<u8>, len: &mut usize) -> io::Result<()> {
    let start = *len;
    if buf.len() < start + RECORD_HEADER {
        buf.resize(start + RECORD_HEADER, 0);
    }
    recv_exact(fd, &mut buf[start..start + RECORD_HEADER])?;
    let hdr = &buf[start..start + RECORD_HEADER];
    let body = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if body > MAX_RECORD_BODY {
        return Err(invalid(format!("TLS record too large ({body})")));
    }
    let end = start + RECORD_HEADER + body;
    if end > MAX_HS_BUFFER {
        return Err(invalid("handshake message too large".into()));
    }
    if buf.len() < end {
        buf.resize(end, 0);
    }
    recv_exact(fd, &mut buf[start + RECORD_HEADER..end])?;
    *len = end;
    Ok(())
}

/// recv exactly `buf.len()` bytes (MSG_WAITALL, retried on short reads / EINTR).
fn recv_exact(fd: RawFd, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: valid buffer.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_WAITALL) };
        if n > 0 {
            buf = &mut buf[n as usize..];
        } else if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed during handshake",
            ));
        } else {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TLS handshake recv timed out",
                    ));
                }
                _ => return Err(e),
            }
        }
    }
    Ok(())
}

fn send_all(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: valid buffer.
        let n = unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL) };
        if n >= 0 {
            buf = &buf[n as usize..];
        } else {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TLS handshake send timed out",
                    ));
                }
                _ => return Err(e),
            }
        }
    }
    Ok(())
}

fn tls_err(e: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_records() {
        assert_eq!(
            classify(21, &[1, 0]),
            ControlRecord::Alert { level: 1, desc: 0 }
        );
        assert!(classify(21, &[1, 0]).is_close_notify());
        assert_eq!(
            classify(21, &[2, 40]),
            ControlRecord::Alert { level: 2, desc: 40 }
        );
        assert_eq!(
            classify(22, &[24, 0, 0, 1, 1]),
            ControlRecord::KeyUpdate {
                request_update: true
            }
        );
        assert_eq!(
            classify(22, &[24, 0, 0, 1, 0]),
            ControlRecord::KeyUpdate {
                request_update: false
            }
        );
        assert_eq!(classify(22, &[24, 0, 0, 1, 2]), ControlRecord::Other);
        assert_eq!(classify(22, &[4, 0, 0, 0]), ControlRecord::Other);
        assert_eq!(classify(21, &[1]), ControlRecord::Other);
    }
}
