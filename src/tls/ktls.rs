//! Kernel TLS (kTLS) UAPI definitions and socket helpers.
//!
//! Values are from `include/uapi/linux/tls.h` (checked against the installed
//! `/usr/include/linux/tls.h` and kernel 6.6). `libc` has `SOL_TLS` and
//! `TCP_ULP`, but not the crypto-info structs, so all of it is defined here.

use std::io;
use std::mem;
use std::os::fd::RawFd;

use rustls::ConnectionTrafficSecrets;

// --- include/uapi/linux/tls.h -------------------------------------------------

/// `SOL_TLS` (include/linux/socket.h).
pub const SOL_TLS: libc::c_int = 282;
/// `TCP_ULP` (include/uapi/linux/tcp.h).
pub const TCP_ULP: libc::c_int = 31;

/// Socket options at level `SOL_TLS`.
pub const TLS_TX: libc::c_int = 1;
pub const TLS_RX: libc::c_int = 2;
pub const TLS_RX_EXPECT_NO_PAD: libc::c_int = 4;

/// cmsg types at level `SOL_TLS`.
pub const TLS_SET_RECORD_TYPE: libc::c_int = 1;
pub const TLS_GET_RECORD_TYPE: libc::c_int = 2;

/// `TLS_VERSION_NUMBER(TLS_1_3)` = (3 << 8) | 4.
pub const TLS_1_3_VERSION: u16 = 0x0304;

pub const TLS_CIPHER_AES_GCM_128: u16 = 51;
pub const TLS_CIPHER_AES_GCM_256: u16 = 52;
pub const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

/// TLS record content types.
pub const CONTENT_ALERT: u8 = 21;
pub const CONTENT_HANDSHAKE: u8 = 22;
pub const CONTENT_APPLICATION_DATA: u8 = 23;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct TlsCryptoInfo {
    version: u16,
    cipher_type: u16,
}

#[repr(C)]
pub(crate) struct Tls12CryptoInfoAesGcm128 {
    info: TlsCryptoInfo,
    iv: [u8; 8],
    key: [u8; 16],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

#[repr(C)]
pub(crate) struct Tls12CryptoInfoAesGcm256 {
    info: TlsCryptoInfo,
    iv: [u8; 8],
    key: [u8; 32],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

#[repr(C)]
pub(crate) struct Tls12CryptoInfoChacha20Poly1305 {
    info: TlsCryptoInfo,
    iv: [u8; 12],
    key: [u8; 32],
    // salt[0]
    rec_seq: [u8; 8],
}

// Layout checks against the kernel struct sizes (all byte arrays, no padding).
const _: () = assert!(mem::size_of::<Tls12CryptoInfoAesGcm128>() == 40);
const _: () = assert!(mem::size_of::<Tls12CryptoInfoAesGcm256>() == 56);
const _: () = assert!(mem::size_of::<Tls12CryptoInfoChacha20Poly1305>() == 56);

/// Kernel crypto info for one direction, built from rustls secrets.
/// Key material is zeroed on drop.
pub(crate) enum CryptoInfo {
    Aes128Gcm(Tls12CryptoInfoAesGcm128),
    Aes256Gcm(Tls12CryptoInfoAesGcm256),
    Chacha20Poly1305(Tls12CryptoInfoChacha20Poly1305),
}

impl CryptoInfo {
    pub(crate) fn from_secrets(seq: u64, secrets: &ConnectionTrafficSecrets) -> io::Result<Self> {
        let rec_seq = seq.to_be_bytes();
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "unexpected kTLS key/iv length");
        match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                let (k, iv) = (key.as_ref(), iv.as_ref());
                Ok(Self::Aes128Gcm(Tls12CryptoInfoAesGcm128 {
                    info: TlsCryptoInfo {
                        version: TLS_1_3_VERSION,
                        cipher_type: TLS_CIPHER_AES_GCM_128,
                    },
                    iv: iv
                        .get(4..12)
                        .ok_or_else(bad)?
                        .try_into()
                        .map_err(|_| bad())?,
                    key: k.try_into().map_err(|_| bad())?,
                    salt: iv
                        .get(0..4)
                        .ok_or_else(bad)?
                        .try_into()
                        .map_err(|_| bad())?,
                    rec_seq,
                }))
            }
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                let (k, iv) = (key.as_ref(), iv.as_ref());
                Ok(Self::Aes256Gcm(Tls12CryptoInfoAesGcm256 {
                    info: TlsCryptoInfo {
                        version: TLS_1_3_VERSION,
                        cipher_type: TLS_CIPHER_AES_GCM_256,
                    },
                    iv: iv
                        .get(4..12)
                        .ok_or_else(bad)?
                        .try_into()
                        .map_err(|_| bad())?,
                    key: k.try_into().map_err(|_| bad())?,
                    salt: iv
                        .get(0..4)
                        .ok_or_else(bad)?
                        .try_into()
                        .map_err(|_| bad())?,
                    rec_seq,
                }))
            }
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                Ok(Self::Chacha20Poly1305(Tls12CryptoInfoChacha20Poly1305 {
                    info: TlsCryptoInfo {
                        version: TLS_1_3_VERSION,
                        cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
                    },
                    iv: iv.as_ref().try_into().map_err(|_| bad())?,
                    key: key.as_ref().try_into().map_err(|_| bad())?,
                    rec_seq,
                }))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cipher suite not supported by kTLS",
            )),
        }
    }

    pub(crate) fn cipher_name(&self) -> &'static str {
        match self {
            Self::Aes128Gcm(_) => "TLS13_AES_128_GCM_SHA256",
            Self::Aes256Gcm(_) => "TLS13_AES_256_GCM_SHA384",
            Self::Chacha20Poly1305(_) => "TLS13_CHACHA20_POLY1305_SHA256",
        }
    }

    fn as_raw(&self) -> (*const libc::c_void, libc::socklen_t) {
        fn raw<T>(t: &T) -> (*const libc::c_void, libc::socklen_t) {
            (
                (t as *const T).cast(),
                mem::size_of::<T>() as libc::socklen_t,
            )
        }
        match self {
            Self::Aes128Gcm(c) => raw(c),
            Self::Aes256Gcm(c) => raw(c),
            Self::Chacha20Poly1305(c) => raw(c),
        }
    }

    /// `setsockopt(SOL_TLS, TLS_TX | TLS_RX, self)`.
    pub(crate) fn install(&self, fd: RawFd, dir: libc::c_int) -> io::Result<()> {
        let (p, len) = self.as_raw();
        // SAFETY: p points to a live repr(C) struct of `len` bytes.
        cvt(unsafe { libc::setsockopt(fd, SOL_TLS, dir, p, len) })
    }
}

impl Drop for CryptoInfo {
    fn drop(&mut self) {
        let (p, len) = self.as_raw();
        let p = p as *mut u8;
        for i in 0..len as usize {
            // SAFETY: in-bounds bytes of a struct we own; volatile so it is not elided.
            unsafe { std::ptr::write_volatile(p.add(i), 0) };
        }
    }
}

fn cvt(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `setsockopt(SOL_TCP, TCP_ULP, "tls")`.
pub(crate) fn set_ulp_tls(fd: RawFd) -> io::Result<()> {
    let name = b"tls";
    // SAFETY: valid pointer/length.
    cvt(unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_TCP,
            TCP_ULP,
            name.as_ptr().cast(),
            name.len() as _,
        )
    })
}

/// Best-effort `TLS_RX_EXPECT_NO_PAD = 1`. Returns whether the kernel accepted it
/// (and reports it back via getsockopt).
pub(crate) fn set_rx_expect_no_pad(fd: RawFd) -> bool {
    let one: u32 = 1;
    // SAFETY: valid pointer/length.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            SOL_TLS,
            TLS_RX_EXPECT_NO_PAD,
            (&one as *const u32).cast(),
            4,
        )
    };
    if rc != 0 {
        return false;
    }
    let mut val: u32 = 0;
    let mut len: libc::socklen_t = 4;
    // SAFETY: valid pointers.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_TLS,
            TLS_RX_EXPECT_NO_PAD,
            (&mut val as *mut u32).cast(),
            &mut len,
        )
    };
    rc == 0 && val == 1
}

/// cmsg buffer for one `u8` payload, 8-byte aligned (CMSG_SPACE(1) == 24 on 64-bit).
#[repr(C, align(8))]
struct CmsgBuf([u8; 32]);

/// recvmsg one record and return (record_type, len).
pub(crate) fn recvmsg_record(fd: RawFd, buf: &mut [u8]) -> io::Result<(u8, usize)> {
    let mut cbuf = CmsgBuf([0; 32]);
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: zeroed msghdr is valid; fields set below.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.0.as_mut_ptr().cast();
    // SAFETY: CMSG_SPACE is a pure computation.
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(1) } as _;
    let n = loop {
        // SAFETY: msg points to valid iov/control buffers for the call's duration.
        let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if n >= 0 {
            break n as usize;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    };
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kTLS cmsg truncated",
        ));
    }
    // SAFETY: walking the control buffer filled by the kernel.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == SOL_TLS && (*c).cmsg_type == TLS_GET_RECORD_TYPE {
                return Ok((*libc::CMSG_DATA(c), n));
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if n == 0 {
        // EOF: no record, no cmsg.
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "no TLS_GET_RECORD_TYPE cmsg",
    ))
}

/// sendmsg `data` as one record of `record_type`.
pub(crate) fn sendmsg_record(fd: RawFd, record_type: u8, data: &[u8]) -> io::Result<()> {
    let mut cbuf = CmsgBuf([0; 32]);
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut _,
        iov_len: data.len(),
    };
    // SAFETY: zeroed msghdr is valid; fields set below.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.0.as_mut_ptr().cast();
    // SAFETY: CMSG macros on a buffer of sufficient size and alignment.
    unsafe {
        msg.msg_controllen = libc::CMSG_SPACE(1) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = SOL_TLS;
        (*c).cmsg_type = TLS_SET_RECORD_TYPE;
        (*c).cmsg_len = libc::CMSG_LEN(1) as _;
        *libc::CMSG_DATA(c) = record_type;
    }
    loop {
        // SAFETY: msg points to valid buffers for the call's duration.
        let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) };
        if n >= 0 {
            // A control record is tiny; the kernel sends it whole or not at all.
            return if n as usize == data.len() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short control record send",
                ))
            };
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Probe whether the kernel can install kTLS (TX and RX) for `cipher_type` by
/// configuring a throwaway loopback TCP connection with an all-zero key.
/// `Ok(false)` if the kernel lacks the AEAD (ENOENT, e.g. no
/// `CONFIG_CRYPTO_CHACHA20POLY1305`); `Err` if kTLS itself is unavailable.
pub(crate) fn probe_cipher(cipher_type: u16) -> io::Result<bool> {
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    let l = TcpListener::bind("127.0.0.1:0")?;
    let c = TcpStream::connect(l.local_addr()?)?;
    let _s = l.accept()?;
    let fd = c.as_raw_fd();
    set_ulp_tls(fd)?;
    let info = TlsCryptoInfo {
        version: TLS_1_3_VERSION,
        cipher_type,
    };
    let ci = match cipher_type {
        TLS_CIPHER_AES_GCM_128 => CryptoInfo::Aes128Gcm(Tls12CryptoInfoAesGcm128 {
            info,
            iv: [0; 8],
            key: [0; 16],
            salt: [0; 4],
            rec_seq: [0; 8],
        }),
        TLS_CIPHER_AES_GCM_256 => CryptoInfo::Aes256Gcm(Tls12CryptoInfoAesGcm256 {
            info,
            iv: [0; 8],
            key: [0; 32],
            salt: [0; 4],
            rec_seq: [0; 8],
        }),
        TLS_CIPHER_CHACHA20_POLY1305 => {
            CryptoInfo::Chacha20Poly1305(Tls12CryptoInfoChacha20Poly1305 {
                info,
                iv: [0; 12],
                key: [0; 32],
                rec_seq: [0; 8],
            })
        }
        _ => return Ok(false),
    };
    for dir in [TLS_TX, TLS_RX] {
        match ci.install(fd, dir) {
            Ok(()) => {}
            // ENOENT: AEAD not available. (EINVAL would mean a struct/size mismatch.)
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}
