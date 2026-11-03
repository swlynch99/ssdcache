//! Control plane (design §2.1, §2.3, §9): accept, TLS handshake + kTLS install, worker
//! selection and handoff, the admin HTTP endpoint. These threads may allocate; they never
//! run request processing.

use crate::config::{Config, Listener};
use crate::stats::WorkerStats;
use crate::worker::Handoff;
use crate::xshard::Mesh;
use crossbeam_queue::ArrayQueue;
use io_uring::{IoUring, opcode, types};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::*};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const K_HANDOFF: u64 = 4 << 56; // same "doorbell" kind as worker::K_DOORBELL

pub struct Control {
    pub mesh: Arc<Mesh>,
    pub handoff: Arc<Vec<ArrayQueue<Handoff>>>,
    pub stop: Arc<AtomicBool>,
    pub stats: Arc<Vec<WorkerStats>>,
    pub next: AtomicUsize,
}

/// A small ring used only to send MSG_RING doorbells from a control thread.
struct Bell {
    ring: IoUring,
}

impl Bell {
    fn new() -> std::io::Result<Bell> {
        Ok(Bell { ring: IoUring::new(8)? })
    }
    fn ring(&mut self, fd: i32) {
        let e = opcode::MsgRingData::new(types::Fd(fd), 0, K_HANDOFF, None).build().user_data(0);
        unsafe {
            let _ = self.ring.submission().push(&e);
        }
        let _ = self.ring.submit_and_wait(1);
        self.ring.completion().for_each(drop);
    }
}

impl Control {
    fn hand_off(&self, bell: &mut Bell, mut h: Handoff) {
        let n = self.mesh.n as usize;
        let w = self.next.fetch_add(1, Relaxed) % n;
        loop {
            match self.handoff[w].push(h) {
                Ok(()) => break,
                Err(back) => {
                    h = back;
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        if self.mesh.needs_doorbell(w as u16) {
            let fd = self.mesh.ring_fd[w].load(Relaxed);
            if fd >= 0 {
                bell.ring(fd);
            }
        }
    }
}

fn set_sockopts(fd: i32) {
    let one: libc::c_int = 1;
    let sndbuf: libc::c_int = 512 * 1024;
    let lowat: libc::c_int = 128 * 1024;
    unsafe {
        libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, &one as *const _ as *const _, 4);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, &sndbuf as *const _ as *const _, 4);
        libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_NOTSENT_LOWAT, &lowat as *const _ as *const _, 4);
    }
}

fn set_timeouts(fd: i32, ms: u32) {
    let tv = libc::timeval { tv_sec: (ms / 1000) as _, tv_usec: ((ms % 1000) * 1000) as _ };
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const _, std::mem::size_of_val(&tv) as u32);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDTIMEO, &tv as *const _ as *const _, std::mem::size_of_val(&tv) as u32);
    }
}

/// Start the acceptor, the handshake pool and the admin listener. Returns the bound
/// listener addresses (useful when a port of 0 was configured).
pub fn start(cfg: &Config, ctl: Arc<Control>) -> std::io::Result<Vec<std::net::SocketAddr>> {
    let tls_cfg = match &cfg.tls {
        Some(t) => Some(crate::tls::load_server_config(&t.cert, &t.key)?),
        None => None,
    };
    let (tx, rx) = mpsc::channel::<(i32, Listener)>();
    let rx = Arc::new(Mutex::new(rx));
    if let (Some(tc), Some(sc)) = (&cfg.tls, &tls_cfg) {
        for i in 0..tc.handshake_threads.max(1) {
            let rx = rx.clone();
            let sc = sc.clone();
            let ctl = ctl.clone();
            let timeout = tc.handshake_timeout_ms;
            std::thread::Builder::new().name(format!("tls-{i}")).spawn(move || {
                let mut bell = Bell::new().expect("bell ring");
                loop {
                    let job = rx.lock().unwrap().recv();
                    let Ok((fd, l)) = job else { return };
                    set_timeouts(fd, timeout);
                    match crate::tls::handshake_and_install(fd, &sc) {
                        Ok(_info) => {
                            set_timeouts(fd, 0);
                            ctl.hand_off(&mut bell, Handoff { fd, proto: l.proto, tls: true });
                        }
                        Err(e) => {
                            if std::env::var_os("SSDCACHE_DEBUG").is_some() {
                                eprintln!("tls handshake failed: {e}");
                            }
                            unsafe { libc::close(fd) };
                        }
                    }
                }
            })?;
        }
    }

    let mut addrs = Vec::new();
    let mut listeners = Vec::new();
    for l in &cfg.listeners {
        let tl = TcpListener::bind(&l.addr)?;
        addrs.push(tl.local_addr()?);
        listeners.push((tl, l.clone()));
    }
    {
        let ctl = ctl.clone();
        std::thread::Builder::new().name("acceptor".into()).spawn(move || {
            let mut bell = Bell::new().expect("bell ring");
            let mut pfds: Vec<libc::pollfd> =
                listeners.iter().map(|(t, _)| libc::pollfd { fd: t.as_raw_fd(), events: libc::POLLIN, revents: 0 }).collect();
            while !ctl.stop.load(Relaxed) {
                let r = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as _, 200) };
                if r <= 0 {
                    continue;
                }
                for (i, p) in pfds.iter_mut().enumerate() {
                    if p.revents & libc::POLLIN == 0 {
                        continue;
                    }
                    p.revents = 0;
                    let (tl, l) = &listeners[i];
                    let Ok((s, _peer)) = tl.accept() else { continue };
                    let fd = s.into_raw_fd();
                    set_sockopts(fd);
                    if l.tls {
                        let _ = tx.send((fd, l.clone()));
                    } else {
                        ctl.hand_off(&mut bell, Handoff { fd, proto: l.proto, tls: false });
                    }
                }
            }
        })?;
    }

    if let Some(admin) = &cfg.admin_addr {
        let al = TcpListener::bind(admin)?;
        addrs.push(al.local_addr()?);
        let ctl = ctl.clone();
        std::thread::Builder::new().name("admin".into()).spawn(move || {
            for s in al.incoming() {
                let Ok(mut s) = s else { continue };
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.split_whitespace().nth(1).unwrap_or("/");
                let (code, body) = match path {
                    "/stats" => ("200 OK", crate::stats::render_json(&ctl.stats, &[])),
                    "/shutdown" => {
                        ctl.stop.store(true, Relaxed);
                        ("200 OK", "{\"ok\":true}\n".to_string())
                    }
                    _ => ("404 Not Found", "{}\n".to_string()),
                };
                let _ = write!(s, "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        })?;
    }
    Ok(addrs)
}
