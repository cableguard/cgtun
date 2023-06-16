// Copyright (c) 2023 cableguard, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
use hex::encode;
use tracing::error;
use hex::ToHex; // Import the `ToHex` trait to convert byte arrays to hexadecimal strings
pub mod allowed_ips;
pub mod api;
mod dev_lock;
pub mod drop_privileges;
#[cfg(test)]
mod integration_tests;
pub mod peer;
use std::process::Command;
use hex::FromHex;
use api::nearorg_rpc_token;
use crate::serialization::{KeyBytes, self};
use std::convert::TryInto;

// This is an embarrasing bit: I am reimplementing this because I don't know how to import it
const SMART_CONTRACT: &str = "dev-1686226311171-75846299095937";
const BLOCKCHAIN_ENV: &str = "testnet."; // IMPORTANT: Values here must be either "testnet." for tesnet or "." for mainnet;
// This exist in main.rs

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "kqueue.rs"]
pub mod poll;

#[cfg(target_os = "linux")]
#[path = "epoll.rs"]
pub mod poll;

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "tun_darwin.rs"]
pub mod tun;

#[cfg(target_os = "linux")]
#[path = "tun_linux.rs"]
pub mod tun;

use std::collections::HashMap;
use std::io::{self, Write as _};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::x25519;
use allowed_ips::AllowedIps;
use parking_lot::Mutex;
use peer::{AllowedIP, Peer};
use poll::{EventPoll, EventRef, WaitResult};
use rand_core::{OsRng, RngCore};
use socket2::{Domain, Protocol, Type};
use tun::TunSocket;
use dev_lock::{Lock, LockReadGuard};

// Adding Cgrodt object as part of DeviceConfig
use crate::device::api::Cgrodt;
use crate::x25519::StaticSecret;
use crate::x25519::PublicKey;
    
const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const MAX_ITR: usize = 100; // Number of packets to handle per handler call

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    Socket(io::Error),
    #[error("{0}")]
    Bind(String),
    #[error("{0}")]
    FCntl(io::Error),
    #[error("{0}")]
    EventQueue(io::Error),
    #[error("{0}")]
    IOCtl(io::Error),
    #[error("{0}")]
    Connect(String),
    #[error("{0}")]
    SetSockOpt(String),
    #[error("Invalid tunnel name")]
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[error("{0}")]
    GetSockOpt(io::Error),
    #[error("{0}")]
    GetSockName(String),
    #[cfg(target_os = "linux")]
    #[error("{0}")]
    Timer(io::Error),
    #[error("iface read: {0}")]
    IfaceRead(io::Error),
    #[error("{0}")]
    DropPrivileges(String),
    #[error("API socket error: {0}")]
    ApiSocket(io::Error),
}

// What the event loop should do after a handler returns
enum Action {
    Continue, // Continue the loop
    Yield,    // Yield the read lock and acquire it again
    Exit,     // Stop the loop
}

// Event handler function
type Handler = Box<dyn Fn(&mut LockReadGuard<Device>, &mut ThreadData) -> Action + Send + Sync>;

pub struct DeviceHandle {
    device: Arc<Lock<Device>>, // The interface this handle owns
    threads: Vec<JoinHandle<()>>,
}

//#[derive(Debug, Clone, Copy)] 
#[derive(Clone)]
pub struct DeviceConfig {
    pub cgrodt: Cgrodt,
    pub cgrodt_private_key:[u8;32],
    pub cgrodt_public_key:[u8;32],
    pub n_threads: usize,
    pub use_connected_socket: bool,
    #[cfg(target_os = "linux")]
    pub use_multi_queue: bool,
    #[cfg(target_os = "linux")]
    pub uapi_fd: i32,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            cgrodt: Cgrodt::default(),
            cgrodt_private_key:[0;32],
            cgrodt_public_key:[0;32],
            n_threads: 4,
            use_connected_socket: true,
            #[cfg(target_os = "linux")]
            use_multi_queue: true,
            #[cfg(target_os = "linux")]
            uapi_fd: -1,
        }
    }
}

pub struct Device {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    queue: Arc<EventPoll<Handler>>,

    listen_port: u16,
    fwmark: Option<u32>,

    iface: Arc<TunSocket>,
    udp4: Option<socket2::Socket>,
    udp6: Option<socket2::Socket>,

    yield_notice: Option<EventRef>,
    exit_notice: Option<EventRef>,

    peers: HashMap<x25519::PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,
    next_index: IndexLfsr,

    config: DeviceConfig,

    cleanup_paths: Vec<String>,

    mtu: AtomicUsize,

    rate_limiter: Option<Arc<RateLimiter>>,

    #[cfg(target_os = "linux")]
    uapi_fd: i32,
}

struct ThreadData {
    iface: Arc<TunSocket>,
    src_buf: [u8; MAX_UDP_SIZE],
    dst_buf: [u8; MAX_UDP_SIZE],
}

impl DeviceHandle {
    pub fn new(name: &str, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        let n_threads = config.n_threads;
        let mut wg_interface = Device::new(name, config)?;
        let port = 0; // 0 is the correct value if we want to listen on a random port
        wg_interface.open_listen_socket(port)?;

        let interface_lock = Arc::new(Lock::new(wg_interface));

        let mut threads = vec![];

        for i in 0..n_threads {
            threads.push({
                let dev = Arc::clone(&interface_lock);
                thread::spawn(move || DeviceHandle::event_loop(i, &dev))
            });
        }

        Ok(DeviceHandle {
            device: interface_lock,
            threads,
        })
    }

    pub fn wait(&mut self) {
        while let Some(thread) = self.threads.pop() {
            thread.join().unwrap();
        }
    }

    pub fn clean(&mut self) {
        for path in &self.device.read().cleanup_paths {
            // attempt to remove any file we created in the work dir
            let _ = std::fs::remove_file(path);
        }
    }

    fn event_loop(_i: usize, device: &Lock<Device>) {
        #[cfg(target_os = "linux")]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            iface: if _i == 0 || !device.read().config.use_multi_queue {
                // For the first thread use the original iface
                Arc::clone(&device.read().iface)
            } else {
                // For for the rest create a new iface queue
                let iface_local = Arc::new(
                    TunSocket::new(&device.read().iface.name().unwrap())
                        .unwrap()
                        .set_non_blocking()
                        .unwrap(),
                );

                device
                    .read()
                    .register_iface_handler(Arc::clone(&iface_local))
                    .ok();

                iface_local
            },
        };

        #[cfg(not(target_os = "linux"))]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            iface: Arc::clone(&device.read().iface),
        };

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = device.read().uapi_fd;

        loop {
            // The event loop keeps a read lock on the device, because we assume write access is rarely needed
            let mut device_lock = device.read();
            let queue = Arc::clone(&device_lock.queue);

            loop {
                match queue.wait() {
                    WaitResult::Ok(handler) => {
                        let action = (*handler)(&mut device_lock, &mut thread_local);
                        match action {
                            Action::Continue => {}
                            Action::Yield => break,
                            Action::Exit => {
                                device_lock.trigger_exit();
                                return;
                            }
                        }
                    }
                    WaitResult::EoF(handler) => {
                        if uapi_fd >= 0 && uapi_fd == handler.fd() {
                            device_lock.trigger_exit();
                            return;
                        }
                        handler.cancel();
                    }
                    WaitResult::Error(e) => tracing::error!(message = "Poll error", error = ?e),
                }
            }
        }
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.device.read().trigger_exit();
        self.clean();
    }
}

impl Device {
    
    const xnet:&str= BLOCKCHAIN_ENV;
    const smart_contract:&str = SMART_CONTRACT;

    fn next_index(&mut self) -> u32 {
        self.next_index.next()
    }

    fn remove_peer(&mut self, pub_key: &x25519::PublicKey) {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Found a peer to remove, now purge all references to it:
            {
                let p = peer.lock();
                p.shutdown_endpoint(); // close open udp socket and free the closure
                self.peers_by_idx.remove(&p.index());
            }
            self.peers_by_ip
                .remove(&|p: &Arc<Mutex<Peer>>| Arc::ptr_eq(&peer, p));

            tracing::info!("Peer removed");
        }
    }

    // This is the single place where new peer is added, apparently
    #[allow(clippy::too_many_arguments)]
    fn update_peer(
        &mut self,
        pub_key: x25519::PublicKey,
        remove: bool,
        _replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) {
        if remove {
            // Completely remove a peer
            return self.remove_peer(&pub_key);
        }

        // Update an existing peer
        if self.peers.get(&pub_key).is_some() {
            // We already have a peer, we need to merge the existing config into the newly created one
            panic!("Modifying existing peers is not yet supported. Remove and add again instead.");
        }

        let next_index = self.next_index();
        let device_key_pair = self
        .key_pair
        .as_ref()
        .expect("Private key must be set first");
    
        let pub_key_str = pub_key.encode_hex::<String>();
    
        // Convert the device_key_pair to strings
        let private_key_str = device_key_pair.0.encode_hex::<String>();
        let public_key_str = device_key_pair.1.encode_hex::<String>();
    
        // Display the converted values in the trace
        tracing::info!("TEN:pub_key of the peer: {}, private_key: {}, public_key: {} in fn updated_peers",
            pub_key_str,
            private_key_str,
            public_key_str
        );
    
        let tunn = Tunn::new(
            device_key_pair.0.clone(),
            pub_key,
            preshared_key,
            keepalive,
            next_index,
            None,
        )
        .unwrap();
        
        // This is where a new peer is updated, apparently
        let peer = Peer::new(tunn, next_index, endpoint, allowed_ips, preshared_key);

        let peer = Arc::new(Mutex::new(peer));
        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip
                .insert(*addr, *cidr as _, Arc::clone(&peer));
        }

        tracing::info!("Peer added");
    }

    pub fn new(name: &str, config: DeviceConfig) -> Result<Device, Error> {
        let poll = EventPoll::<Handler>::new()?;

        // Create a tunnel device
        let iface = Arc::new(TunSocket::new(name)?.set_non_blocking()?);
        let mtu = iface.mtu()?;

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = config.uapi_fd;

        let mut device = Device {
            queue: Arc::new(poll),
            iface,
            // I think that config contains a Cgrodt
            config,
            exit_notice: Default::default(),
            yield_notice: Default::default(),
            fwmark: Default::default(),
            key_pair: Default::default(),
            listen_port: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            udp4: Default::default(),
            udp6: Default::default(),
            cleanup_paths: Default::default(),
            mtu: AtomicUsize::new(mtu),
            rate_limiter: None,
            #[cfg(target_os = "linux")]
            uapi_fd,
        };

        if uapi_fd >= 0 {
            device.register_api_fd(uapi_fd)?;
        } else {
            device.register_api_handler()?;
        }
        device.register_iface_handler(Arc::clone(&device.iface))?;
        device.register_notifiers()?;
        device.register_timers()?;

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                if name == "utun" {
                    std::fs::write(&name_file, device.iface.name().unwrap().as_bytes()).unwrap();
                    device.cleanup_paths.push(name_file);
                }
            }
        }

        // Normally the tunnel waits to receive the command to set the private key
        // Instead we are proactively setting it
        // Derive the seed from the private key using a KDF (SHA-256 in this example)
        device.set_key(x25519::StaticSecret::from(device.config.cgrodt_private_key));

        // BEGIN running "sudo ip addr add cidrblock dev tun_name"
        let command = "ip addr add ".to_owned()+&device.config.cgrodt.metadata.cidrblock +" dev "+ name;
    
        let output = Command::new("bash")
            .arg("-c")
            .arg(command)
            .output()
            .expect("Failed to execute command");
        
        if output.status.success() {
            let _stdout = String::from_utf8_lossy(&output.stdout);
            tracing::info!("Ip addr add command executed successfully:\n{}",device.config.cgrodt.metadata.cidrblock);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::info!("Ip addr add command failed to execute:\n{}", stderr);
        }
        // END of running postup
        
        // BEGIN adding peers
        if device.config.cgrodt.token_id.contains(&device.config.cgrodt.metadata.authornftcontractid) {
            // If we are a server we set a fictional peer to be ready for handshakes
            tracing::info!("This is a server");

            let randoprivate_key = StaticSecret::random_from_rng(&mut OsRng);
            let randopublic_key: PublicKey = (&randoprivate_key).into();   
            let rando_public_key_hex: [u8; 32] = randopublic_key.as_bytes().clone(); 
            let rando_public_key_str = hex::encode(rando_public_key_hex);        
            device.api_set_internal("set_peer_public_key", &rando_public_key_str);

            // listen port value passed is ignored and always set to 
            // device.config.cgrodt.metadata.listenport
            device.api_set_internal("listen_port", "0");          
        }
        else{
            // BEGIN If we are a client, find the server and check if it is trusted
            // This can be performed with a IsTrusted() call with 
            // cgrodt.metadata.authornftcontractid as a parameter
            // Checking if the Issuer smart contract has published a TXT 
            // entry with the token_id of the server
            // If we are client, add the server as a peer
            // END If we are a client, find the server and check if it is trusted
            tracing::info!("This is a client");    

            let account_idargs = "{\"token_id\": \"".to_owned() 
                + &device.config.cgrodt.metadata.authornftcontractid + "\"}";
                match nearorg_rpc_token(Self::xnet,
                    Self::smart_contract,
                    "nft_token",&account_idargs) {
                    Ok(result) => {
                        let server_cgrodt = result;
                        tracing::info!("Server RODT: {:?}", server_cgrodt);
                        tracing::info!("Server RODT Owner: {:?}", server_cgrodt.owner_id);
                        let serverpeer_xpublic_key = ed2x_public_key_hex(&server_cgrodt.owner_id);
                        tracing::info!("TEN calling api_set_internal set peer public key with {:?}",serverpeer_xpublic_key);
                        device.api_set_internal("set_peer_public_key",
                            &serverpeer_xpublic_key);
                        // api_set_peer_internal_internal_internal(device,x25519::PublicKey::from(servercgrodt_publickey.0),
                        //    "list_port", device.config.metadata.listen_port)
                    }
                    Err(err) => {
                        tracing::error!("There is no server RODT associated with the account: {}", err);
                        std::process::exit(1);        }
                }
        }
        // END adding peers
        Ok(device)
    }


    fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        // Binds the network facing interfaces
        // First close any existing open socket, and remove them from the event loop
        if let Some(s) = self.udp4.take() {
            unsafe {
                // This is safe because the event loop is not running yet
                self.queue.clear_event_by_fd(s.as_raw_fd())
            }
        };

        if let Some(s) = self.udp6.take() {
            unsafe { self.queue.clear_event_by_fd(s.as_raw_fd()) };
        }

        for peer in self.peers.values() {
            peer.lock().shutdown_endpoint();
        }

        // Then open new sockets and bind to the port
        let udp_sock4 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock4.set_reuse_address(true)?;
        udp_sock4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        udp_sock4.set_nonblocking(true)?;

        if port == 0 {
            // Random port was assigned
            port = udp_sock4.local_addr()?.as_socket().unwrap().port();
        }

        let udp_sock6 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock6.set_reuse_address(true)?;
        udp_sock6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        udp_sock6.set_nonblocking(true)?;

        self.register_udp_handler(udp_sock4.try_clone().unwrap())?;
        self.register_udp_handler(udp_sock6.try_clone().unwrap())?;
        self.udp4 = Some(udp_sock4);
        self.udp6 = Some(udp_sock6);

        self.listen_port = port;

        Ok(())
    }

    fn set_key(&mut self, mut private_key: x25519::StaticSecret) {
        let mut bad_peers = vec![];

        // This was the original assignment of the public key
        // let public_key = x25519::PublicKey::from(&private_key);
        // Now we are going to set public_key to the cgrodt value
        let public_key = x25519::PublicKey::from(self.config.cgrodt_public_key);
 
        let tenbytes = public_key.to_bytes();
        let string = encode(&tenbytes);
        tracing::info!(message = "TEN: Curve25519 Public Key (PublicKey) FN set_key Hex: {}", string);
        
        // There is a quirk wheras the private key generated is alternates with 
        // a given input so I am invoking and dumping so the next time I call it 
        // I get the same output as the previous one
//         let _dump = x25519::StaticSecret::from(self.config.cgrodt_private_key);

        // Now we are going to set public_key to the cgrodt value, discarding the passed parameter
        private_key = x25519::StaticSecret::from(self.config.cgrodt_private_key);
        
        let key_pair = Some((private_key.clone(), public_key));
        
        let tenpbytes = private_key.to_bytes();
        let stringp = encode(&tenpbytes);
        tracing::info!(message = "TEN: Curve25519 Private Key (after StaticSecret) FN set_key Hex: {}", stringp);

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.key_pair.as_ref().map(|p| &p.1) {
            return;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            let mut peer_mut = peer.lock();
        
            if peer_mut
                .tunnel
                .set_static_private(
                    private_key.clone(),
                    public_key.clone(),
                    Some(Arc::clone(&rate_limiter)),
                )
                .is_err()
            {
                // Convert private_key and public_key to strings
                let private_key_str = private_key.encode_hex::<String>();
                let public_key_str = public_key.encode_hex::<String>();
        
                // Display the converted values in the trace
                tracing::info!("TEN: private_key: {}, public_key: {} in fn set_key",
                    private_key_str,
                    public_key_str
                );
        
                // In case we encounter an error, we will remove that peer
                // An error will be a result of a bad public key/secret key combination
                bad_peers.push(Arc::clone(peer));
            }
        }

        self.key_pair = key_pair;
        self.rate_limiter = Some(rate_limiter);

        // Remove all the bad peers
        for _ in bad_peers {
            unimplemented!();
        }
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        // First set fwmark on listeners
        if let Some(ref sock) = self.udp4 {
            sock.set_mark(mark)?;
        }

        if let Some(ref sock) = self.udp6 {
            sock.set_mark(mark)?;
        }

        // Then on all currently connected sockets
        for peer in self.peers.values() {
            if let Some(ref sock) = peer.lock().endpoint().conn {
                sock.set_mark(mark)?
            }
        }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }

    fn register_notifiers(&mut self) -> Result<(), Error> {
        let yield_ev = self
            .queue
            // The notification event handler simply returns Action::Yield
            .new_notifier(Box::new(|_, _| Action::Yield))?;
        self.yield_notice = Some(yield_ev);

        let exit_ev = self
            .queue
            // The exit event handler simply returns Action::Exit
            .new_notifier(Box::new(|_, _| Action::Exit))?;
        self.exit_notice = Some(exit_ev);
        Ok(())
    }

    fn register_timers(&self) -> Result<(), Error> {
        self.queue.new_periodic_event(
            // Reset the rate limiter every second give or take
            Box::new(|d, _| {
                if let Some(r) = d.rate_limiter.as_ref() {
                    r.reset_count()
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;

        self.queue.new_periodic_event(
            // Execute the timed function of every peer in the list
            Box::new(|d, t| {
                let peer_map = &d.peers;

                let (udp4, udp6) = match (d.udp4.as_ref(), d.udp6.as_ref()) {
                    (Some(udp4), Some(udp6)) => (udp4, udp6),
                    _ => return Action::Continue,
                };

                // Go over each peer and invoke the timer function
                for peer in peer_map.values() {
                    let mut p = peer.lock();
                    let endpoint_addr = match p.endpoint().addr {
                        Some(addr) => addr,
                        None => continue,
                    };

                    match p.update_timers(&mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            p.shutdown_endpoint(); // close open udp socket
                        }
                        TunnResult::Err(e) => tracing::error!(message = "Timer error", error = ?e),
                        TunnResult::WriteToNetwork(packet) => {
                            match endpoint_addr {
                                SocketAddr::V4(_) => {
                                    udp4.send_to(packet, &endpoint_addr.into()).ok()
                                }
                                SocketAddr::V6(_) => {
                                    udp6.send_to(packet, &endpoint_addr.into()).ok()
                                }
                            };
                        }
                        _ => panic!("Unexpected result from update_timers"),
                    };
                }
                Action::Continue
            }),
            std::time::Duration::from_millis(250),
        )?;
        Ok(())
    }

    pub(crate) fn trigger_yield(&self) {
        self.queue
            .trigger_notification(self.yield_notice.as_ref().unwrap())
    }

    pub(crate) fn trigger_exit(&self) {
        self.queue
            .trigger_notification(self.exit_notice.as_ref().unwrap())
    }

    pub(crate) fn cancel_yield(&self) {
        self.queue
            .stop_notification(self.yield_notice.as_ref().unwrap())
    }

    fn register_udp_handler(&self, udp: socket2::Socket) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // Handler that handles anonymous packets over UDP
                let mut iter = MAX_ITR;
                let (private_key, public_key) = d.key_pair.as_ref().expect("Key not set");

                let rate_limiter = d.rate_limiter.as_ref().unwrap();

                // Loop while we have packets on the anonymous connection

                // Safety: the `recv_from` implementation promises not to write uninitialised
                // bytes to the buffer, so this casting is safe.
                let src_buf =
                    unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
                while let Ok((packet_len, addr)) = udp.recv_from(src_buf) {
                    let packet = &t.src_buf[..packet_len];
                    // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
                    let parsed_packet = match rate_limiter.verify_packet(
                        Some(addr.as_socket().unwrap().ip()),
                        packet,
                        &mut t.dst_buf,
                    ) {
                        Ok(packet) => packet,
                        Err(TunnResult::WriteToNetwork(cookie)) => {
                            let _: Result<_, _> = udp.send_to(cookie, &addr);
                            continue;
                        }
                        Err(_) => continue,
                    };
                    
                    let peer = match &parsed_packet {
                        Packet::HandshakeInit(p) => {
                            parse_handshake_anon(private_key, public_key, p)
                                .ok()
                                .and_then(|hh| {
                                    let private_key_str = private_key.encode_hex::<String>();
                                    let public_key_str = public_key.encode_hex::<String>();
                                    let peer_static_public_str = hh.peer_static_public.encode_hex::<String>();
                    
                                    // Display the converted values in the trace
                                    tracing::info!("TEN: private_key: {}, public_key: {}, hh.peer_static_public: {}, in the fn peer - HandshakeInit",
                                        private_key_str,
                                        public_key_str,
                                        peer_static_public_str
                                    );
                    
                                    d.peers.get(&x25519::PublicKey::from(hh.peer_static_public))
                                })
                        }
                        Packet::HandshakeResponse(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketCookieReply(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                    };
                    
                    let peer = match peer {
                        None => continue,
                        Some(peer) => peer,
                    };

                    let mut p = peer.lock();

                    // We found a peer, use it to decapsulate the message+
                    let mut flush = false; // Are there packets to send from the queue?
                    match p
                        .tunnel
                        .handle_verified_packet(parsed_packet, &mut t.dst_buf[..])
                    {
                        TunnResult::Done => {}
                        TunnResult::Err(_) => continue,
                        TunnResult::WriteToNetwork(packet) => {
                            flush = true;
                            let _: Result<_, _> = udp.send_to(packet, &addr);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                t.iface.write4(packet);
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                t.iface.write6(packet);
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        while let TunnResult::WriteToNetwork(packet) =
                            p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            let _: Result<_, _> = udp.send_to(packet, &addr);
                        }
                    }

                    // This packet was OK, that means we want to create a connected socket for this peer
                    let addr = addr.as_socket().unwrap();
                    let ip_addr = addr.ip();
                    p.set_endpoint(addr);
                    if d.config.use_connected_socket {
                        if let Ok(sock) = p.connect_endpoint(d.listen_port, d.fwmark) {
                            d.register_conn_handler(Arc::clone(peer), sock, ip_addr)
                                .unwrap();
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_conn_handler(
        &self,
        peer: Arc<Mutex<Peer>>,
        udp: socket2::Socket,
        peer_addr: IpAddr,
    ) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |_, t| {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.
                let iface = &t.iface;
                let mut iter = MAX_ITR;

                // Safety: the `recv_from` implementation promises not to write uninitialised
                // bytes to the buffer, so this casting is safe.
                let src_buf =
                    unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };

                while let Ok(read_bytes) = udp.recv(src_buf) {
                    let mut flush = false;
                    let mut p = peer.lock();
                    match p.tunnel.decapsulate(
                        Some(peer_addr),
                        &t.src_buf[..read_bytes],
                        &mut t.dst_buf[..],
                    ) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => eprintln!("Decapsulate error {:?}", e),
                        TunnResult::WriteToNetwork(packet) => {
                            flush = true;
                            let _: Result<_, _> = udp.send(packet);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                iface.write4(packet);
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                iface.write6(packet);
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        while let TunnResult::WriteToNetwork(packet) =
                            p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            let _: Result<_, _> = udp.send(packet);
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_iface_handler(&self, iface: Arc<TunSocket>) -> Result<(), Error> {
        self.queue.new_event(
            iface.as_raw_fd(),
            Box::new(move |d, t| {
                // The iface_handler handles packets received from the WireGuard virtual network
                // interface. The flow is as follows:
                // * Read a packet
                // * Determine peer based on packet destination ip
                // * Encapsulate the packet for the given peer
                // * Send encapsulated packet to the peer's endpoint
                let mtu = d.mtu.load(Ordering::Relaxed);

                let udp4 = d.udp4.as_ref().expect("Not connected");
                let udp6 = d.udp6.as_ref().expect("Not connected");

                let peers = &d.peers_by_ip;
                for _ in 0..MAX_ITR {
                    let src = match iface.read(&mut t.src_buf[..mtu]) {
                        Ok(src) => src,
                        Err(Error::IfaceRead(e)) => {
                            let ek = e.kind();
                            if ek == io::ErrorKind::Interrupted || ek == io::ErrorKind::WouldBlock {
                                break;
                            }
                            eprintln!("Fatal read error on tun interface: {:?}", e);
                            return Action::Exit;
                        }
                        Err(e) => {
                            eprintln!("Unexpected error on tun interface: {:?}", e);
                            return Action::Exit;
                        }
                    };

                    let dst_addr = match Tunn::dst_address(src) {
                        Some(addr) => addr,
                        None => continue,
                    };

                    let mut peer = match peers.find(dst_addr) {
                        Some(peer) => peer.lock(),
                        None => continue,
                    };

                    match peer.tunnel.encapsulate(src, &mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => {
                            tracing::error!(message = "Encapsulate error", error = ?e)
                        }
                        TunnResult::WriteToNetwork(packet) => {
                            let mut endpoint = peer.endpoint_mut();
                            if let Some(conn) = endpoint.conn.as_mut() {
                                // Prefer to send using the connected socket
                                let _: Result<_, _> = conn.write(packet);
                            } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                                let _: Result<_, _> = udp4.send_to(packet, &addr.into());
                            } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                                let _: Result<_, _> = udp6.send_to(packet, &addr.into());
                            } else {
                                tracing::error!("No endpoint");
                            }
                        }
                        _ => panic!("Unexpected result from encapsulate"),
                    };
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    // This version of api_set operates internally, not talking to wg
    pub fn api_set_internal(&mut self, key: &str, val: &str) {
    // Check if both sides have all these properly configured to be able to connect
    // with the Noise procotol that has not been modified yet
    // Usage: wg set <interface>
    // [private-key <file path>]
    // [listen-port <port>]
    // [fwmark <mark>] 
    // [peer <base64 public key> [remove] 
    // [preshared-key <file path>] 
    // [endpoint <ip>:<port>] 
    // [persistent-keepalive <interval seconds>] 
    // [allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...] ]...

        match key {
            // We can self-serve the private key from the input json wallet file
            // Once transformed to Montgomery form
            // I think I can call set_key with device.config.cgrodt_private_key
            "private_key" => match val.parse::<KeyBytes>() {
                Ok(key_bytes) => {
                    // This is the pattern to follow when getting the key as text from a file
                let key_str = serialization::keybytes_to_hex_string(&key_bytes);
                let string = format!("{:02X?}", key_str);
                    // Dumping the private key that is associated with the device in HEX format
                    tracing::info!(message = "TEN:Private_key FN api_set_internal: {}", string);
                    // This call needs to read the key from the cgrodt instead of key_bytes
                    self.set_key(x25519::StaticSecret::from(key_bytes.0))
                    }
                Err(_) => return,
                },
            // We can self-serve the listen_port from the Cgrodt
            "listen_port" => {
                let listenport_str = &self.config.cgrodt.metadata.listenport;
                let listenport = listenport_str.parse::<u16>();
                if let Ok(parsed_listenport) = listenport {
                    if let Err(_) = self.open_listen_socket(parsed_listenport) {
                        return;
                    }
                } else {
                    return;
                }
            },
                #[cfg(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "linux"
                ))]
            // There is no source for this parameter at the moment
            "fwmark" => match val.parse::<u32>() {
                Ok(mark) => match self.set_fwmark(mark) {
                    Ok(()) => {}
                       Err(_) => return,
                    },
                Err(_) => return,
                },
            // I have not seen a case for this call in our version yet
            // but it may come handy when adding not previously seen peers
            "replace_peers" => match val.parse::<bool>() {
                Ok(true) => self.clear_peers(),
                    Ok(false) => {}
                      Err(_) => return,
                    },
            // If we are a client we can find the blockchain
            // public key of the server and transform it to montgomery
            // for to use as X25519 public key
            "set_peer_public_key" => match val.parse::<KeyBytes>() {
                // Indicates a new peer section
                Ok(key_bytes) => {
                    // So here a peer is set
                    // As we don't know our peers (if we are a server)
                    // We need to set a fictional peer that we may never see
                    // api_set_peer needs to be reworked to use the info
                    // from the rodt
                    let key_bytes_encoded = encode(key_bytes.0);
                    tracing::info!("TEN:Peer Public Key FN api_set_internal {:?}", key_bytes_encoded);
                        return self.api_set_peer_internal(
                            x25519::PublicKey::from(key_bytes.0),
                        )
                    }
                    Err(_) => return,
                },
              _ => return,     
            }
    }

    fn api_set_peer_internal(&mut self, pub_key: x25519::PublicKey) {
    // cidrblock is allowed-ips
    // allowedips  is part of postup / postdown commands)

        let remove = false;
        let replace_ips = false;
        // let mut endpoint = None;
        let keepalive = None;
        let public_key_ofthepeer = pub_key;
        let preshared_key = None;
        let mut allowed_ips: Vec<AllowedIP> = vec![];

        let ip: IpAddr = self.config.cgrodt.metadata.endpoint.parse().expect("Invalid IP address");
        let port: u16 = self.config.cgrodt.metadata.listenport.parse().expect("Invalid port");
        let endpoint_listenport = SocketAddr::new(ip,port);      
        println!("Setting Server IP and port {}", endpoint_listenport);        
        // Cidrblock is allowed_ip, it FAILS if the cidr format is not followed
        let allowed_ip_str = &self.config.cgrodt.metadata.cidrblock;
        println!("Setting own assigned IP? {}", allowed_ip_str);
        let allowed_ip: AllowedIP = allowed_ip_str.parse().expect("Invalid AllowedIP");
        println!("Setting allowed IP {:?}", allowed_ip);
//            let ipv6_allowed_ip_str = "2001:db8::1/64"; // Replace with your IPv6 AllowedIP string
//            let ipv6_allowed_ip: AllowedIP = ipv6_allowed_ip_str.parse().expect("Invalid IPv6 AllowedIP");
        // Create or update peer
        allowed_ips.push(allowed_ip);
        self.update_peer(
            public_key_ofthepeer,
            remove,
            replace_ips,
            Some(endpoint_listenport),
            &allowed_ips,
            keepalive,
            preshared_key,
            );                    
        allowed_ips.clear();
    }
}

/// A basic linear-feedback shift register implemented as xorshift, used to
/// distribute peer indexes across the 24-bit address space reserved for peer
/// identification.
/// The purpose is to obscure the total number of peers using the system and to
/// ensure it requires a non-trivial amount of processing power and/or samples
/// to guess other peers' indices. Anything more ambitious than this is wasted
/// with only 24 bits of space.
struct IndexLfsr {
    initial: u32,
    lfsr: u32,
    mask: u32,
}

impl IndexLfsr {
    /// Generate a random 24-bit nonzero integer
    fn random_index() -> u32 {
        const LFSR_MAX: u32 = 0xffffff; // 24-bit seed
        loop {
            let i = OsRng.next_u32() & LFSR_MAX;
            if i > 0 {
                // LFSR seed must be non-zero
                return i;
            }
        }
    }

    /// Generate the next value in the pseudorandom sequence
    fn next(&mut self) -> u32 {
        // 24-bit polynomial for randomness. This is arbitrarily chosen to
        // inject bitflips into the value.
        const LFSR_POLY: u32 = 0xd80000; // 24-bit polynomial
        let value = self.lfsr - 1; // lfsr will never have value of 0
        self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1u32)) & LFSR_POLY);
        assert!(self.lfsr != self.initial, "Too many peers created");
        value ^ self.mask
    }
}

impl Default for IndexLfsr {
    fn default() -> Self {
        let seed = Self::random_index();
        IndexLfsr {
            initial: seed,
            lfsr: seed,
            mask: Self::random_index(),
        }
    }
}

// This function takes a Ed25519 public key in Hex of 32 bytes and creates a matching X25519 key
// as a <KeyBytes> of 32 bytes
pub fn ed2x_public_key_hex(key: &str) -> String {
    // Parse the input key string as a hex-encoded Ed25519 public key
    let ed25519_pub_bytes = hex::decode(key).expect("Invalid hexadecimal string");
    tracing::info!("Server Public Ed25519 Key in Bytes: {:?}", ed25519_pub_bytes);

    // Convert the Ed25519 public key bytes to Montgomery form
    let ed25519_pub_array: [u8; 32] = ed25519_pub_bytes.as_slice().try_into().expect("Invalid length");
    let x25519_pub_key = curve25519_dalek::edwards::CompressedEdwardsY(ed25519_pub_array)
    .decompress()
    .expect("An Ed25519 public key is a valid point by construction.")
    .to_montgomery()
    .0;
            
    // Convert the Montgomery public key to a hex-encoded string
    let x25519_pub_key_hex = hex::encode(x25519_pub_key);
            
    // Return the hex-encoded public key as a String
    x25519_pub_key_hex
}
            