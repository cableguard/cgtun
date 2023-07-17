// Copyright (c) 2023 cableguard, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::dev_lock::LockReadGuard;
// use parking_lot::RwLockReadGuard;
use super::drop_privileges::get_saved_ids;
use super::{AllowedIP, Device, Error, SocketAddr};
use crate::device::Action;
use crate::serialization::{KeyBytes};
use crate::x25519;
use libc::*;
use std::fs::{create_dir, remove_file};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::Ordering;
use base64::{URL_SAFE_NO_PAD};
use reqwest::blocking::Client;
use serde_json::{Value};
use serde::{Deserialize, Serialize};
use hex::encode as encode_hex;
const SOCK_DIR: &str = "/var/run/wireguard/";

pub mod constants {
    // Define the smart contract account (the Issuer) and the blockchain environment and 'global constants'
    pub const SMART_CONTRACT: &str = "dev-1689342658867-37960738962963";
    pub const BLOCKCHAIN_NETWORK: &str = "testnet."; // IMPORTANT: Values here must be either "testnet." for tesnet or "." for mainnet;
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rodt {
    pub token_id: String,
    pub owner_id: String,
    pub metadata: RodtMetadata,
    pub approved_account_ids: serde_json::Value,
    pub royalty: serde_json::Value,
}

impl Default for Rodt {
    fn default() -> Self {
        Rodt {
            token_id: String::default(),
            owner_id: String::default(),
            metadata: RodtMetadata::default(),
            approved_account_ids: serde_json::Value::Null,
            royalty: serde_json::Value::Null,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RodtMetadata {
    pub title: String,
    pub description: String,
    pub notafter: String,
    pub notbefore: String,
    pub cidrblock: String,
    pub listenport: String,
    pub dns: String,
    pub postup: String,
    pub postdown: String,
    pub allowedips: String,
    pub endpoint: String,
    pub authornftcontractid: String,
    pub authorsignature: String,
    pub kbpersecond: String,
}

impl Default for RodtMetadata {
    fn default() -> Self {
        RodtMetadata {
            title: String::default(),
            description: String::default(),
            notafter: String::default(),
            notbefore: String::default(),
            cidrblock: String::default(),
            listenport: String::default(),
            dns: String::default(),
            postup: String::default(),
            postdown: String::default(),
            allowedips: String::default(),
            endpoint: String::default(),
            authornftcontractid: String::default(),
            authorsignature: String::default(),
            kbpersecond: String::default(),
        }
    }
}

pub fn nearorg_rpc_tokens_for_owner(
    xnet: &str,
    id: &str,
    account_id: &str,
    method_name: &str,
    args: &str,
) -> Result<Rodt, Box<dyn std::error::Error>> {
    let client: Client = Client::new();
    let url: String = "https://rpc.".to_string() + &xnet + "near.org";
    tracing::debug!("Debugging: Blockchain Directory Network: {}",xnet);
    let json_data: String = format!(
        r#"{{
            "jsonrpc": "2.0",
            "id": "{}",
            "method": "query",
            "params": {{
                "request_type": "call_function",
                "finality": "optimistic",
                "account_id": "{}",
                "method_name": "{}",
                "args_base64": "{}"
            }}
        }}"#,
        id, account_id, method_name, base64::encode_config(args,URL_SAFE_NO_PAD)
    );

    let response: reqwest::blocking::Response = client
        .post(&url)
        .body(json_data)
        .header("Content-Type", "application/json")
        .send()?;

    let response_text: String = response.text()?;

    let parsed_json: Value = serde_json::from_str(&response_text).unwrap();

    let result_array = parsed_json["result"]["result"].as_array().ok_or("Result is not an array")?;

    let result_bytes: Vec<u8> = result_array
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();

    let result_slice: &[u8] = &result_bytes;
        
    let result_string = core::str::from_utf8(&result_slice).unwrap();
    
    let result_struct: Vec<Rodt> = match serde_json::from_str(result_string) {
        Ok(value) => value,
        Err(err) => {
            tracing::error!("Error: can't handle RODT struct {:?}",result_string);
            // Handle the error, such as logging or returning an error result
            return Err(Box::new(err));
        }
    };
    
    let mut result_iter = match serde_json::from_str::<Vec<Rodt>>(result_string) {
        Ok(value) => value.into_iter(),
        Err(err) => {
            tracing::error!("Error: can't handle RODT iter  {}",result_string);
            // Handle the error, such as logging or returning an error result
            return Err(Box::new(err));
        }
    };
    
    if let Some(rodt) = result_iter.next() {
        for rodt in result_struct {
            tracing::debug!("token_id: {}", rodt.token_id);
            tracing::debug!("owner_id: {}", rodt.owner_id);
            tracing::debug!("title: {}", rodt.metadata.title);
            tracing::debug!("description: {}", rodt.metadata.description);
            tracing::debug!("notafter: {}", rodt.metadata.notafter);
            tracing::debug!("notbefore: {}", rodt.metadata.notbefore);
            tracing::debug!("notbefore: {}", rodt.metadata.listenport);
            tracing::debug!("cidrblock: {}", rodt.metadata.cidrblock);
            tracing::debug!("dns: {}", rodt.metadata.dns);
            tracing::debug!("postup: {}", rodt.metadata.postup);
            tracing::debug!("postdown: {}", rodt.metadata.postdown);
            tracing::debug!("allowedips: {}", rodt.metadata.allowedips);
            tracing::debug!("endpoint: {}", rodt.metadata.endpoint);
            tracing::debug!("authornftcontractid: {}", rodt.metadata.authornftcontractid);
            tracing::debug!("authorsignature: {}", rodt.metadata.authorsignature);
            tracing::debug!("kbpersecond: {}", rodt.metadata.kbpersecond);
        }
     // Return the first Rodt instance as the result
        return Ok(rodt.clone());
     } else {
     // If no Rodt instance is available, return an error
        return Err("No Rodt instance found".into());
    }
}

pub fn nearorg_rpc_token(
    xnet: &str,
    id: &str,
    method_name: &str,
    args: &str,
) -> Result<Rodt, Box<dyn std::error::Error>> {
    let client: Client = Client::new();
    let url: String = "https://rpc.".to_string() + &xnet + "near.org";
    tracing::debug!("Debugging: Blockchain Directory Network: {}",xnet);
    let json_data: String = format!(
        r#"{{
            "jsonrpc": "2.0",
            "id": "{}",
            "method": "query",
            "params": {{
                "request_type": "call_function",
                "finality": "final",
                "account_id": "{}",
                "method_name": "{}",
                "args_base64": "{}"
            }}
        }}"#,
        id, id, method_name, base64::encode_config(args,URL_SAFE_NO_PAD)
    );
    let response: reqwest::blocking::Response = client
        .post(&url)
        .body(json_data)
        .header("Content-Type", "application/json")
        .send()?;

    let response_text: String = response.text()?;

    tracing::info!("response_text: {}", response_text);

    let parsed_json: Value = serde_json::from_str(&response_text).unwrap();
    
    tracing::info!("parsed_json: {}", parsed_json);

    let result_array = parsed_json["result"]["result"].as_array().ok_or("Result is not an array")?;

    tracing::info!("result_array: {:?}", result_array);

    let result_bytes: Vec<u8> = result_array
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();

    tracing::info!("result_bytes: {:?}", result_bytes);

    let result_slice: &[u8] = &result_bytes;    

    tracing::info!("result_slice: {:?}", result_slice);

    let result_string = String::from_utf8(result_slice.to_vec()).unwrap();
    
    tracing::info!("result_string: {}", result_string);
    
    let rodt: Rodt = serde_json::from_str(&result_string).unwrap();

    Ok(rodt.clone())
}

pub fn nearorg_rpc_state(
    xnet: &str,
    id: &str,
    account_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client: Client = Client::new();
    let url: String = "https://rpc.".to_string() + &xnet + "near.org";
    tracing::debug!("Debugging: Blockchain Directory Network: {}",xnet);
    let json_data: String = format!(
        r#"{{
            "jsonrpc": "2.0",
            "id": "{}",
            "method": "query",
            "params": {{
                "request_type": "view_account",
                "finality": "final",
                "account_id": "{}"
            }}
        }}"#,
        id, account_id
    );

    let response: reqwest::blocking::Response = client
        .post(&url)
        .body(json_data)
        .header("Content-Type", "application/json")
        .send()?;

    let response_text: String = response.text()?;
    let parsed_json: Value = serde_json::from_str(&response_text).unwrap();
    if parsed_json.to_string().contains("does not exist while viewing") {
        println!("{}","The account does not exist in the blockchain, it needs to be funded with at least 0.01 NEAR");
        return Err("The account does not exist in the blockchain".into());
    }
    Ok(())
}

fn produce_sock_dir() {
    let _ = create_dir(SOCK_DIR); // Create the directory if it does not exist

    if let Ok((saved_uid, saved_gid)) = get_saved_ids() {
        unsafe {
            let c_path = std::ffi::CString::new(SOCK_DIR).unwrap();
            // The directory is under the root user, but we want to be able to
            // delete the files there when we exit, so we need to change the owner
            chown(
                c_path.as_bytes_with_nul().as_ptr() as _,
                saved_uid,
                saved_gid,
            );
        }
    }
}

impl Device {
    /// Register the api handler for this Device. The api handler receives stream connections on a Unix socket
    /// with a known path: /var/run/wireguard/{tun_name}.sock.
    pub fn register_api_handler(&mut self) -> Result<(), Error> {
        let path = format!("{}/{}.sock", SOCK_DIR, self.interface.name()?);

        produce_sock_dir();

        let _ = remove_file(&path); // Attempt to remove the socket if already exists

        let api_listener = UnixListener::bind(&path).map_err(Error::ApiSocket)?; // Bind a new socket to the path

        self.cleanup_paths.push(path.clone());

        self.queue.new_event(
            api_listener.as_raw_fd(),
            Box::new(move |thisnetworkdevice, _| {
                // This is the closure that listens on the api unix socket
                let (api_conn, _) = match api_listener.accept() {
                    Ok(conn) => conn,
                    _ => return Action::Continue,
                };

                let mut readerbufferdevice = BufReader::new(&api_conn);
                let mut writerbufferdevice = BufWriter::new(&api_conn);
                let mut cmd = String::new();
                if readerbufferdevice.read_line(&mut cmd).is_ok() {
                    cmd.pop(); // pop the new line character
                    let status = match cmd.as_ref() {
                        // Only two commands are legal according to the protocol, get=1 and set=1.
                        "get=1" => api_get(&mut writerbufferdevice, thisnetworkdevice),
                        "set=1" => api_set(&mut readerbufferdevice, thisnetworkdevice),
                        _ => EIO,
                    };
                    // The protocol requires to return an error code as the response, or zero on success
                    writeln!(writerbufferdevice, "errno={}\n", status).ok();
                }
                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        self.register_monitor(path)?;
        self.register_api_signal_handlers()
    }

    pub fn register_api_fd(&mut self, fd: i32) -> Result<(), Error> {
        let io_file = unsafe { UnixStream::from_raw_fd(fd) };

        self.queue.new_event(
            io_file.as_raw_fd(),
            Box::new(move |thisnetworkdevice, _| {
                // This is the closure that listens on the api file descriptor
                let mut readerbufferdevice = BufReader::new(&io_file);
                let mut writerbufferdevice = BufWriter::new(&io_file);
                let mut cmd = String::new();
                if readerbufferdevice.read_line(&mut cmd).is_ok() {
                    cmd.pop(); // pop the new line character
                    let status = match cmd.as_ref() {
                        "get=1" => api_get(&mut writerbufferdevice, thisnetworkdevice),
                        "set=1" => api_set(&mut readerbufferdevice, thisnetworkdevice),
                        _ => EIO,
                    };
                    // The protocol requires to return an error code as the response, or zero on success
                    writeln!(writerbufferdevice, "errno={}\n", status).ok();
                } else {
                    // The remote side is likely closed; we should trigger an exit.
                    thisnetworkdevice.trigger_exit();
                    return Action::Exit;
                }
                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        Ok(())
    }

    fn register_monitor(&self, path: String) -> Result<(), Error> {
        self.queue.new_periodic_event(
            Box::new(move |thisnetworkdevice, _| {
                // This is not a very nice hack to detect if the control socket was removed
                // and exiting nicely as a result. We check every 3 seconds in a loop if the
                // file was deleted by stating it.
                // The problem is that on linux inotify can be used quite beautifully to detect
                // deletion, and kqueue EVFILT_VNODE can be used for the same purpose, but that
                // will require introducing new events, for no measurable benefit.
                // TODO: Could this be an issue if we restart the service too quickly?
                let path = std::path::Path::new(&path);
                if !path.exists() {
                    thisnetworkdevice.trigger_exit();
                    return Action::Exit;
                }

                // Periodically read the mtu of the interface in case it changes
                if let Ok(mtu) = thisnetworkdevice.interface.mtu() {
                    thisnetworkdevice.mtu.store(mtu, Ordering::Relaxed);
                }

                Action::Continue
            }),
            std::time::Duration::from_millis(1000),
        )?;

        Ok(())
    }

    fn register_api_signal_handlers(&self) -> Result<(), Error> {
        self.queue
            .new_signal_event(SIGINT, Box::new(move |_, _| Action::Exit))?;

        self.queue
            .new_signal_event(SIGTERM, Box::new(move |_, _| Action::Exit))?;

        Ok(())
    }
}

#[allow(unused_must_use)]
fn api_get(writerbufferdevice: &mut BufWriter<&UnixStream>, thisnetworkdevice: &Device) -> i32 {
    // get command requires an empty line, but there is no reason to be religious about it
    if let Some(ref own_static_key_pair) = thisnetworkdevice.key_pair {
        writeln!(writerbufferdevice, "own_public_key={}", encode_hex(own_static_key_pair.1.as_bytes()));
        writeln!(writerbufferdevice, "own_private_key={}", encode_hex(own_static_key_pair.0.as_bytes()));
    }

    if thisnetworkdevice.listen_port != 0 {
        writeln!(writerbufferdevice, "listen_port={}", thisnetworkdevice.listen_port);
    }

    if let Some(fwmark) = thisnetworkdevice.fwmark {
        writeln!(writerbufferdevice, "fwmark={}", fwmark);
    }

    for (own_static_key_pair, peer) in thisnetworkdevice.peers.iter() {
        let peer = peer.lock();
        writeln!(writerbufferdevice, "public_key={}", encode_hex(own_static_key_pair.as_bytes()));

        if let Some(ref peer_preshared_key) = peer.preshared_key() {
            writeln!(writerbufferdevice, "preshared_key={}", encode_hex(peer_preshared_key));
        }

        if let Some(keepalive) = peer.persistent_keepalive() {
            writeln!(writerbufferdevice, "persistent_keepalive_interval={}", keepalive);
        }

        if let Some(ref addr) = peer.endpoint().addr {
            writeln!(writerbufferdevice, "endpoint={}", addr);
        }

        for (ip, cidr) in peer.allowed_ips_listed() {
            writeln!(writerbufferdevice, "allowed_ip={}/{}", ip, cidr);
        }

        if let Some(time) = peer.time_since_last_handshake() {
            writeln!(writerbufferdevice, "last_handshake_time_sec={}", time.as_secs());
            writeln!(writerbufferdevice, "last_handshake_time_nsec={}", time.subsec_nanos());
        }

        let (_, tx_bytes, rx_bytes, ..) = peer.tunnel.stats();

        writeln!(writerbufferdevice, "rx_bytes={}", rx_bytes);
        writeln!(writerbufferdevice, "tx_bytes={}", tx_bytes);
    }
    0
}

fn api_set(readerbufferdevice: &mut BufReader<&UnixStream>, d: &mut LockReadGuard<Device>) -> i32 {
    d.try_writeable(
        |device| device.trigger_yield(),
        |device| {
            device.cancel_yield();

            let mut cmd = String::new();

            while readerbufferdevice.read_line(&mut cmd).is_ok() {
                cmd.pop(); // remove newline if any
                if cmd.is_empty() {
                    return 0; // Done
                }
                {
                    let parsed_cmd: Vec<&str> = cmd.split('=').collect();
                    if parsed_cmd.len() != 2 {
                        return EPROTO;
                    }

                    let (option, value) = (parsed_cmd[0], parsed_cmd[1]);

                    match option {
                        "private_key" => match value.parse::<KeyBytes>() {
                            Ok(own_static_bytes_key_pair) => {
                                // Dumping the private key that is associated with the device in HEX format
                                // let own_static_b64_private_key = hex_to_base64(&own_static_string_private_key);
                                // let own_static_hex_private_key = serialization::keybytes_to_hex_string(&own_static_bytes_key_pair);
                                // let own_static_string_private_key = format!("{:02X?}", own_static_hex_private_key);
                                // tracing::debug!(message = "Debugging: Private_key FN api_set: {}",own_static_string_private_key);
                                device.set_key_pair(x25519::StaticSecret::from(own_static_bytes_key_pair.0))
                            }
                            Err(_) => return EINVAL,
                        },
                        "listen_port" => match value.parse::<u16>() {
                            Ok(port) => match device.open_listen_socket(port) {
                                Ok(()) => {}
                                Err(_) => return EADDRINUSE,
                            },
                            Err(_) => return EINVAL,
                        },
                        #[cfg(any(
                            target_os = "android",
                            target_os = "fuchsia",
                            target_os = "linux"
                        ))]
                        "fwmark" => match value.parse::<u32>() {
                            Ok(mark) => match device.set_fwmark(mark) {
                                Ok(()) => {}
                                Err(_) => return EADDRINUSE,
                            },
                            Err(_) => return EINVAL,
                        },
                        "replace_peers" => match value.parse::<bool>() {
                            Ok(true) => device.clear_peers(),
                            Ok(false) => {}
                            Err(_) => return EINVAL,
                        },
                        "set_peer_public_key" => match value.parse::<KeyBytes>() {
                            Ok(peer_keybytes_key) => {
                                    return api_set_peer(
                                        readerbufferdevice,
                                        device,
                                        x25519::PublicKey::from(peer_keybytes_key.0),
                                    )
                                }
                                Err(_) => return EINVAL,
                            },
                        "public_key" => match value.parse::<KeyBytes>() {
                            Ok(own_static_bytes_key_pair) => {
                                return api_set_peer(
                                    readerbufferdevice,
                                    device,
                                    x25519::PublicKey::from(own_static_bytes_key_pair.0),
                                )
                            }
                            Err(_) => return EINVAL,
                        },
                        _ => return EINVAL,
                    }
                }
                cmd.clear();
            }
            0
        },
    )
    .unwrap_or(EIO)
}

fn api_set_peer(
    readerbufferdevice: &mut BufReader<&UnixStream>,
    thisnetworkdevice: &mut Device,
    peer_publickey_public_key: x25519::PublicKey,
) -> i32 {
    let mut cmd = String::new();

    let mut remove = false;
    let mut replace_ips = false;
    let mut endpoint = None;
    let mut keepalive = None;
    let mut clone_peer_publickey_public_key = peer_publickey_public_key;
    let mut preshared_key = None;
    
    let mut allowed_ips_listed: Vec<AllowedIP> = vec![];
    while readerbufferdevice.read_line(&mut cmd).is_ok() {
        cmd.pop(); // remove newline if any
        if cmd.is_empty() {
            thisnetworkdevice.update_peer(
                clone_peer_publickey_public_key,
                remove,
                replace_ips,
                endpoint,
                allowed_ips_listed.as_slice(),
                keepalive,
                preshared_key,
            );
            allowed_ips_listed.clear(); //clear the vector content after update
            return 0; // Done
        }
        {
            let parsed_cmd: Vec<&str> = cmd.splitn(2, '=').collect();
            if parsed_cmd.len() != 2 {
                return EPROTO;
            }
            let (option, value) = (parsed_cmd[0], parsed_cmd[1]);
            match option {
                "remove" => match value.parse::<bool>() {
                    Ok(true) => remove = true,
                    Ok(false) => remove = false,
                    Err(_) => return EINVAL,
                },
                "preshared_key" => match value.parse::<KeyBytes>() {
                    Ok(own_static_bytes_key_pair) => preshared_key = Some(own_static_bytes_key_pair.0),
                    Err(_) => return EINVAL,
                },
                "endpoint" => match value.parse::<SocketAddr>() {
                    Ok(addr) => endpoint = Some(addr),
                    Err(_) => return EINVAL,
                },
                "persistent_keepalive_interval" => match value.parse::<u16>() {
                    Ok(interval) => keepalive = Some(interval),
                    Err(_) => return EINVAL,
                },
                "replace_allowed_ips" => match value.parse::<bool>() {
                    Ok(true) => replace_ips = true,
                    Ok(false) => replace_ips = false,
                    Err(_) => return EINVAL,
                },
                "allowed_ip" => match value.parse::<AllowedIP>() {
                    Ok(ip) => allowed_ips_listed.push(ip),
                    Err(_) => return EINVAL,
                },
                "public_key" => {
                    // Indicates a new peer section
                    // Commit changes for current peer, and continue to next peer
                    thisnetworkdevice.update_peer(
                        clone_peer_publickey_public_key,
                        remove,
                        replace_ips,
                        endpoint,
                        allowed_ips_listed.as_slice(),
                        keepalive,
                        preshared_key,
                    );
                    allowed_ips_listed.clear(); //clear the vector content after update
                    match value.parse::<KeyBytes>() {
                        Ok(own_static_bytes_key_pair) => clone_peer_publickey_public_key = own_static_bytes_key_pair.0.into(),
                        Err(_) => return EINVAL,
                    }
                }
                "protocol_version" => match value.parse::<u32>() {
                    Ok(1) => {}
                    _ => return EINVAL,
                },
                _ => return EINVAL,
            }
        }
        cmd.clear();
    }
    0
}