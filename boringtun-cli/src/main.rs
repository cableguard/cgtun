// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use boringtun::device::drop_privileges::drop_privileges;
use boringtun::device::{DeviceConfig, DeviceHandle};
use clap::{Arg, Command};
use daemonize::Daemonize;
use std::os::unix::net::UnixDatagram;
use std::process::exit;
use tracing::Level;
use std::fs::{File, OpenOptions};
// use std::io::prelude::*;
use std::io::{self, ErrorKind};
use std::io::Read;
use serde_json::Value;
use boringtun::device::api::nearorg_rpc_call;
use base58::{FromBase58};
use base64::{encode};
use ed25519_dalek::{Keypair, PublicKey};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use hex::encode as hex_encode;

mod constants {
    // Define the global constant as a static item
    pub static SMART_CONTRACT: &str = "dev-1685354692039-21267193472211";
}

// The following function changes as tun name is not an input anymore
fn check_tun_name(_v: String) -> Result<(), String> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if boringtun::device::tun::parse_utun_name(&_v).is_ok() {
            Ok(())
        } else {
            Err("Tunnel name must have the format 'utun[0-9]+', use 'utun' for automatic assignment".to_owned())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

fn main() {
    let matches = Command::new("cableguard")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Vicente Aceituno Canal <vicente@cableguard.org> and Vlad Krasnov <vlad@cloudflare.com>")
        .args(&[
            // We replace the input of an interface name with the file that has the private key
            // of the blockchain account, the interface name will be derived from the token_id
            Arg::new("FILE_WITH_ACCOUNT")
                .required(true)
                .takes_value(true)
            // The following validator is muted as the entry here is not an INTERFACE_NAME any more
            //  .validator(|tunname| check_tun_name(tunname.to_string()))
                .help("The full filename of the file with the blockchain account"),
            Arg::new("foreground")
                .long("foreground")
                .short('f')
                .help("Run and log in the foreground"),
            Arg::new("threads")
                .takes_value(true)
                .long("threads")
                .short('t')
                .env("WG_THREADS")
                .help("Number of OS threads to use")
                .default_value("4"),
            Arg::new("verbosity")
                .takes_value(true)
                .long("verbosity")
                .short('v')
                .env("WG_LOG_LEVEL")
                .possible_values(["error", "info", "debug", "trace"])
                .help("Log verbosity")
                .default_value("error"),
            Arg::new("uapi-fd")
                .long("uapi-fd")
                .env("WG_UAPI_FD")
                .help("File descriptor for the user API")
                .default_value("-1"),
            Arg::new("tun-fd")
                .long("tun-fd")
                .env("WG_TUN_FD")
                .help("File descriptor for an already-existing TUN device")
                .default_value("-1"),
            Arg::new("log")
                .takes_value(true)
                .long("log")
                .short('l')
                .env("WG_LOG_FILE")
                .help("Log file")
                .default_value("/tmp/cableguard.out"),
            Arg::new("disable-drop-privileges")
                .long("disable-drop-privileges")
                .env("WG_SUDO")
                .help("Do not drop sudo privileges"),
            Arg::new("disable-connected-udp")
                .long("disable-connected-udp")
                .help("Disable connected UDP sockets to each peer"),
            #[cfg(target_os = "linux")]
            Arg::new("disable-multi-queue")
                .long("disable-multi-queue")
                .help("Disable using multiple queues for the tunnel interface"),
        ])
        .get_matches();

    let background = !matches.is_present("foreground");
    #[cfg(target_os = "linux")]
    let uapi_fd: i32 = matches.value_of_t("uapi-fd").unwrap_or_else(|e| e.exit());
    let tun_fd: isize = matches.value_of_t("tun-fd").unwrap_or_else(|e| e.exit());

    // Here is where we need to extract the public key from the file with the account
    // and use to to perform a RPC call and obtain the token_id
    let file_name = matches.value_of("FILE_WITH_ACCOUNT").unwrap();

    let file_path = file_name;
    let mut file = File::open(file_path).expect("Failed to open the file");

    let mut file_contents = String::new();
    file.read_to_string(&mut file_contents).expect("Failed to read the file");

    let json: Value = serde_json::from_str(&file_contents).expect("Failed to parse JSON");

    // Extract the value of the "account_id" field, include it in a json string and encode it as Base64
    let account_id = json["account_id"].as_str().expect("Invalid account_id value");
    let account_idargs = "{\"account_id\":\"" .to_owned() + account_id + "\",\"from_index\":0,\"limit\":1}";

    println!("Json args encoded: {}", account_id);

    // Extract the value of the "private_key" field  from the account file
    let private_key = json["private_key"].as_str().expect("Invalid private_key value");   

    // Set the account where is the ROTD smart contract
    let smart_contract = constants::SMART_CONTRACT;

    // NEXT: We need to retrieve the value of the token id from this call
    match nearorg_rpc_call(smart_contract,smart_contract,"nft_tokens_for_owner",&account_idargs){
        Ok(cgrotd) => {
        }
        Err(err) => {
            // Handle the error
            println!("Error: {}", err);
        }
    }

    // Convert the Ed25519 private key into a X25519 private key
    // Replace `private_key_base58` with your actual private key in Base58
    let private_key_base58 = private_key;

    // Decode the private key from Base58
    let private_key_bytes = private_key_base58.from_base58().unwrap();

    // Convert the private key bytes to a hex string for display purposes
    let private_key_hex = hex_encode(&private_key_bytes);

    // Generate the Ed25519 key pair from the private key
    let keypair = Keypair::from_bytes(&private_key_bytes).unwrap();
    let public_key_bytes: [u8; 32] = keypair.public.to_bytes();

    // Convert the Ed25519 public key to Curve25519 public key
    let mut csprng = OsRng;
    let scalar = Scalar::from(keypair.to_bytes());
    let curve25519_private_key = scalar * RistrettoPoint::basepoint();
    let curve25519_public_key = curve25519_private_key.compress();

    // Convert the Curve25519 public key to Base64
    let curve25519_public_key_base64 = encode(curve25519_public_key.as_bytes());

    println!("Private key (Base58): {}", private_key_base58);
    println!("Private key (Hex): {}", private_key_hex);
    println!("Curve25519 public key (Base64): {}", curve25519_public_key_base64);

    // In the following line INTERFACE_NAME is derived from the token_id ULID, with a max
    // 15 characters, by default utun+last 11 of ULID, this is compatible with: fn check_tun_name

    let mut tun_name = file_name;
    // The following line is the original naming of a tun interface from a command line input in boringtun
    //    let mut tun_name = matches.value_of("INTERFACE_NAME").unwrap();
    if tun_fd >= 0 {
        tun_name = matches.value_of("tun-fd").unwrap();
    }
    let n_threads: usize = matches.value_of_t("threads").unwrap_or_else(|e| e.exit());
    let log_level: Level = matches.value_of_t("verbosity").unwrap_or_else(|e| e.exit());

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);

    let _guard;

    if background {
        let log = matches.value_of("log").unwrap();

        let log_file = if let Ok(metadata) = std::fs::metadata(&log) {
            if metadata.is_file() {
                OpenOptions::new().append(true).open(&log)
            } else {
                Err(io::Error::new(
                    ErrorKind::Other,
                    format!("{} is not a regular file.", log),
                ))
            }
        } else {
            File::create(&log)
        }
        .unwrap_or_else(|err| panic!("Could not open log file {}: {}", log, err));

        let (non_blocking, guard) = tracing_appender::non_blocking(log_file);

        _guard = guard;

        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(non_blocking)
            .with_ansi(false)
            .init();

        let daemonize = Daemonize::new()
            .working_directory("/tmp")
            .exit_action(move || {
                let mut b = [0u8; 1];
                if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                    println!("CableGuard started successfully");
                } else {
                    eprintln!("CableGuard failed to start. Check if the capabilites are set and you are running with enough privileges.");
                    exit(1);
                };
            });

        match daemonize.start() {
            Ok(_) => tracing::info!("CableGuard started successfully"),
            Err(e) => {
                tracing::error!(error = ?e);
                exit(1);
            }
        }
    } else {
        tracing_subscriber::fmt()
            .pretty()
            .with_max_level(log_level)
            .init();
    }

    let config = DeviceConfig {
        n_threads,
        #[cfg(target_os = "linux")]
        uapi_fd,
        use_connected_socket: !matches.is_present("disable-connected-udp"),
        #[cfg(target_os = "linux")]
        use_multi_queue: !matches.is_present("disable-multi-queue"),
    };

    let mut device_handle: DeviceHandle = match DeviceHandle::new(tun_name, config) {
        Ok(d) => d,
        Err(e) => {
            // Notify parent that tunnel initialization failed
            tracing::error!(message = "Failed to initialize tunnel", error=?e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    };

    if !matches.is_present("disable-drop-privileges") {
        if let Err(e) = drop_privileges() {
            tracing::error!(message = "Failed to drop privileges", error = ?e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    }

    // Notify parent that tunnel initialization succeeded
    sock1.send(&[1]).unwrap();
    drop(sock1);

    tracing::info!("CableGuard started successfully");

    device_handle.wait();
}
