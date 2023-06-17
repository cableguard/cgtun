// Copyright (c) 2023 Cableguard, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use clap::{Arg, Command};
use daemonize::Daemonize;
use std::os::unix::net::UnixDatagram;
use std::process::exit;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind};
use std::io::Read;
use std::env;
use tracing::Level;
use serde_json::Value;
use cableguard::device::drop_privileges::drop_privileges;
use cableguard::device::{DeviceConfig, DeviceHandle};
use cableguard::device::api::nearorg_rpc_tokens_for_owner;
use cableguard::device::api::nearorg_rpc_state;
use cableguard::device::api::Cgrodt;
use cableguard::device::ed2x_public_key_hex;
use cableguard::device::ed2x_private_key_hex;
// use cableguard::x25519::PublicKey;
// use cableguard::x25519::StaticSecret;
// use curve25519_dalek::scalar::Scalar;
// use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
// use curve25519_dalek::edwards::EdwardsPoint;
// use hex::FromHex;
use hex::{encode};
use crate::constants::SMART_CONTRACT;
use crate::constants::BLOCKCHAIN_ENV;

mod constants {
    // Define the global constant as a static item
    pub static SMART_CONTRACT: &str = "dev-1686226311171-75846299095937";
    pub static BLOCKCHAIN_ENV: &str = "testnet."; // IMPORTANT: Values here must be either "testnet." for tesnet or "." for mainnet;
}

fn main() {
    let matches = Command::new("cableguard")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Vicente Aceituno Canal <vicente@cableguard.org> and Vlad Krasnov <vlad@cloudflare.com> et al")
        .args(&[
            // We input a file path and name that has the private key
            // of the blockchain account, the interface name will be derived from the token_id of the RODT
            Arg::new("FILE_WITH_ACCOUNT")
                .required(true)
                .takes_value(true)
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

    // Extract the public key from the file with the account
    // Perform a RPC call with it and obtain the token_id
    let accountfile_name = matches.value_of("FILE_WITH_ACCOUNT").unwrap();

    let accountfile_path = accountfile_name;
    let mut accountfile = match File::open(&accountfile_path) {
        Ok(accountfile) => accountfile,
        Err(err) => {
            eprintln!("Failed to open the file: {}", err);
            return; // Terminate the program or handle the error accordingly
        }
    };

    let mut accountfile_contents = String::new();
    if let Err(err) = accountfile.read_to_string(&mut accountfile_contents) {
        eprintln!("Failed to read the file: {}", err);
        return; // Terminate the program or handle the error accordingly
    }

    let json: Value = match serde_json::from_str(&accountfile_contents) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("Failed to parse JSON: {}", err);
            // Add any additional error handling logic if needed
            return; // Terminate the program
        }
    };

    // Extract the value of the "account_id" field, include it in a json string
    let account_id = json["account_id"].as_str().expect("Invalid account_id value");

    // Extract the value of the "private_key" field, include it in a json string and encode it as Base58
    let private_key_base58 = json["private_key"].as_str().expect("Invalid private_key value");   
    let private_key_base58 = private_key_base58.trim_start_matches("ed25519:");

    // Set the account where is the rodt smart contract
    let smart_contract = constants::SMART_CONTRACT;

    // Set the environment to testnet or mainnet
    let xnet = BLOCKCHAIN_ENV;

    // Initialize a RODT object
    let cgrodt: Cgrodt;
    
    println!("ROTD Directory is NEAR.ORG: {}", SMART_CONTRACT);
    println!("Owner Account ID: {}", account_id);

    // Show a warning if the account is not primed    
    match nearorg_rpc_state(xnet, smart_contract, account_id) {
        Ok(result) => { println!("Result {:?}",result)
        }
        Err(err) => {
            // Handle the error
            tracing::error!("RPC Return Error: {}", err);
            std::process::exit(1);
        }
    }

    // Retrieve from the blockchain the RODT using the account_id
    let account_idargs = "{\"account_id\":\"".to_owned() + account_id + "\",\"from_index\":0,\"limit\":1}";
    match nearorg_rpc_tokens_for_owner(xnet, smart_contract, smart_contract, "nft_tokens_for_owner", &account_idargs) {
        Ok(result) => {
            cgrodt = result;
        }
        Err(err) => {
            // Handle the error
            tracing::error!("There is no RODT associated with the account: {}", err);
            std::process::exit(1);
        }
    }

    // Create an Interface Name derived from the token_id ULID,
    // with a max length of 15 characters, by default utun+last 11 of ULID for operating systems compatibility, 
    let tun_name = format!("utun{}", &cgrodt.token_id[cgrodt.token_id.len() - 11..]);
    
    // Now we create a Curve5519 key pair from Private Key Ed25519 of 64 bytes in Base58 format
    println!("Ed25519 Private Key Base58 {}",private_key_base58);

    // We decode it to Hex format Private Key Ed25519 of 64 bytes
    let ed25519_private_key_bytes = bs58::decode(private_key_base58)
        .into_vec()
        .expect("Failed to decode the private key from Base58");
    let ed25519_private_key_hex = hex::encode(&ed25519_private_key_bytes);

    // Ensure the decoded Private Key Ed25519 of 64 bytes has the expected length
    assert_eq!(ed25519_private_key_bytes.len(), 64);
    assert_eq!(ed25519_private_key_hex.len(), 128);

    println!("Ed25519 Private Key Hex {}",ed25519_private_key_hex);

    // let curve25519_private_key_ss = ed2x_private_key_hex(&ed25519_private_key_hex);

    // We extract the Secret Key of 32 bytes from the hex Private Key Ed25519 of 64 bytes
    // let mut private_key_array: [u8; 64] = [0u8; 64];
    // let private_key_vec = Vec::<u8>::from_hex(ed25519_private_key_hex.clone()).clone().expect("Invalid hexadecimal string");
    
    // Extract the Secret Key
    // let (left,_right) = private_key_array.split_at_mut(private_key_vec.len());
    // left.copy_from_slice(&private_key_vec);

    // Convert to Scalar type
    // let secret_key: [u8; 64] = private_key_array;
    // let secret_key_scalar = Scalar::from_bytes_mod_order_wide(&secret_key);

    // Generate the Curve25519 private key with direct conversion from the private key
    let server_xprivate_key_ss = ed2x_private_key_hex(ed25519_private_key_bytes.try_into().unwrap());
    let curve25519_private_key_bytes = server_xprivate_key_ss.as_bytes();  
    println!("X25519 Private Key DIRECT FN main Hex{:?}",encode(curve25519_private_key_bytes));

    // Obtain the secret point from the Secret Key of 32 bytes
    // let secret_key_point: EdwardsPoint = &secret_key_scalar * &ED25519_BASEPOINT_POINT;

    // Generate the X25519 Private Key from the Private Key Ed25519
    // let curve25519_private_key_montgomery = secret_key_point.to_montgomery();
    // let curve25519_private_key_bytes = curve25519_private_key_montgomery.to_bytes();

    // Create a StaticSecret from the private key bytes, with a [u8; 32] array as intermediate format
    // let mut curve25519_private_key_array = [0u8; 32];
    // curve25519_private_key_array.copy_from_slice(&curve25519_private_key_bytes[..]);
    // let curve25519_private_key_ss = StaticSecret::from(curve25519_private_key_array);

    // Generate the corresponding PublicKey from the StaticSecret
    // let curve25519_public_key: PublicKey = (&curve25519_private_key_ss).into();

    // Convert the PublicKey to bytes
    // let mut curve25519_public_key_bytes = curve25519_public_key.as_bytes();  

    // Generate the Curve25519 base64 private key for display purposes
    // let curve25519_private_key_display = encode(curve25519_private_key_bytes);
    // println!("X25519 Private Key FN main Hex: {}",curve25519_private_key_display);
    
    // Generate the Curve25519 base64 public key for display purpose
    // let curve25519_public_key_display = encode(curve25519_public_key_bytes);
    // println!("X25519 Public Key VIA PRIVATE FN main Hex: {}",curve25519_public_key_display);

    // Generate the Curve25519 public key with direct conversion from the account id
    let server_xpublic_key_str = ed2x_public_key_hex(&account_id);
    let curve25519_public_key_bytes = server_xpublic_key_str;
    println!("X25519 account ID DIRECT FN main Hex{:?}",account_id);
    println!("X25519 Public Key DIRECT FN main Hex{:?}",encode(server_xpublic_key_str));

    // Number 0: Verify that you can still tunnel with the currently created key pairs
    // Number 1: create ed2xpublickey that creates a X public key in Hex from an Ed public Key
    // Number 2: verify that you get the same X public key when you create it from an Ed public Key or from an Ed private Key 
    // let curve25519_public_key_display  = ed2x_public_key_hex(account_id);
    // println!("X25519 Public key hex fn main {:?}",curve25519_public_key_display);

    let n_threads: usize = matches.value_of_t("threads").unwrap_or_else(|e| e.exit());
    let log_level: Level = matches.value_of_t("verbosity").unwrap_or_else(|e| e.exit());
    
    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);
    
    let _guard;
    
    println!("To display current configuration of the tunnel use \"sudo wg show\"");
    println!("To display available NEAR.ORG accounts use \"showrotd.sh\"");
    println!("To create a NEAR.ORG account use \"wg genaccount\"");

    if background {
        // Running in background mode
        let log = matches.value_of("log").unwrap();
    
        // Check if the log file exists, open it in append mode if it does
        // Otherwise, create a new log file
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
    
        // Create a non-blocking log writer and get a guard to prevent dropping it
        let (non_blocking, guard) = tracing_appender::non_blocking(log_file);
        _guard = guard;
    
        // Initialize the logging system with the configured log level and writer
        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(non_blocking)
            .with_ansi(false)
            .init();
    
        // Create a daemon process and configure it
        let daemonize = Daemonize::new()
            .working_directory("/tmp")
            .exit_action(move || {
                // Perform an action when the daemon process exits
                let mut b = [0u8; 1];
                if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                    println!("CableGuard opened a sock successfully");
                } else {
                    eprintln!("CableGuard failed to start. Check if the capabilities are set and you are running with enough privileges.");
                    exit(1);
                };
            });
    
        // Start the daemon process
        match daemonize.start() {
            Ok(_) => println!("CableGuard daemonized successfully"),
            Err(e) => {
                tracing::error!(error = ?e);
                exit(1);
            }
        }
    } else {
        // Running in foreground mode
        tracing_subscriber::fmt()
            .pretty()
            .with_max_level(log_level)
            .init();
    }
    
    // Configure the device with the provided settings
    let config = DeviceConfig {
        cgrodt,
        cgrodt_private_key:*curve25519_private_key_bytes,
        cgrodt_public_key:curve25519_public_key_bytes,
        n_threads,
        #[cfg(target_os = "linux")]
        uapi_fd,
        use_connected_socket: !matches.is_present("disable-connected-udp"),
        #[cfg(target_os = "linux")]
        use_multi_queue: !matches.is_present("disable-multi-queue"),
    };
    
    // Initialize the device handle with the specified tunnel name and configuration
    let mut device_handle: DeviceHandle = match DeviceHandle::new(&tun_name, config) {
        Ok(d) => d,
        Err(e) => {
            // Notify parent that tunnel initialization failed
            tracing::error!(message = "Failed to initialize tunnel", error=?e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    };
    
    if !matches.is_present("disable-drop-privileges") {
        // Drop privileges if not disabled
        if let Err(e) = drop_privileges() {
            tracing::error!(message = "Failed to drop privileges", error = ?e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    }
    
    // Notify parent that tunnel initialization succeeded
    sock1.send(&[1]).unwrap();
    drop(sock1);
    
    println!("CableGuard will hand over to device handle");
    
    // Wait for the device handle to finish processing
    device_handle.wait();    
}
