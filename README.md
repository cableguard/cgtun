![cableguard logo banner](./banner.png)

# CableGuard TUN

**CableGuard TUN** is an implementation of the [WireGuard<sup>®</sup>](https://www.wireguard.com/) protocol with Rich Online Digital Tokens (RODiT). RODiT are an implementation of non-fungible tokens that contain all the configuration, identity, and subscription information for Cableguard TUN endpoints. Cableguard TUN is based on Cloudflare's Borintung, a Rust implememtation of Wireguard.
This project is part of a large ecosystem (Cableguard FORGE, Cableguard TOOL, Cableguard WALLET, Cableguard FIND and Cableguard AUTH), and consists of three parts:

* The executable `cableguard-cli`, a [userspace WireGuard](https://www.wireguard.com/xplatform/) implementation for Linux and macOS.
* The library `cableguard` that implements the underlying WireGuard protocol, without the network or tunnel stacks that need to be that need to be implemented in a platform idiomatic way.
* The rodtwallet.sh scripts (temporary implementation of Cableguard WALLET) that works with the NEAR CLI interface. It provides barebones command line crytographic commands for the management of RODiT and NEAR implicit accounts.

## License
This project is released under the [GPLv2](COPYING).
More information may be found at [WireGuard.com](https://www.wireguard.com/).**

### Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the 3-Clause BSD License, shall be licensed as above, without any additional terms or conditions.

If you want to contribute to this project, please contact <vpn@cableguard.org>.

## How to Install from Source
- sudo apt install pkg-config
- git clone https://github.com/alanesmizi/cableguardvpn.git
- cargo build --bin cableguard-cli --release
By default the executable is placed in the `./target/release` folder. You can copy it to a desired location manually, or install it using `cargo install --bin cableguard --path .`.

##Note
- master branch operates in mainnet and has even version numbers.
- testnet branch operates in testnet and has odd version numbers

You may want to add to .bashrc these lines:
- export RODITCONTRACTID="name of the NEAR PROTOCOL smartcontract"
- export BLOCKCHAIN_ENV=testnet (or mainnet)

## How to Install from .deb package
wget https://cableguard.fra1.digitaloceanspaces.com/cableguard-cli_0.90.55_amd64.deb
sudo apt install ./cableguard-cli_0.90.55_amd64.deb

## How to Use
To start a tunnel use:
`cableguard-cli [-f/--foreground] <filewithaccount.json>`

Where <filewithaccount.json> is a NEAR implicit account created with wg genaccount, or with cgroditwallet.sh genaccount

To connect the default VPN server listed in the RODiT use:
`cgcvpn.sh <filewithaccount.json>`

To start a VPN server that has a working eth0 interface use:
`cgsvpn-eth0.sh <filewithaccount.json>`

`cableguard` will drop privileges when started. When privileges are dropped it is not possible to set `fwmark`. If `fwmark` is required, such as when using `wg-quick`, run with `--disable-drop-privileges` or set the environment variable `WG_SUDO=1`.
You will need to give the executable the `CAP_NET_ADMIN` capability using: `sudo setcap cap_net_admin+epi cableguard`.

## Supported platforms
- It has only been tested in AMD/Intel
- `x86-64` architecture is supported.

# Cableguard Ecosystem
- Cableguard RODIVPN: RODiT and VPN manager
- Cableguard TOOLS: local VPN tunnel configuration
- Cableguard TUN: VPN tunnels
- Cableguard FORGE: RODiT minter

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. Cableguard is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>
