#!/bin/bash
#set -e: This option makes the script exit immediately if any command returns a non-zero exit status, indicating an error.
#set -x: This option makes the script print each command to the standard error (stderr) before it is executed. It's useful for debugging.
set -ex

#This line checks whether the script is running as the root user (UID 0).
#If its not running as root, it attempts to re-execute the script with sudo.
# The -E option preserves the user's environment variables while running as root.
#readlink -f $0 gets the absolute path of the script, and $@ passes any command-line arguments to the re-executed script.
[[ $UID != 0 ]] && exec sudo -E "$(readlink -f "$0")" "$@"

up() {
#It kills any running instances of wpa_supplicant and dhcpcd (if any).
    killall wpa_supplicant dhcpcd || true
#It creates a network namespace called cg-physical-namespace.
    ip netns add cg-physical-namespace

#It moves the cg-physical-namespace network interfaces (eth0 and wlan0) to the cg-physical-namespace namespace.
    ip link set eth0 down
    ip link set wlan0 down
    ip link set eth0 netns cg-physical-namespace
    iw phy phy0 set netns name cg-physical-namespace

#It configures network interfaces within the cg-physical-namespace namespace using dhcpcd and wpa_supplicant.
    ip netns exec cg-physical-namespace dhcpcd -b eth0
    ip netns exec cg-physical-namespace dhcpcd -b wlan0
    ip netns exec cg-physical-namespace wpa_supplicant -B -c/etc/wpa_supplicant/wpa_supplicant-wlan0.conf -iwlan0

#It gives the tun a name and assigns an ip address and configure it
#This should also add the tun interface to the namespace
    ip netns exec cg-physical-namespace cableguard-cli filewiththenearprotocolaccount.json

#It adds a WireGuard interface (wgvpn0) to the cg-physical-namespace namespace.
#    ip -n cg-physical-namespace link add wgvpn0 type wireguard
#It assigns an IP address (192.168.4.33/32) to the wgvpn0 interface.
#    ip addr add 192.168.4.33/32 dev wgvpn0
#It configures WireGuard using the configuration file /etc/wireguard/wgvpn0.conf.
#    wg setconf wgvpn0 /etc/wireguard/wgvpn0.conf
    
#obtain the interfacename of the newly created tunnel
    sudo wg show grep etc

#It moves the cg-physical-namespace network cableguard interface to the init  namespace
    ip -n cg-physical-namespace link set utunCGINTERFACENAME netns 1

#It brings up the wgvpn0 interface and sets a default route through it.
    ip link set utunCGINTERFACENAME up
    ip route add default dev utunCGINTERFACENAME
}
#It kills any running instances of wpa_supplicant and dhcpcd (if any).
#It brings down the cg-physical-namespace network interfaces (eth0 and wlan0), removes the wgvpn0 interface, and deletes the cg-physical-namespace network namespace.
#It brings back the network interfaces to the default network namespace and configures them using dhcpcd and wpa_supplicant.
down() {
    killall wpa_supplicant dhcpcd || true
    ip -n cg-physical-namespace link set eth0 down
    ip -n cg-physical-namespace link set wlan0 down
    ip -n cg-physical-namespace link set eth0 netns 1
    ip netns exec cg-physical-namespace iw phy phy0 set netns 1
    ip link del wgvpn0
    ip netns del cg-physical-namespace
    dhcpcd -b eth0
    dhcpcd -b wlan0
    wpa_supplicant -B -c/etc/wpa_supplicant/wpa_supplicant-wlan0.conf -iwlan0
}

execi() {
    exec ip netns exec cg-physical-namespace sudo -E -u \#${SUDO_UID:-$(id -u)} -g \#${SUDO_GID:-$(id -g)} -- "$@"
}

command="$1"
shift

case "$command" in
    up) up "$@" ;;
    down) down "$@" ;;
    exec) execi "$@" ;;
    *) echo "Usage: $0 up|down|exec" >&2; exit 1 ;;
esac
