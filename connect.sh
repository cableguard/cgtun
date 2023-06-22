sudo wg
cat publickey
echo sudo ./target/release/cableguard-cli wg33
sudo ip addr add 10.0.0.2/24 dev $2
sudo wg set $2 private-key ./privatekey
sudo ip link set $2 up
echo sudo wg set $2 peer m8LczmjtoMolx4yIAtsoJDiA2U6YJZ/v5SkVU9qRJjk= allowed-ips 10.0.0.1/32 endpoint 134.122.78.66:$1
