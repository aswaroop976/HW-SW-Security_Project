export IF=enx1a5589a26942

sudo ip addr flush dev $IF
sudo ip addr add 10.0.0.2/24 dev $IF
sudo ip link set $IF up

ssh-keygen -f "/home/arpan/.ssh/known_hosts" -R "10.0.0.1"
