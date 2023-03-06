ip netns add new
ip link add dev outside type veth peer name outsidebr
ip link add dev inside type veth peer name insidebr
ip link add brtest type bridge
ip addr add 172.172.1.1/24 dev brtest
ip link set outsidebr master brtest
ip link set insidebr master brtest
ip link set brtest up
ip link set inside netns new
ip link set outsidebr up
ip link set insidebr up
ip addr add 172.172.1.2/24 dev outside
ip link set outside up
ip netns exec new ip link set lo up
ip netns exec new ip link set inside up
