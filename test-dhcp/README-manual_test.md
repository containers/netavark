# How to test the proxy and client manually

The following instructions can help you manually test the proxy server and client.  You will need dnsmasq which
is used for DHCP services only.

## Setup network and namespace

The first step is to set up an example virtual network with a bridge.  Then one of the virtual ethernet devices
needs to be put into a netns.  The following should suffice:

```
$ ip netns add new
$ ip link add dev outside type veth peer name outsidebr
$ ip link add dev inside type veth peer name insidebr
$ ip link add brtest type bridge
$ ip addr add 172.172.1.1/24 dev brtest
$ ip link set outsidebr master brtest
$ ip link set insidebr master brtest
$ ip link set brtest up
$ ip link set inside netns new
$ ip link set outsidebr up
$ ip link set insidebr up
$ ip addr add 172.172.1.2/24 dev outside
$ ip link set outside up
$ ip netns exec new ip link set lo up
$ ip netns exec new ip link set inside up
```

Verify that all the interfaces are status of UP using `ip a` and `ip netns exec new ip a`.

## Start DNSMasq

Open a terminal and from the git repository, edit *test/dnsmasqfiles/sample.conf*.  Make sure the interface
matches the interface of the bridge (brtest) in this case.

```
# Set the interface on which dnsmasq operates.
# If not set, all the interfaces is used.
interface=brtest

# To disable dnsmasq's DNS server functionality.
port=0
...
```

```
$ sudo dnsmasq  -d --log-debug --log-queries --conf-dir test/dnsmasqfiles
```

## Start the nv-proxy server

Open another terminal and build the server and client

```
$ make all
```

Then run the server with debug enabled:

```
$ sudo RUST_LOG=debug ./bin/netavark-dhcp-proxy
```

Note: When doing debug of the client or server, it can be very nice to run the server in your IDE.  This allows
you to set breakpoints and see variable values. Here is an example of doing this with CLion.

![CLION setup](IDE.png)

## Run the client

In another terminal, you can then run the client.  You need to generate a config file first.  A script is provided
that will generate a basic config file for you. The script needs the interface name of the bridge, the name of the
netns, and the name of the interface inside the netns respectively.  Simply pipe the output to a file.

```
$ sudo sh ./contrib/script/basic.sh brtest new inside
```

Then run the client with debug enabled:
```
$ sudo RUST_LOG=debug ./bin/client -f <path_to_config> setup|teardown foo
```
