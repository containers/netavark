% NETAVARK-FIREWALLD 7 Netavark Firewalld Interactions Man Page
% Matthew Heon
% January 2025

## Name

netavark-firewalld - description of the interaction of Netavark and firewalld

## Description

Netavark can be used on systems with firewalld enabled without issue.
When using the default `nftables` or `iptables` firewall drivers, on systems where firewalld is running, firewalld will automatically be configured to allow connectivity to Podman containers.
All subnets of Podman-managed networks will be automatically added to the `trusted` zone to allow this access.

### Firewalld Driver

There is also a dedicated firewalld driver in Netavark.
This driver uses the firewalld DBus API to natively interact with firewalld.
It can be enabled by setting `firewall_driver` to `firewalld` in `containers.conf`.
The native firewalld driver offers better integration with firewalld, but presently suffers from several limitations.
It does not support isolation (the `--opt isolate=` option to `podman network create`.
Connections to ports forwarded by a container on the same host can only be made through the IPv4 localhost IP (`127.0.0.1`).
Using other IPs on the host will not work, unless the connection comes from a separate host.

### Strict Port Forwarding

Since firewalld version 2.3.0, a new setting, `StrictForwardPorts`, has been added.
The setting is located in `/etc/firewalld/firewalld.conf` and defaults to `no` (disabled).
When disabled, port forwarding with Podman works as normal.
When it is enabled (set to `yes`), port forwarding with root Podman will become nonfunctional.
Attempting to start a container or pod with the `-p` or `-P` options will return errors.
When StrictForwardPorts is enabled, all port forwarding must be done through firewalld using the firewall-cmd tool.
This ensures that containers cannot allow traffic through the firewall without administrator intervention.
Please note that rootless Podman is unaffected by this setting and will function as it always has.

Instead, containers should be started without forwarded ports specified and preferably with static IPs.

To forward a port externally, the following command should be run, substituting the desired host and container port numbers, protocol, and the container's IP.
```
# firewall-cmd --permanent --zone {ZONE} --add-forward-port=port={HOST_PORT_NUMBER}:proto={PROTOCOL}:toport={CONTAINER_PORT_NUMBER}:toaddr={CONTAINER_IP}
```

If you are not sure which zone to use, the `public` zone should always work.

If the container does not have a static IP, it can be found with `podman inspect`:
```
# podman inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {CONTAINER_NAME_OR_ID}
```

Once the container is stopped or removed, the rule must be manually removed with the following command:
```
# firewall-cmd --permanent --zone {ZONE} --remove-forward-port=port={HOST_PORT_NUMBER}:proto={PROTOCOL}:toport={CONTAINER_PORT_NUMBER}:toaddr={CONTAINER_IP}
```

To also allow forwarding via IPv4 localhost (`127.0.0.1`), a firewalld policy must be added, as well as a rich rule for each port requiring localhost forwarding.
Forwarding via IPv6 localhost is not possible due to kernel limitations.

To add the policies required for IPv4 localhost forwarding, the following commands must be run.
This is only necessary once per system.
```
# firewall-cmd --permanent --new-policy localhostForward
# firewall-cmd --permanent --policy localhostForward --add-ingress-zone HOST
# firewall-cmd --permanent --policy localhostForward --add-egress-zone ANY
```

A further rich rule for each container is required:
```
# firewall-cmd --permanent --policy localhostForward --add-rich-rule='rule family=ipv4 destination address=127.0.0.0/8 forward-port port={HOST_PORT_NUMBER} protocol={PROTOCOL} to-port={CONTAINER_PORT_NUMBER} to-addr={CONTAINER_IP}'
```

These rules must be manually removed when the container is stopped or removed with the following command:
```
# firewall-cmd --permanent --policy localhostForward --remove-rich-rule='rule family=ipv4 destination address=127.0.0.0/8 forward-port port={HOST_PORT_NUMBER} protocol={PROTOCOL} to-port={CONTAINER_PORT_NUMBER} to-addr={CONTAINER_IP}'
```

The associated `localhostForward` policy does not need to be removed.

Please also note that, at present, it is only possible to access forwarded ports of a container on the same host via the IPv4 localhost IP (`127.0.0.1`), and only when the rich rule above has been applied.
Accessing via an IP that is not `127.0.0.1` from the same host is presently not possible, but we hope to address this with a future firewalld release.

Please note that the firewalld driver presently bypasses this protection, and will still allow traffic through the firewall when `StrictForwardPorts` is enabled without manual forwarding through `firewall-cmd`.
This may be changed in a future release.

## SEE ALSO

firewalld(1), firewall-cmd(1), firewalld.conf(5), podman(1), containers.conf(5)

## Authors

Matthew Heon <mheon@redhat.com>
