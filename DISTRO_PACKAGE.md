# Netavark: A container network stack

This document is currently written with Fedora as a reference. As Netavark
gets shipped in other distros, this should become a distro-agnostic
document.

## Fedora Users
Netavark is available as an officlal Fedora package on Fedora 35 and newer versions
and is only meant to be used with Podman v4 and newer releases.

```console
$ sudo dnf install netavark
```

**NOTE:** Fedora 35 users will not be able to install Podman v4 using the default yum
repositories. Please consult the Podman packaging docs for instructions on how
to fetch Podman v4.0 on Fedora 35.


After installation, if you would like to migrate all your containers to use
Netavark, you will need to set `network_backend = "netavark"` under
the `[network]` section in your containers.conf (typically located at:
`/usr/share/containers/containers.conf`

If you would like to test the latest unreleased upstream code, try the
podman-next COPR

```console
$ sudo dnf copr enable rhcontainerbot/podman-next

$ sudo dnf install netavark
```

**CAUTION:** The podman-next COPR provides the latest unreleased sources of Podman,
Netavark and Aardvark-dns as rpms which would override the versions provided by
the official packages.

## Distro Packagers

The vendored sources for netavark will be attached to each netavark release as
a tarball. You can download them with the following:

`https://github.com/containers/netavark/releases/download/v{version}/netavark-v{version}-vendor.tar.gz`

And then create a cargo config file to point it to the vendor dir.
```
tar xvf %{SOURCE}
mkdir -p .cargo
cat >.cargo/config << EOF
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF
```

The Fedora packaging sources for Netavark are available at the [Netavark
dist-git](https://src.fedoraproject.org/rpms/netavark).

The Fedora packaged versions of the rust crates that Netavark depends on are
frequently out of date, for example, rtnetlink, sha2, zbus and zvariant at the
time of initial package creation. So, the Fedora package builds Netavark using
the dependencies vendored upstream, found in the `vendor` subdirectory.

The `netavark` binary is installed to `/usr/libexec/podman/netavark`.

## Dependency on aardvark-dns
The netavark package has a `Recommends` on the `aardvark-dns` package. The
aardvark-dns package will be installed by default with netavark, but netavark
will be functional without it.

## Relationship with the CNI Plugins package

While Netavark is a replacement for CNI Plugins (available as
`containernetworking-plugins` on Fedora), the `netavark` package should be
recommended for new installations but will not conflict with
`containernetworking-plugins`. To avoid that conflict, we have made the following
changes to the Fedora packages.

1. netavark package includes:
```
Provides: container-network-stack = 2
```

2. containernetworking-plugins package includes:
```
Provides: container-network-stack = 1
```

3. containers-common package includes:
```
Requires: container-network-stack
Recommends: netavark
```

## Listing bundled dependencies
If you need to list the bundled dependencies in your packaging sources, you can
run the `cargo tree` command in the upstream source.
For example, Fedora's packaging source uses:

```
$ cargo tree --prefix none | awk '{print "Provides: bundled(crate("$1")) = "$2}' | sort | uniq
```
