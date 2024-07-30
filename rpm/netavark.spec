# Building from fedora dependencies not possible
# Latest upstream rtnetlink frequently required
# sha2, zbus, zvariant are currently out of date

%global with_debug 1

%if 0%{?with_debug}
%global _find_debuginfo_dwz_opts %{nil}
%global _dwz_low_mem_die_limit 0
%else
%global debug_package %{nil}
%endif

# Minimum X.Y dep for aardvark-dns
%define major_minor %((v=%{version}; echo ${v%.*}))

# Set default firewall to nftables on CentOS Stream 10+, RHEL 10+, Fedora 41+
# and default to iptables on all other environments
# The `rhel` macro is defined on CentOS Stream, RHEL as well as Fedora ELN.
%if (%{defined rhel} && 0%{?rhel} >= 10) || (%{defined fedora} && 0%{?fedora} >= 41)
%define default_fw nftables
%else
%define default_fw iptables
%endif

Name: netavark
# Set a different Epoch for copr builds
%if %{defined copr_username}
Epoch: 102
%else
Epoch: 2
%endif
Version: 0
Release: %autorelease
# The `AND` needs to be uppercase in the License for SPDX compatibility
License: Apache-2.0 AND BSD-3-Clause AND MIT
%if %{defined golang_arches_future}
ExclusiveArch: %{golang_arches_future}
%else
ExclusiveArch: aarch64 ppc64le s390x x86_64
%endif
Summary: OCI network stack
URL: https://github.com/containers/%{name}
# Tarballs fetched from upstream's release page
Source0: %{url}/archive/v%{version}.tar.gz
Source1: %{url}/releases/download/v%{version}/%{name}-v%{version}-vendor.tar.gz
BuildRequires: cargo
BuildRequires: %{_bindir}/go-md2man
# aardvark-dns and %%{name} are usually released in sync
Requires: aardvark-dns >=  %{epoch}:%{major_minor}
Provides: container-network-stack = 2
%if "%{default_fw}" == "nftables"
Requires: nftables
%else
Requires: iptables
%endif
BuildRequires: make
BuildRequires: protobuf-c
BuildRequires: protobuf-compiler
%if %{defined rhel}
# rust-toolset requires the `local` repo enabled on non-koji ELN build environments
BuildRequires: rust-toolset
%else
BuildRequires: rust-packaging
BuildRequires: rust-srpm-macros
%endif
BuildRequires: git-core
BuildRequires: systemd
BuildRequires: systemd-devel

%description
%{summary}

Netavark is a rust based network stack for containers. It is being
designed to work with Podman but is also applicable for other OCI
container management applications.

Netavark is a tool for configuring networking for Linux containers.
Its features include:
* Configuration of container networks via JSON configuration file
* Creation and management of required network interfaces,
    including MACVLAN networks
* All required firewall configuration to perform NAT and port
    forwarding as required for containers
* Support for iptables and firewalld at present, with support
    for nftables planned in a future release
* Support for rootless containers
* Support for IPv4 and IPv6
* Support for container DNS resolution via aardvark-dns.

%prep
%autosetup -Sgit %{name}-%{version}
# Following steps are only required on environments like koji which have no
# network access and thus depend on the vendored tarball. Copr pulls
# dependencies directly from the network.
%if !%{defined copr_username}
tar fx %{SOURCE1}
%if 0%{?fedora} || 0%{?rhel} >= 10
%cargo_prep -v vendor
%else
%cargo_prep -V 1
%endif
%endif

%build
NETAVARK_DEFAULT_FW=%{default_fw} %{__make} CARGO="%{__cargo}" build
%if (0%{?fedora} || 0%{?rhel} >= 10) && !%{defined copr_username}
%cargo_license_summary
%{cargo_license} > LICENSE.dependencies
%cargo_vendor_manifest
%endif

cd docs
%{__make}

%install
%{__make} DESTDIR=%{buildroot} PREFIX=%{_prefix} install

%preun
%systemd_preun %{name}-dhcp-proxy.service
%systemd_preun %{name}-firewalld-reload.service

%postun
%systemd_postun %{name}-dhcp-proxy.service
%systemd_postun %{name}-firewalld-reload.service

%files
%license LICENSE
%if (0%{?fedora} || 0%{?rhel} >= 10) && !%{defined copr_username}
%license LICENSE.dependencies
%license cargo-vendor.txt
%endif
%dir %{_libexecdir}/podman
%{_libexecdir}/podman/%{name}*
%{_mandir}/man1/%{name}.1*
%{_unitdir}/%{name}-dhcp-proxy.service
%{_unitdir}/%{name}-dhcp-proxy.socket
%{_unitdir}/%{name}-firewalld-reload.service

%changelog
%if %{defined autochangelog}
%autochangelog
%else
# NOTE: This changelog will be visible on CentOS 8 Stream builds
# Other envs are capable of handling autochangelog
* Fri Jun 16 2023 RH Container Bot <rhcontainerbot@fedoraproject.org>
- Placeholder changelog for envs that are not autochangelog-ready
- Contact upstream if you need to report an issue with the build.
%endif
