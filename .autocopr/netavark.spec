%global debug_package %{nil}

Name: netavark
Epoch: 100
Version: 0
%define build_timestamp %{lua: print(os.date("%Y%m%d"))}
Release: %{build_timestamp}
Summary: OCI network stack
License: ASL 2.0
URL: https://github.com/containers/%{name}
Source: %{url}/archive/main.tar.gz#/%{name}-%{version}-%{release}.tar.gz
BuildRequires: rust-packaging
BuildRequires: go-md2man

ExclusiveArch:  %{rust_arches}
%if %{__cargo_skip_build}
BuildArch:      noarch
%endif

%global _description %{expand:
OCI network stack.}

%description %{_description}

%prep
%autosetup -n %{name}-main
sed -i 's/install: docs build/install:/' Makefile
sed -i 's/\-C install/\-C docs install/' Makefile

%build
%{__make} build
pushd docs
go-md2man -in %{name}.1.md -out %{name}.1 
popd

%install
%{__make} DESTDIR=%{buildroot} PREFIX=%{_prefix} install


%files
%license LICENSE
%dir %{_libexecdir}/podman
%{_libexecdir}/podman/%{name}
%{_mandir}/man1/%{name}.1*

%changelog
%autochangelog
