# dyn-sandbox.spec — 单 RPM：内核模块 + userspace 二进制 + systemd 服务
#
# .ko 与构建机内核强绑定，需在目标内核的机器上构建。
# 构建: rpmbuild -ba dyn-sandbox.spec

%define kernelver %(names=`rpm -qa | grep kernel-devel`;echo ${names#*kernel-devel-})

%global debug_package %{nil}

Name:      dyn-sandbox
Version:   1.0.0
Release:   1%{?dist}
Summary:   dyn-sandbox sandbox isolation: kernel module + DNS proxy
License:   GPL-2.0-only
URL:       https://www.huawei.com
Source0:   %{name}-%{version}.tar.gz

BuildRequires: libyaml-devel
BuildRequires: kernel-devel
BuildRequires: ldns-devel
BuildRequires: systemd-devel
BuildRequires: gcc
BuildRequires: make

Requires: iproute
Requires: nftables
Requires: firewalld

%description
dyn-sandbox provides process sandboxing with network isolation (netns/veth +
nftables whitelist) and file control (Landlock + runtime authorization).
This package contains the kernel module dyn_sandbox.ko, the sandbox CLI
dyn-sandbox, the DNS proxy dyn-sandbox-dns, and the systemd unit that
manages module load/unload.

%prep
%setup -q

%build
make all

%install
make install DESTDIR=%{buildroot}

%post
/sbin/depmod -a
systemctl daemon-reload
systemctl enable dyn-sandbox.service >/dev/null 2>&1 || :
systemctl start dyn-sandbox.service >/dev/null 2>&1 || :

%preun
if [ $1 -eq 0 ]; then
    systemctl stop dyn-sandbox.service >/dev/null 2>&1 || :
    systemctl disable dyn-sandbox.service >/dev/null 2>&1 || :
fi

%postun
/sbin/depmod -a
systemctl daemon-reload
if [ $1 -ge 1 ]; then
    systemctl try-restart dyn-sandbox.service >/dev/null 2>&1 || :
fi

%files
/usr/bin/dyn-sandbox
/usr/bin/dyn-sandbox-dns
/usr/lib/systemd/system/dyn-sandbox.service
/lib/modules/%{kernelver}/extra/dyn_sandbox.ko
%license License/LICENSE
%doc README.md docs/*.md

%changelog
* Fri Jul 31 2026 dyn-sandbox team - 1.0.0-1
- Initial RPM packaging
