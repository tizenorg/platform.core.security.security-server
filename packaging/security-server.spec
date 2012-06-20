Name:       security-server
Summary:    Security server
Version: 0.0.1
Release:    37
Group:      TO_BE/FILLED_IN
License:    Apache 2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    security-server.service
Source1001: packaging/security-server.manifest 
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  libattr-devel
Requires(preun):  systemd
Requires(post):   systemd
Requires(postun): systemd

%description
Security server package

%package -n libsecurity-server-client
Summary:    Security server (client)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libsecurity-server-client
Security server package (client)

%package -n libsecurity-server-client-devel
Summary:    Security server (client-devel)
Group:      Development/Libraries
Requires:   libsecurity-server-client = %{version}-%{release}

%description -n libsecurity-server-client-devel
Security server package (client-devel)


%prep
%setup -q

%build
cp %{SOURCE1001} .
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}


make %{?_smp_mflags}

%install
%make_install

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
install -m 0644 %{SOURCE1} %{buildroot}%{_libdir}/systemd/system/security-server.service
ln -s ../security-server.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/security-server.service

# FIXME: remove initscripts once systemd is in
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc3.d
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc5.d
ln -s ../init.d/security-serverd %{buildroot}%{_sysconfdir}/rc.d/rc3.d/S25security-server
ln -s ../init.d/security-serverd %{buildroot}%{_sysconfdir}/rc.d/rc5.d/S25security-server


%preun
if [ $1 == 0 ]; then
    systemctl stop security-server.service
fi

%post
/sbin/ldconfig
systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart security-server.service
fi

%postun
systemctl daemon-reload

%post -n libsecurity-server-client -p /sbin/ldconfig

%postun -n libsecurity-server-client -p /sbin/ldconfig


%files
%manifest security-server.manifest
%attr(0755,root,root) %{_sysconfdir}/rc.d/init.d/security-serverd
%{_sysconfdir}/rc.d/rc3.d/*
%{_sysconfdir}/rc.d/rc5.d/*
%{_bindir}/security-server
%{_bindir}/sec-svr-util
%{_libdir}/systemd/system/multi-user.target.wants/security-server.service
%{_libdir}/systemd/system/security-server.service
%{_datadir}/security-server/mw-list

%files -n libsecurity-server-client
%manifest security-server.manifest
%{_libdir}/libsecurity-server-client.so.*

%files -n libsecurity-server-client-devel
%manifest security-server.manifest
%{_includedir}/security-server/security-server.h
%{_libdir}/libsecurity-server-client.so
%{_libdir}/pkgconfig/security-server.pc
