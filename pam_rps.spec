Name:		pam_rps
Version:	0.2
Release:	1%{?dist}
Summary:	A challenge-response PAM authentication module

Group:		System Environment/Base
License:	MIT
Source0:	pam_rps-%{version}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	pam-devel

%description
The pam_rps module can be used to exercise the PAM conversation support in
applications and for demonstrations.

%prep
%setup -q

%build
%configure --libdir=/%{_lib}
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/%{name}
./libtool --mode=install install -m755 src/%{name} $RPM_BUILD_ROOT/%{_libdir}/%{name}/

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc README LICENSE
/%{_lib}/security/*
%{_mandir}/*/*
%{_libdir}/%{name}

%changelog
* Thu Apr 29 2010 Nalin Dahyabhai <nalin@redhat.com> - 0.2-1
- initial package
