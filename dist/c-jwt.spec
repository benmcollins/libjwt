Summary:            JSON Web Token (C implementation)
Name:               c-jwt
Version:            1.8.0
Release:            0%{?dist}
License:            LGPL v3
Group:              Development/Tools
Source:             %{name}-%{version}.tar.bz2
URL:                https://github.com/benmcollins/libjwt
BuildRequires:      make libtool automake
BuildRequires:      gcc doxygen
BuildRequires:      openssl-devel jansson-devel check-devel
Requires:           openssl jansson check


%description
JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims
 securely between two parties. This package is a C library implementing JWT functionnality.
It supports HS256, HS384 and HS512 digest algorithms.


%package devel
Summary:            JSON Web Token (C implementation) development kit
Group:              Development/Libraries
Requires:           c-jwt

%description devel
Development files for the JWT C library.


%package devel-docs
Summary:            JSON Web Token (C implementation) development kit documentation
Group:              Development/Libraries

%description devel-docs
Development documentation files for the JWT C library.

%prep
%autosetup -q -n c-jwt-%{version}

%build
autoreconf -i
%configure
make all doxygen-doc


%install
make install DESTDIR=%{buildroot}
mkdir -p %{buildroot}%{_datadir}/%{name}
cp -r doxygen-doc/html %{buildroot}%{_datadir}/%{name}

%files
%{_libdir}/*

%files devel
%{_includedir}/*

%files devel-docs
%{_datadir}/*

%changelog
* Thu Oct 12 2017 Julien Courtat <julien.courtat@aqsacom.com> - 1.8.0-0
- Initial packaging
