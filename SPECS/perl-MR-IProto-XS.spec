%bcond_without graphite

%define __libiprotocluster_version 20160218.1650

Name:           perl-MR-IProto-XS
Version:        %{__version}
Release:        %{__release}%{?dist}

Summary:        high performance iproto perl client
License:        BSD
Group:          MAILRU

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-buildroot
BuildRequires:  perl(ExtUtils::MakeMaker), perl(Test::More)
BuildRequires:  perl(EV), perl(Coro)
BuildRequires:  libiprotocluster-devel >= %{__libiprotocluster_version}
BuildRequires:  libiprotocluster >= %{__libiprotocluster_version}
Requires:       perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
Requires:       prel(EV)
Requires:       libiprotocluster >= %{__libiprotocluster_version}

%description
High performance iproto perl client. Built from revision %{__revision}

%prep
%setup -n iproto/xs
sed -i "s/^our \$VERSION = '[0-9\.]\+';$/our \$VERSION = '%{version}';/" lib/MR/IProto/XS.pm

%build
%__perl Makefile.PL %{?with_graphite:--graphite} INSTALLDIRS=vendor
%__make %{?_smp_mflags}

%install
%__make pure_install PERL_INSTALL_ROOT=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -type f -name .packlist -exec rm -f {} ';'
find $RPM_BUILD_ROOT -depth -type d -exec rmdir {} 2>/dev/null ';'
chmod -R u+w $RPM_BUILD_ROOT/*
mkdir -p $RPM_BUILD_ROOT%{_includedir}
cp iprotoxs.h $RPM_BUILD_ROOT%{_includedir}/

%files
%defattr(-,root,root,-)
%{perl_vendorarch}/*
%{_mandir}/*/*

%package devel
Summary:  iproto XS client library header files
Group:    Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: libiprotocluster-devel >= %{__libiprotocluster_version}

%description devel
iproto XS client library header files

%files devel
%{_includedir}/*

%changelog
* Thu Nov 22 2012 Aleksey Mashanov <a.mashanov@corp.mail.ru>
- initial version
