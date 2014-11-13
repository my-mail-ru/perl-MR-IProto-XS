use 5.008008;
use strict;
use warnings;
use ExtUtils::MakeMaker;
use EV::MakeMaker 'ev_args';
use Getopt::Long;
use File::Spec;

my $graphite;

GetOptions(
    'graphite!' => \$graphite,
);

my $define = join ' ',
    $graphite ? '-DWITH_GRAPHITE' : ();

WriteMakefile(ev_args(
    NAME              => 'MR::IProto::XS',
    VERSION_FROM      => 'lib/MR/IProto/XS.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/MR/IProto/XS.pm', # retrieve abstract from module
       AUTHOR         => 'a.mashanov <a.mashanov@corp.mail.ru>') : ()),
    LIBS              => '-liprotocluster',
    DEFINE            => $define, # e.g., '-DHAVE_SOMETHING'
    INC               => "",
	# Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
    CCFLAGS           => '-std=gnu99 -Wall -Werror',
    OPTIMIZE          => '-ggdb3',
));
