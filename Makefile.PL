use 5.008008;
use strict;
use warnings;
use ExtUtils::MakeMaker;
use Getopt::Long;
use File::Spec;

my $iprotodir = '/home/a.mashanov/octopus/client/libiproto'; # FIXME
my $iprotosharddir = '../shard';
my $graphite;
my $my;

GetOptions(
    'iprotodir=s'      => \$iprotodir,
    'iprotosharddir=s' => \$iprotosharddir,
    'with-graphite!'   => \$graphite,
    'my!'              => \$my,
);
die "--iprotodir is required" unless $iprotodir;
$iprotosharddir = File::Spec->rel2abs($iprotosharddir);

my $IPROTOSHARD_BUILDDIR = 'build-iprotoshard';

my $cmakeopts = join ' ',
    $graphite ? '-D WITH_GRAPHITE:BOOL=TRUE' : (),
    $my ? '-D MY_MAIL_RU:BOOL=TRUE' : ();

my $xsdefine = join ' ',
    $graphite ? '-DWITH_GRAPHITE' : ();

system("mkdir -p $IPROTOSHARD_BUILDDIR && cd $IPROTOSHARD_BUILDDIR && cmake $cmakeopts $iprotosharddir")
    and die "Failed to 'cmake iprotoshard'\n";

WriteMakefile(
    NAME              => 'MR::IProto::XS',
    VERSION_FROM      => 'lib/MR/IProto/XS.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/MR/IProto/XS.pm', # retrieve abstract from module
       AUTHOR         => 'a.mashanov <a.mashanov@corp.mail.ru>') : ()),
    LIBS              => '', # e.g., '-lm'
    DEFINE            => $xsdefine, # e.g., '-DHAVE_SOMETHING'
    INC               => "-I$iprotosharddir -I$iprotodir",
	# Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
    CCFLAGS           => '-std=gnu99 -Wall -Werror',
    OPTIMIZE          => '-g',
    DIR               => [$IPROTOSHARD_BUILDDIR],
    LDFROM            => "\$(OBJECT) $IPROTOSHARD_BUILDDIR/libiprotoshard.a $iprotodir/libiproto.a",
    depend            => {
        'XS.c' => "$IPROTOSHARD_BUILDDIR/libiprotoshard.a $iprotodir/libiproto.a",
        "$IPROTOSHARD_BUILDDIR/libiprotoshard.a" => 'subdirs',
    },
    clean             => { FILES => $IPROTOSHARD_BUILDDIR },
);
