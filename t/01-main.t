use strict;
use warnings;
use Test::More tests => 72;
use Test::LeakTrace;
use IO::Socket;
use Time::HiRes qw/sleep time/;
use POSIX qw/SIGTERM/;
use MR::Pinger::Const;
use IPC::SysV qw/IPC_CREAT/;
use IPC::SharedMem;

BEGIN { use_ok('MR::IProto::XS') };

MR::IProto::XS->set_logmask(MR::IProto::XS::LOG_NOTHING);
ok(MR::IProto::XS::Stat->set_graphite("alei9.mail.ru", 2005, "my.iproto-xs"), "set_graphite") or diag($!);

isa_ok(MR::IProto::XS->new(shards => {}), 'MR::IProto::XS');

my $PORT = $ENV{FIRST_PORT} || 40000;
my $EMPTY_PORT = $ENV{EMPTY_PORT} || 19999;
my @servers;

{
    package Test::Smth;
    use base 'MR::IProto::XS';
}

check_const();
check_new();
check_errors();
check_success();
check_early_retry();
check_retry();
check_soft_retry();
check_timeout();
check_replica();
check_priority();
check_pinger();
check_fork();
check_stat();
check_singleton();
check_leak();

sub fork_test_server {
    my (@cb) = @_;
    my $port = $PORT++;
    my $parent = $$;
    my $pid = fork();
    die "Failed to fork(): $!\n" unless defined $pid;
    if ($pid == 0) {
        my $socket = IO::Socket::INET->new(
            Listen    => 5,
            LocalHost => '127.0.0.1',
            LocalPort => $port,
            Proto     => 'tcp',
            Timeout   => 5,
        ) or do {
            warn "Failed to listen 127.0.0.1:$port: $@";
            kill SIGTERM, $parent;
            exit 1;
        };
        my %childs;
        foreach my $cb (@cb) {
            if (my $accept = $socket->accept()) {
                my $apid = fork();
                if ($apid == 0) {
                    $socket->close();
                    eval { $cb->($accept); 1 } or warn "Died in callback: $@";
                    my $len = $accept->sysread(my $eof, 1);
                    if ($len == -1 ) {
                        warn "Failed to read EOF";
                    }
                    $accept->close();
                    exit;
                } else {
                    $childs{$apid} = 1;
                    $accept->close();
                }
            }
        }
        while (%childs) {
            delete $childs{wait()};
        }
        $socket->close();
        exit;
    }
    push @servers, $pid;
    sleep 0.5;
    return $port;
}

sub close_all_servers {
    kill SIGTERM, @servers;
    @servers = ();
    return;
}

sub check_and_reply {
    my ($socket, $ccode, $cdata, $reply) = @_;
    my $header;
    my $len = $socket->sysread($header, 12);
    die "Failed to read: $!" if $len == -1;
    die "EOF" if $len == 0;
    die "Invalid header length" unless $len == 12;
    my ($code, $length, $sync) = unpack 'LLL', $header;
    die "Invalid code" unless $code == $ccode;
    my $data;
    $len = $socket->sysread($data, $length);
    die "Failed to read: $!" if $len == -1;
    die "Invalid data length: $len != $length" unless $len == $length;
    die "Invalid data" unless $data eq $cdata;
    $len = $socket->syswrite(pack 'LLLa*', $code, length $reply, $sync, $reply);
    die "Failed to write: $!" if $len == -1;
    return;
}

sub echo {
    my ($socket) = @_;
    my $header;
    my $len = $socket->sysread($header, 12);
    die "Failed to read: $!" if $len == -1;
    die "EOF" if $len == 0;
    die "Invalid header length" unless $len == 12;
    my ($code, $length, $sync) = unpack 'LLL', $header;
    my $data;
    $len = $socket->sysread($data, $length);
    die "Failed to read: $!" if $len == -1;
    $len = $socket->syswrite(pack 'LLLa*', $code, length $data, $sync, $data);
    die "Failed to write: $!" if $len == -1;
    return;
}

sub msgs {
    my ($msg, @ids) = @_;
    return [
        map {{
            %$msg,
            request  => { %{$msg->{request}}, data => [ $_ ] },
            response => { %{$msg->{response}} },
        }} @ids
    ];
}

sub check_const {
    is(MR::IProto::XS::ERR_CODE_OK, 0, "ERR_CODE_OK");
    is(MR::IProto::XS::ERR_CODE_CONNECT_ERR, 131078, "libiproto error code");
    is(MR::IProto::XS::ERR_CODE_TIMEOUT, 8454149, "libiprotoshard error code");
    is(MR::IProto::XS::LOG_DEBUG, 4, "logmask_t constant");
    return;
}

sub check_new {
    my $iproto = MR::IProto::XS->new(
        masters  => ['10.0.0.1:1000', '10.0.0.2:2000'],
        replicas => ['10.0.1.1:1001', '10.0.1.2:2001'],
    );
    is($iproto->get_shard_count(), 1, "one shard");

    $iproto = MR::IProto::XS->new(
        shards => {
            1 => { masters => ['10.0.2.1:1002'], replicas => ['10.0.3.1:1003'] },
            2 => { masters => ['10.0.2.2:2002'], replicas => ['10.0.3.2:2003'] },
            3 => { masters => ['10.0.2.3:2002'], replicas => ['10.0.3.3:2003'] },
        },
    );
    is($iproto->get_shard_count(), 3, "three shards");

    $iproto = MR::IProto::XS->new(
        masters  => [['10.0.0.1:1000', '10.0.0.2:2000'], ['10.0.0.3:3000', '10.0.0.4:4000']],
        replicas => [['10.0.1.1:1001', '10.0.1.2:2001'], ['10.0.1.3:3001', '10.0.1.4:4001']],
    );

    $iproto = MR::IProto::XS->new(
        masters => ['188.93.61.208:30000'],
    );

    return;
}

sub check_errors {
    my $msg = { code => 17, request => { method => 'pack', format => 'L', data => [ 0x01020304 ] } };

    {
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$EMPTY_PORT"]);
        my $resp = $iproto->bulk([$msg, $msg, $msg]);
        is_deeply($resp, [ map {{ error => "connection error" }} (1 .. 3) ], "connection error");
    }

    {
        my $iproto = MR::IProto::XS->new(masters => ["10.0.0.1:$EMPTY_PORT"]);
        my $resp = $iproto->bulk([$msg, $msg, $msg]);
        is_deeply($resp, [ map {{ error => "timeout" }} (1 .. 3) ], "timeout");
    }

    {
        my $iproto = MR::IProto::XS->new(shards => { 1 => { masters => ["127.0.0.1:$EMPTY_PORT"] }, 2 => { masters => ["10.0.0.1:$EMPTY_PORT"] } });
        my $resp = $iproto->bulk([{ %$msg, shard_num => 1 }, { %$msg, shard_num => 2 }, { %$msg, shard_num => 3 }]);
        is_deeply($resp, [ { error => "connection error" }, { error => "timeout" }, { error => "invalid shard_num" } ], "different errors for different shards");
        $resp = $iproto->bulk([$msg]);
        is_deeply($resp, [ { error => "invalid shard_num" } ], "shard_num is required if max_shard > 1");
        $resp = $iproto->bulk([{ %$msg, shard_num => 1 }, { %$msg, shard_num => 2 }, { %$msg, shard_num => 3 }]);
        is_deeply($resp, [ { error => "connection error" }, { error => "timeout" }, { error => "invalid shard_num" } ], "different errors for different shards - the same");
    }

    {
        my $port = fork_test_server(sub { });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        my $resp = $iproto->bulk([$msg, $msg, $msg]);
        is_deeply($resp, [ map {{ error => "connection error" }} (1 .. 3) ], "unexpected close");
    }

    {
        my $port = fork_test_server(sub { sleep 2.5 });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        my $resp = $iproto->bulk([$msg, $msg, $msg]);
        is_deeply($resp, [ map {{ error => "timeout" }} (1 .. 3) ], "send/recv timeout");
    }

    {
        my $port = fork_test_server(sub {
            my ($socket) = @_;
            echo(@_);
            my $header;
            my $len = $socket->sysread($header, 12);
            die "Failed to read: $!" if $len == -1;
            die "EOF" if $len == 0;
            die "Invalid header length" unless $len == 12;
            my ($code, $length, $sync) = unpack 'LLL', $header;
            my $data;
            $len = $socket->sysread($data, $length);
            die "Failed to read: $!" if $len == -1;
            $len = $socket->syswrite(pack 'LLLa*', $code, length $data, $sync + 1234, $data);
            die "Failed to write: $!" if $len == -1;
            echo(@_);
            return;
        });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        my $resp = $iproto->bulk([$msg, $msg, $msg]);
        is_deeply($resp, [ { error => 'ok', data => pack('L', 0x01020304) }, map {{ error => 'protocol error' }} (1, 2) ], "invalid sync");
    }

    close_all_servers();
    return;
}

sub check_success {
    {
        my $msg = { code => 17, request => { method => 'pack', format => 'Lw/a*L*', data => [ 89, 'test', 15 ] }, response => { method => 'unpack', format => 'w/a*L*' } };
        my $port = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('Lw/a*L', 89, 'test', 15), pack('w/a*L', 'test', $_)) foreach (11 .. 23);
        });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        my $resp = $iproto->bulk([ map $msg, (11 .. 23)]);
        is_deeply($resp, [ map {{ error => "ok", data => [ 'test', $_ ] }} (11 .. 23) ], "generic request");
    }

    {
        my $msg = { code => 17, request => { method => 'pack', format => 'Lw/a*L*', data => [ 89, 'test', 15 ] }, response => { method => 'unpack', format => 'w/a*L*' }, inplace => 1 };
        my $port = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('Lw/a*L', 89, 'test', 15), pack('w/a*L', 'test', $_)) foreach (11 .. 23);
        });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        my $resp = $iproto->bulk(my $req = [ map {{
                code     => 17,
                request  => { method => 'pack', format => 'Lw/a*L*', data => [ 89, 'test', 15 ] },
                response => { method => 'unpack', format => 'w/a*L*' },
                inplace  => 1,
            }} (11 .. 23)]);
        is_deeply($req, [ map {{
                code     => 17,
                request  => { method => 'pack', format => 'Lw/a*L*', data => [ 89, 'test', 15 ] },
                response => { method => 'unpack', format => 'w/a*L*', data => [ 'test', $_ ] },
                inplace  => 1,
                error    => "ok",
            }} (11 .. 23) ], "inplace request");
    }

    {
        my $msg = { code => 17, request => { method => 'pack', format => 'L', data => [ 1 ] }, response => { method => 'unpack', format => 'L' } };
        my $port = fork_test_server(sub { echo(@_) for (5, 6) });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        my $resp = $iproto->bulk(msgs($msg, 5));
        is_deeply($resp, [ { error => "ok", data => [ 5 ] } ], "two requests: first");
        $resp = $iproto->bulk(msgs($msg, 6));
        is_deeply($resp, [ { error => "ok", data => [ 6 ] } ], "two requests: second");
    }

    {
        my $msg = { code => 17, request => { method => 'pack', format => 'L', data => [ 1 ] }, response => { method => 'unpack', format => 'L' } };
        my $port1 = fork_test_server(map { sub { check_and_reply($_[0], 17, pack('L', 1), pack('L', 1)); } } (1 .. 100));
        my $port2 = fork_test_server(map { sub { check_and_reply($_[0], 17, pack('L', 1), pack('L', 2)); } } (1 .. 100));
        my $port3 = fork_test_server(map { sub { check_and_reply($_[0], 17, pack('L', 1), pack('L', 3)); } } (1 .. 100));
        my %count;
        for (1 .. 100) {
            my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port1", "127.0.0.1:$port2", "127.0.0.1:$port3"]);
            my $resp = $iproto->do($msg);
            $count{$resp->{data}->[0]}++ if $resp->{error} == 0;
        }
        is(scalar grep({ $_ > 20 } values %count), 3, "shuffle");
    }

    close_all_servers();
    return;
}

sub check_early_retry {
    my $msg = { code => 17, request => { method => 'pack', format => 'L', data => [ 0x01020304 ] }, response => { method => 'unpack', format => 'L' }, early_retry => 1 };

    {
        my $port1 = fork_test_server(sub { sleep 2 });
        my $port2 = fork_test_server(sub { echo(@_) for (11 .. 13) });
        my $iproto = MR::IProto::XS->new(masters => [["127.0.0.1:$port1"], ["127.0.0.1:$port2"], ["127.0.0.1:$EMPTY_PORT"]]);
        my $start = time();
        my $resp = $iproto->bulk(msgs($msg, (11 .. 13)));
        is_deeply($resp, [ map {{ error => 'ok', data => [ $_ ] }} (11 .. 13) ], "early retry");
        is(sprintf('%.02f', time() - $start), '0.06', "early retry time");
    }

    {
        my $port1 = fork_test_server(sub { sleep 2 });
        my $port2 = fork_test_server(sub { echo(@_) for (11 .. 13) });
        my $iproto = MR::IProto::XS->new(masters => [["127.0.0.1:$port1"], ["127.0.0.1:$port2"]]);
        my $start = time();
        my $resp = $iproto->bulk(msgs($msg, (11 .. 13)));
        is_deeply($resp, [ map {{ error => 'ok', data => [ $_ ] }} (11 .. 13) ], "early retry with less servers");
        is(sprintf('%.02f', time() - $start), '0.06', "early retry with less servers time");
    }

    {
        my $port = fork_test_server(sub { sleep 2 });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        my $start = time();
        my $resp = $iproto->bulk([$msg, $msg, $msg]);
        is_deeply($resp, [ map {{ error => 'timeout' }} (1 .. 3) ], "early retry with no servers");
        is(sprintf('%.02f', time() - $start), '0.50', "early retry with no servers time");
    }

    {
        my $port1 = fork_test_server(sub { sleep 0.1; echo(@_) foreach (21 .. 26) });
        my $port2 = fork_test_server(sub { echo(@_) foreach (11 .. 13) });
        my $iproto = MR::IProto::XS->new(masters => [["127.0.0.1:$port1"], ["127.0.0.1:$port2"]]);
        my $resp = $iproto->bulk(msgs($msg, (11 .. 13)));
        is_deeply($resp, [ map {{ error => 'ok', data => [ $_ ] }} (11 .. 13) ], "early retry 2");

        $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port1"]);
        $resp = $iproto->bulk(msgs($msg, (24 .. 26)));
        is_deeply($resp, [ map {{ error => 'ok', data => [ $_ ] }} (24 .. 26) ], "server wake up after early retry");
    }

    close_all_servers();
    return;
}

sub check_retry {
    my $msg = { code => 17, request => { method => 'pack', format => 'L', data => [ 97 ] }, response => { method => 'unpack', format => 'L' }, from => 'master,replica', safe_retry => 0 };

    {
        my $port = fork_test_server(sub {}, sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 9));
        });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        my $resp = $iproto->bulk([$msg]);
        is_deeply($resp, [ { error => 'ok', data => [ 9 ] } ], "retry when only one server allowed");
    }

    {
        local $msg->{retry_same} = 1;
        my $port1 = fork_test_server(sub { sleep 1 }, sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 1));
        });
        my $port2 = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 2));
        });
        my $iproto = MR::IProto::XS->new(masters => [["127.0.0.1:$port1"], ["127.0.0.1:$port2"]]);
        my $resp = $iproto->do($msg);
        is_deeply($resp, { error => 'ok', data => [ 1 ] }, "retry from the same server");
    }

    {
        local $msg->{retry_same} = 0;
        my $port1 = fork_test_server(sub { sleep 1 }, sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 1));
        });
        my $port2 = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 2));
        });
        my $iproto = MR::IProto::XS->new(masters => [["127.0.0.1:$port1"], ["127.0.0.1:$port2"]]);
        my $resp = $iproto->do($msg);
        is_deeply($resp, { error => 'ok', data => [ 2 ] }, "retry from another server");
    }

    {
        local $msg->{safe_retry} = 1;
        my $port1 = fork_test_server(sub { sleep 1 });
        my $port2 = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 2));
        });
        my $iproto = MR::IProto::XS->new(masters => [["127.0.0.1:$port1"], ["127.0.0.1:$port2"]]);
        my $resp = $iproto->do($msg);
        is_deeply($resp, { error => 'timeout' }, "safe retry - is unsafe");
    }

    {
        local $msg->{safe_retry} = 1;
        my $port = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 2));
        });
        my $iproto = MR::IProto::XS->new(masters => [["127.0.0.1:$EMPTY_PORT"], ["127.0.0.1:$port"]]);
        my $resp = $iproto->do($msg);
        is_deeply($resp, { error => 'ok', data => [ 2 ] }, "safe retry - is safe");
    }

    {
        local $msg->{retry_same} = 1;
        local $msg->{safe_retry} = 1;
        my $port = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 2));
        });
        my $iproto = MR::IProto::XS->new(masters => [["127.0.0.1:$EMPTY_PORT"], ["127.0.0.1:$port"]]);
        my $resp = $iproto->do($msg);
        is_deeply($resp, { error => 'ok', data => [ 2 ] }, "safe retry from the same server goes to another");
    }

    close_all_servers();
    return;
}

sub check_soft_retry {
    my $count = 0;
    my $msg = {
        code => 17,
        request => { method => 'pack', format => 'L', data => [ 97 ] },
        response => { method => 'unpack', format => 'L' },
        soft_retry_callback => sub { $count++; my ($r) = unpack('L', $_[0]); $r == 12 },
    };

    {
        my $port = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 12));
            check_and_reply($socket, 17, pack('L', 97), pack('L', 9));
        });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        my $start = time();
        my $resp = $iproto->bulk([$msg]);
        is_deeply($resp, [ { error => 'ok', data => [ 9 ] } ], "soft_retry - want");
        is(sprintf('%.01f', time() - $start), '0.1', "soft_retry - retry time");
    }

    {
        my $port = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 13));
            check_and_reply($socket, 17, pack('L', 97), pack('L', 9));
        });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        my $resp = $iproto->bulk([$msg]);
        is_deeply($resp, [ { error => 'ok', data => [ 13 ] } ], "soft_retry - don't want");
    }

    {
        my $port = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 12));
            check_and_reply($socket, 17, pack('L', 97), pack('L', 12));
            check_and_reply($socket, 17, pack('L', 97), pack('L', 9));
        });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        local $msg->{max_tries} = 6;
        my $start = time();
        my $resp = $iproto->bulk([$msg]);
        is_deeply($resp, [ { error => 'ok', data => [ 9 ] } ], "soft_retry - want twice");
        is(sprintf('%.01f', time() - $start), '0.4', "soft_retry - twice retry time");
    }

    {
        my $port = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 12));
            check_and_reply($socket, 17, pack('L', 97), pack('L', 12));
            check_and_reply($socket, 17, pack('L', 97), pack('L', 12));
            check_and_reply($socket, 17, pack('L', 97), pack('L', 9));
        });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        my $start = time();
        my $resp = $iproto->bulk([$msg]);
        is_deeply($resp, [ { error => 'ok', data => [ 12 ] } ], "soft_retry - want max");
        is(sprintf('%.01f', time() - $start), '1.0', "soft_retry - max retry time");
    }

    is($count, 8, "soft_retry count");
    close_all_servers();
    return;
}

sub check_timeout {
    my $msg = { code => 17, request => { method => 'pack', format => 'L', data => [ 97 ] }, response => { method => 'unpack', format => 'L' }, from => 'master,replica', safe_retry => 0 };

    {
        my $iproto = MR::IProto::XS->new(masters => ["10.0.0.1:$EMPTY_PORT"]);
        my $start = time();
        my $resp = $iproto->bulk([$msg, $msg, $msg]);
        is_deeply($resp, [ map {{ error => 'timeout' }} (1 .. 3) ], "server connect timeout");
        is(sprintf('%.01f', time() - $start), '0.6', "server connect timeout time");
    }

    {
        my $port = fork_test_server(sub { sleep 2 });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        local $msg->{max_tries} = 1;
        my $start = time();
        my $resp = $iproto->bulk([$msg, $msg, $msg]);
        is_deeply($resp, [ map {{ error => 'timeout' }} (1 .. 3) ], "message timeout");
        is(sprintf('%.01f', time() - $start), '0.5', "message timeout time");
    }

    {
        my $port = fork_test_server(sub { sleep 2 });
        my $iproto = MR::IProto::XS->new(masters => [["10.0.0.1:$EMPTY_PORT"], ["127.0.0.1:$port"]]);
        local $msg->{max_tries} = 2;
        my $start = time();
        my $resp = $iproto->bulk([$msg, $msg, $msg]);
        is_deeply($resp, [ map {{ error => 'timeout' }} (1 .. 3) ], "connect and message timeout");
        is(sprintf('%.01f', time() - $start), '0.7', "connect and message timeout time");
    }

    {
        my $port = fork_test_server(map { sub { sleep 1 } } (1 .. 10));
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        local $msg->{max_tries} = 10;
        my $start = time();
        my $resp = $iproto->bulk([$msg, $msg, $msg], timeout => 2);
        is_deeply($resp, [ map {{ error => 'timeout' }} (1 .. 3) ], "call timeout");
        is(sprintf('%.01f', time() - $start), '2.0', "call timeout time");
    }

    close_all_servers();
    return;
}

sub check_replica {
    my $msg = { code => 17, request => { method => 'pack', format => 'L', data => [ 97 ] }, response => { method => 'unpack', format => 'L' }, from => 'master,replica', safe_retry => 0 };

    {
        my $port1 = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 8));
            sleep 0.1
        });
        my $port2 = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 9));
        });
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port1"], replicas => ["127.0.0.1:$port2"]);
        my $resp = $iproto->bulk([$msg, $msg]);
        is_deeply($resp, [ { error => 'ok', data => [ 8 ] }, { error => 'ok', data => [ 9 ], replica => 1 } ], "retry from replica");
    }

    close_all_servers();
    return;
}

sub check_priority {
    my $msg = { code => 17, request => { method => 'pack', format => 'L', data => [ 97 ] }, response => { method => 'unpack', format => 'L' }, safe_retry => 0 };

    {
        my $port1 = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 8));
            sleep 0.1
        });
        my $port2 = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 9));
        });
        my $iproto = MR::IProto::XS->new(masters => [["127.0.0.1:$port1"], ["127.0.0.1:$port2"]]);
        my $resp = $iproto->bulk([$msg, $msg]);
        is_deeply($resp, [ { error => 'ok', data => [ 8 ] }, { error => 'ok', data => [ 9 ] } ], "retry from low priority");
    }

    close_all_servers();
    return;
}

sub check_pinger {
    my $msg = { code => 17, request => { method => 'pack', format => 'L', data => [ 97 ] }, response => { method => 'unpack', format => 'L' } };

    {
        my $port1 = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 8));
        });
        my $port2 = fork_test_server(sub {
            my ($socket) = @_;
            check_and_reply($socket, 17, pack('L', 97), pack('L', 9));
        });

        sleep 1;
        my $pinger_string = "lwp:xxx,iproto:127.0.0.1:$port1,iproto:127.0.0.1:29998\0";
        my $share = IPC::SharedMem->new(MR::Pinger::Const::SHM_KEY_FALL(), MR::Pinger::Const::SHM_SIZE(), 0666|IPC_CREAT) or die "Failed to create pinger shared memory";
        $share->write($pinger_string, 0, length($pinger_string)) or die "Filed to write to shared memory";

        my $iproto = MR::IProto::XS->new(masters => [["127.0.0.1:$port1"], ["127.0.0.1:$port2"]]);
        my $resp = $iproto->bulk([$msg]);
        is_deeply($resp, [ { error => 'ok', data => [ 9 ] } ], "check pinger");
    }

    close_all_servers();
    return;
}

sub check_fork {
    my $msg = { code => 17, request => { method => 'pack', format => 'L', data => [ 97 ] }, response => { method => 'unpack', format => 'L' }, max_tries => 1 };

    {
        my $port = fork_test_server(
            sub {
                my ($socket) = @_;
                check_and_reply($socket, 17, pack('L', 97), pack('L', 7));
                check_and_reply($socket, 17, pack('L', 97), pack('L', 8));
            },
            sub {
                my ($socket) = @_;
                check_and_reply($socket, 17, pack('L', 97), pack('L', 9));
            }
        );
        my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
        my $resp = $iproto->bulk([$msg]);
        my $pid = fork();
        die "Failed to fork()" unless defined $pid;
        if ($pid == 0) {
            $resp = $iproto->bulk([$msg]);
            my $ok = is_deeply($resp, [ { error => 'ok', data => [ 9 ] } ], "check fork");
            exit($ok ? 0 : 1);
        } else {
            waitpid $pid, 0;
            is($? >> 8, 0, "check fork");
        }
    }

    close_all_servers();
    return;
}

sub check_stat {
    my @stat;
    MR::IProto::XS::Stat->set_callback(sub { @stat = @_; return });
    my $msg = { code => 17, request => { method => 'pack', format => 'L', data => [ 97 ] } };
    my $port = fork_test_server(sub {
        my ($socket) = @_;
        check_and_reply($socket, 17, pack('L', 97), pack('L', 9)) for (1 .. 10);
    });
    my $iproto = MR::IProto::XS->new(masters => ["127.0.0.1:$port"]);
    $iproto->bulk([$msg]) for (1 .. 10);
    undef $iproto;
    ok(@stat == 4 && $stat[0] eq "call" && !defined $stat[1] && $stat[2] == 0 && $stat[2] eq "ok" && $stat[3]{count} == 10, "check stat callback");
    close_all_servers();
    return;
}

sub check_singleton {
    my $port = fork_test_server(sub {
        my ($socket) = @_;
        check_and_reply($socket, 17, pack('Lw/a*L', 89, 'test', 15), pack('w/a*L', 'test', $_)) foreach (11 .. 13);
    });
    {
        my $singleton = Test::Smth->create_singleton(masters => ["127.0.0.1:$port"]);
        isa_ok($singleton, "Test::Smth");
    }

    my $msg = { code => 17, request => { method => 'pack', format => 'Lw/a*L', data => [ 89, 'test', 15 ] }, response => { method => 'unpack', format => 'w/a*L' } };
    my $resp = Test::Smth->bulk([$msg, $msg, $msg]);
    is_deeply($resp, [ map {{ error => "ok", data => [ 'test', $_ ] }} (11 .. 13) ], "generic request througth singleton");
    {
        my $singleton = Test::Smth->remove_singleton();
        isa_ok($singleton, "Test::Smth");
    }
    close_all_servers();
    return;
}

sub check_leak {
    no warnings 'redefine';
    local *main::is = sub {};
    local *main::ok = sub {};
    local *main::cmp_ok = sub {};
    local *main::isa_ok = sub {};
    local *main::is_deeply = sub {};
    no_leaks_ok { check_new() } "constructor not leaks";
    no_leaks_ok { check_errors() } "error handling not leaks";
    no_leaks_ok { check_success() } "success query not leaks";
    no_leaks_ok { check_early_retry() } "early retry not leaks";
    no_leaks_ok { check_retry() } "retry not leaks";
    no_leaks_ok { check_soft_retry() } "soft retry not leaks";
    no_leaks_ok { check_timeout() } "timeout not leaks";
    no_leaks_ok { check_replica() } "replica not leaks";
    no_leaks_ok { check_priority() } "priority not leaks";
    no_leaks_ok { check_pinger() } "pinger not leaks";
    no_leaks_ok { check_stat() } "stat not leaks";
    no_leaks_ok { check_singleton() } "singleton not leaks";
    return;
}
