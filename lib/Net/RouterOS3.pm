use strict;
use warnings;
package Net::RouterOS3;
# ABSTRACT: Operation of MikroTik RouterOS API for RouterOS3

=head1 SYNOPSIS

ON YOUR ROUTER: [admin@MikroTik] > /ip service enable api

use Net::RouterOS3;

my $router = Net::RouterOS3->new(
	{
		host => '127.0.0.1',
		username => 'someuser',
		password => 'somepass',
	}
);

$router->login;

my @command = qw(/user/getall/);
$router->command(\@command);

=method new

Create a new Net::RouterOS3 connection

=cut

use Moose;
use namespace::autoclean;
use IO::Socket;
use Digest::MD5;
use Data::Dumper;

has 'host' => (
	is => 'rw',
	isa => 'Str',
	required => 1,
);

has 'port' => (
	is => 'rw',
	isa => 'Int',
	default => 8728,
	predicate => 'has_port',
);

has 'username' => (
	is => 'rw',
	isa => 'Str',
	required => 1,
);

has 'password' => (
	is => 'rw',
	isa => 'Str',
	required => 1,
);

has 'socket' => (
	is => 'rw',
	isa => 'IO::Socket::INET',
	default => sub {my $self = shift;$self->connect}
);

has 'debug' => (
	is => 'rw',
	isa => 'Int',
	required => 1,
	default => 0
);

sub write_len {
	my ($self, $len) = @_;

	my $bytes = $len < 0x80 ? 1 :
		$len < 0x4000 ? 2 : $len < 0x200000 ? 3 : $len < 0x10000000? 4 : 5;

	$len |= (0x0F >> (5 - $bytes)) << ($bytes * 8 - $bytes + 1);

	my $str;
	while ($bytes--) {
		$str .= chr($len & 0xFF);
		$len >>= 8;
	}

	$self->socket->send($str);
}

sub write_word {
	my ($self, $word) = @_;
	$self->write_len(length($word));
	$self->socket->send($word);
}

sub write_sentence {
	my ($self, $sentence) = @_;
	for my $word (@$sentence) {
		$self->write_word($word);
		warn ">>> $word\n" if $self->debug > 2;
	}
	$self->write_word('');
}

sub read_len {
	my ($self) = @_;
	my ($c);
	$self->socket->recv($c,1);
	$c = ord($c);

	my $bytes = $c < 0x80 ? 0 : $c < 0xC0 ? 1 : $c < 0xE0? 2 : $c < 0xF0 ? 3 : 4;
	my $len=$c & (0xFF >> $bytes);
	$bytes or return $len;
	while ($bytes--) {
		$self->socket->recv($c, 1);
		$len = ($len << 8) + ord($c);
	}
	return $len;
}

sub read_word {
	my ($self) = @_;

	my $len = $self->read_len;
	my $ret_line;
	if ($len > 0)
	{
		if ($self->debug > 3)
		{
			warn "recv $len\n";
		}
		while (1) {
			my ($line) = '';
			$self->socket->recv($line,$len);
			# append to $ret_line, in case we didn't get the whole word and are going round again
			$ret_line .= $line;
			my $got_len = length($line);
			if ($got_len < $len)
			{
				# we didn't get the whole word, so adjust length and try again
				$len -= $got_len;
			}
			else
			{
				# woot woot!  we got the required length
				last;
			}
		}
	}
	return $ret_line;
}

sub read_sentence {
	my ($self) = @_;
	my @reply;
	my $retval = 0;
	my $done = 0;

	while (my $word = $self->read_word) {
		if ($word =~ /^!done/) {
			$retval = 1;
			$done = 1;
		} elsif ($word =~ /^!trap/) {
			$retval = 2;
		} elsif ($word =~ /^!fatal/) {
			$retval = 3;
		}
		push @reply, $word;
		if ($self->debug > 2) {
			warn "<<< $word\n"
		}
	}
	return ($retval, \@reply, $done);
}

sub talk {
	my($self, $sentence) = @_;
	$self->write_sentence($sentence);
	my($retval) = 0;
	my($reply, $attrs, $done);
	while (($retval, $reply, $done) = $self->read_sentence) {
		for my $line (@$reply) {
			if ($line =~ /^=(\S+)=(.*)/) {
				push @{$attrs}, {$1 => $2};
			}
		}
		last if ($retval > 0 and $done > 0);
	}
	return ($retval, $attrs);
}

sub connect {
	my ($self) = @_;
	my $socket = IO::Socket::INET->new(
		PeerAddr => $self->host,
		PeerPort => $self->port,
		Proto    => 'tcp'
	);
	return $socket;
}

sub login {
	my ($self) = @_;
	if ($self->socket) {
		my @command = qw(/login);
		my ($retval, $results) = $self->talk(\@command);
		my ($chal) = pack("H*", $results->[0]->{'ret'});
		my ($md) = Digest::MD5->new;
		$md->add(chr(0));
    $md->add($self->password);
    $md->add($chal);
		@command = qw(/login);
    push @command, '=name=' . $self->username;
    push @command, '=response=00' . $md->hexdigest;
		($retval, $results) = $self->talk(\@command);
    if ($retval > 1) {
#     $error_msg = $results[0]{'message'};
			return -1;
    }
    if ($self->debug > 0) {
			warn "Logged in to $self->host as $self->username\n";
    }
		return 0;
	} else {
		return -1;
	}
}

sub logout {
	my ($self) = @_;
	my @command = qw(/quit);
	$self->command(\@command);
}

sub command {
	my ($self, $command, $attrs) = @_;
#	my $error_msg = '';
	my (@command);
	push @command, $command;
	while (my ($k, $v) = each(%$attrs)) {
		push @command, "=$k=$v";
	}
	print Dumper @command;
	my ($retval,$results) = $self->talk(\@command);
	if ($retval > 1) {
#		$error_msg = $results->[0]{'message'};
	}
	return ($retval,$results);
}


no Moose;
__PACKAGE__->meta->make_immutable;

1;
