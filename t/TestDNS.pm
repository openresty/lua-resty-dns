package TestDNS;

use 5.010001;
use Test::Nginx::Socket -Base;
use JSON::XS;

use constant {
    TYPE_A => 1,
    TYPE_CNAME => 5,
    TYPE_AAAA => 28,
    CLASS_INTERNET => 1,
};

sub encode_name ($);
sub encode_ipv4 ($);

sub Test::Base::Filter::dns {
    my ($filter, $code) = @_;

    my $t = eval $code;
    if ($@) {
        die "failed to evaluate code $code: $@\n";
    }

    my $s = '';

    my $id = $t->{id} // 0;

    $s .= pack("n", $id);
    #warn "id: ", length($s), " ", encode_json([$s]);

    my $qr = $t->{qr} // 1;

    my $opcode = $t->{opcode} // 1;

    my $aa = $t->{aa} // 0;

    my $tc = $t->{tc} // 0;
    my $rd = $t->{rd} // 1;
    my $ra = $t->{ra} // 1;
    my $rcode = $t->{rcode} // 0;

    my $flags = ($qr << 15) + ($opcode << 11) + ($aa << 10) + ($tc << 9) + ($rd << 8) + ($ra << 7) + $rcode;
    #warn sprintf("flags: %b", $flags);

    $flags = pack("n", $flags);
    $s .= $flags;

    #warn "flags: ", length($flags), " ", encode_json([$flags]);

    my $answers = $t->{answer} // [];
    if (!ref $answers) {
        $answers = [$answers];
    }

    my $qdcount = $t->{qdcount} // 1;
    my $ancount = $t->{ancount} // scalar @$answers;
    my $nscount = 0;
    my $arcount = 0;

    $s .= pack("nnnn", $qdcount, $ancount, $nscount, $arcount);

    my $qname = encode_name($t->{qname} // "");

    #warn "qname: ", length($qname), " ", encode_json([$qname]);

    $s .= $qname;

    my $qs_type = $t->{qtype} // TYPE_A;
    my $qs_class = $t->{qclass} // CLASS_INTERNET;

    $s .= pack("nn", $qs_type, $qs_class);

    for my $ans (@$answers) {
        my $name = encode_name($ans->{name});
        my $type = $ans->{type};
        my $class = $ans->{class};
        my $ttl = $ans->{ttl} // 0;

        my ($rdlength, $rddata);

        my $ipv4 = $ans->{ipv4};
        if (defined $ipv4) {
            ($rddata, $rdlength) = encode_ipv4($ipv4);
            $type //= TYPE_A;
            $class //= CLASS_INTERNET;
        }

        $rdlength //= $ans->{rdlength} // 0;
        $rddata //= $ans->{rddata} // "";

        #warn "rdlength: $rdlength, rddata: ", encode_json([$rddata]), "\n";

        $s .= $name . pack("nnNn", $type, $class, $ttl, $rdlength) . $rddata;
    }

    return $s;
}

sub encode_ipv4 ($) {
    my $txt = shift;
    my @bytes = split /\./, $txt;
    return pack("CCCC", @bytes), 4;
}

sub encode_name ($) {
    my $name = shift;
    $name =~ s/([^.]+)\.?/chr(length($1)) . $1/ge;
    $name .= "\0";
    return $name;
}

1
