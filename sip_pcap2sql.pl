#!/usr/bin/perl 
use strict;
#use warnings;
use Net::Pcap::Easy;
use DBI;
use DBD::mysql;

my $file=$ARGV[0];
my $tname=$ARGV[1];
my $res_str="";
if(!defined($file))
{print "\nError 1=============================\n
          Dump file is not defined. Exit!\n
          Please specify the name of the dump file and the table name in the format:\n
          my_pcap.pl <file_name> <table_name>\n
          ====================================\n\n"; exit 1;}
if(!defined($tname))
{
	print "Table is not defined. Out put in console;\n";
}
#<0>, Via,From,To,Call-ID,CSeq,Contact,Max-Forwards,User-Agent
#SUBSCRIBE sip:finotdel.octoline.ru SIP/2.0 =====  SIP/2.0 200 OK
 
my $npe = Net::Pcap::Easy->new(
      dev              => "file:$file",
      packets_per_loop => 1,
      icmp_callback => sub { warn "ping or something!\n" },
      udp_callback => sub {
	my ($npe, $ether, $ip, $udp, $header ) = @_;
	my @sip;
        my ($field, $value,$i,$method,$status,$reason);
        my %sip_hash;
	#my $iquie;

        #my $xmit = localtime( $header->{tv_sec} )." ".$header->{tv_usec};
	my $xmit = $header->{tv_sec}." ".$header->{tv_usec};

	format STDOUT =
-----------------------------------------------------------------------------------------------------------------------------------------------------------------
^<<<<<<<<<<<< |ip_s: ^<<<<<<<<<<< |p_s: ^<<<<< | ip_d: ^||||||||| |p_d: ^||||| |Call-id: ^|||||||||||||| |U-agent: ^||||||| |Len: ^||| |Met: ^|||||| |Stat ^||| |
$xmit,    $ip->{src_ip},  $udp->{src_port},   $ip->{dest_ip},  $udp->{dest_port}, $sip_hash{"Call-ID"},$sip_hash{"User-Agent"}, $udp->{len}, $sip_hash{"CSeq"},$status
^<<<<<<<<<<<< | ^<<<<<<<<<<<<<<<< | ^<<<<<<<<< | ^||||||||||||||| | ^||||||||| | ^|||||||||||||||||||||| | ^||||||||||||||| | ^||||||| | ^|||||||||| | ^||||||| |
$xmit,    $ip->{src_ip},  $udp->{src_port},   $ip->{dest_ip},  $udp->{dest_port}, $sip_hash{"Call-ID"},$sip_hash{"User-Agent"}, $method,$sip_hash{"CSeq"},$reason
.
#       print "$xmit UDP: $ip->{src_ip}:$udp->{src_port}". " -> $ip->{dest_ip}:$udp->{dest_port}\n";
        @sip= split(/\r/,$udp->{data});
        for($i=0;$i<$#sip;$i++)
        {
		($field, $value)= split(': ',$sip[$i]);chomp($field);chomp($value);$field=~s/[\s\r\n]*//;
		if ($field eq "CSeq")
                {
                        if ($value =~/[\d+] ([a-zA-Z]+)/){$value=$1;}
                }
		$sip_hash{$field}=$value;
		if ($field =~/.*SIP\/2\.0 (\d{3}) ([a-zA-Z\/ ]+).*/){$status=$1;$reason=$2;}
		#SUBSCRIBE sip:yuliya.ignatova@finotdel.octoline.ru SIP/2.0
		if ($field =~/([A-Z]+).*SIP\/2\.0.*/){$method=$1;}
		#print "### Field=".$field."### HashValue=".$sip_hash{$field}."\n";#"### TrueValue=".$value."\n";
	}
    $value=$udp->{data};
    $value =~ s/'/\\'/g;
    $sip_hash{"Contact"} =~ s/'/\\'/g;
    $sip_hash{"Call-ID"} =~ s/'/\\'/g;
    $sip_hash{"User-Agent"} =~ s/'/\\'/g;

	if(defined($tname))
	{
	   $res_str='INSERT INTO sip_traffic.'.$tname.' (
      ts_sec,
      ts_usec,
      ip_source,
      ip_dest,
      udp_source_port,
      udp_dest_port,
      dgram_size,
      sip_method,
      sip_status,
      sip_reason,
      user_agent,
      callid,
      uri,
      sip_message) 
       VALUES(
        "'.$header->{tv_sec}.'",
        "'.$header->{tv_usec}.'",
        "'.$ip->{src_ip}.'",
        "'.$ip->{dest_ip}.'",
        "'.$udp->{src_port}.'",
        "'.$udp->{dest_port}.'",
        "'.$udp->{len}.'",
        \''.$sip_hash{"CSeq"}.'\',
        \''.$status.'\',
        \''.$reason.'\',
        \''.$sip_hash{"User-Agent"}.'\',
        \''.$sip_hash{"Call-ID"}.'\',
        \''.$sip_hash{"Contact"}.'\',
        \''.$value.'\')';
   }
	else
	{
	   write;
	}

#	  print "\t$ether->{src_mac} -> $ether->{dest_mac}\n"; # if $SHOW_MAC;
     },

   );


        my $database = "sip_traffic";
        my $platform = "mysql";
        my $host = "localhost";
        my $port = "3306";
        my $user = "root";
        my $pw = "11";
        my $sth = "";
if(defined($tname))
{
    my $dsn = "dbi:mysql:$database:$host:3306";
    my $dbh = DBI->connect($dsn, $user, $pw) or die "Unable to connect: $DBI::errstr\n";
    my $quie= $dbh->prepare("CREATE TABLE $tname LIKE dump_etalon");
    $quie->execute;
    while ($npe->loop)
    {
	      if(defined($tname) and defined($dbh))#{print $res_str."\n";}
        {
          $quie = $dbh->prepare($res_str); 
          $quie->execute or print $res_str."\n";
        }
    } # loop() returns 3 twice, then a 0
    $dbh->disconnect;
}
else {1 while $npe->loop}
    exit 0;
