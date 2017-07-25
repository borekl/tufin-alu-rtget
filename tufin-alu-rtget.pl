#!/usr/bin/perl

#=============================================================================
# TUFIN ALCATEL-LUCENT 7750SR ROUTE TABLE SCRAPER
#
# This tool is reads defined route tables from Alcate-Lucet 7750SR router
# and writes them into a text file formatted for TUFIN security orchestration
# tool.
#=============================================================================


#=============================================================================
# MODULES AND PRAGMAS
#=============================================================================

use strict;
use warnings;

use Try::Tiny;
use JSON;
use Expect;
use Log::Log4perl qw(get_logger);
use Net::IP qw(:PROC);
use Cwd qw(abs_path);


#=============================================================================
# CONFIGURATION
#=============================================================================

my $cfgname = 'tufin-alu-rtget.cfg';


#=============================================================================
# GLOBAL VARIABLES
#=============================================================================

my $js = JSON->new()->relaxed(1);
my $cfg;


#=============================================================================
# FUNCTIONS
#=============================================================================


#=============================================================================
# Perform token replacement in a string.
#=============================================================================

sub repl
{
  my $string = shift;
  my $replacements = $cfg->{'keyring'} // {};

  return undef if !$string;
  for my $k (keys %$replacements) {
    my $v = $replacements->{$k};
    $k = quotemeta($k);
    $string =~ s/$k/$v/g;
  }
  return $string;
}


#=============================================================================
#=============================================================================

sub get_ip_net
{
  my ($ip, $len) = @_;

  my $bin_ip  = ip_bintoint(ip_iptobin($ip,4));
  my $bin_msk = ip_bintoint(ip_get_mask($len, 4));
  my $bin_net = $bin_ip & $bin_msk;
  my $ip_net  = ip_bintoip(ip_inttobin($bin_net,4),4);

  return $ip_net;
}


#=============================================================================
# Function to execute pre-configured batch of expect-response strings.
#=============================================================================

sub run_expect_batch
{
  #--- arguments

  my (
    $host          # 1. router hostname
  ) = @_;

  #--- other variables

  my $logger = get_logger('tufin-alu-rtget::run_expect_batch');
  my %result;
  my $vpns;
  my $spawn = sprintf(
    $cfg->{'expect'}{'spawn'}, $cfg->{'credentials'}{'login'}, $host
  );

  #--- check arguments

  return "Invalid arguments to run_expect_batch()" if !$host;

  if(
    !exists $cfg->{'routers'}{$host}
    || !ref($cfg->{'routers'}{$host})
    || !scalar(@{$cfg->{'routers'}{$host}})
  ) {
    return "List of VPNs not defined for router $host";
  }
  $vpns = $cfg->{'routers'}{$host};
  $logger->info(sprintf('[%s] vpn list: %s', $host, join(',', @$vpns)));

  #--- initiate connection

  my $exh = Expect->spawn($spawn) or do {
    return "Connection failed";
  };
  $exh->log_stdout(0);

  #--- perform the chat

  try {

    #--- password

    $exh->expect(
      10,
      [
        qr/password:/i,
        sub {
          my $self = shift;
          $self->send($cfg->{'credentials'}{'password'} . "\r");
        }
      ]
    ) or die;

    #--- disable pagination

    $exh->expect(
      5,
      [
        qr/# /,
        sub {
          my $self = shift;
          $self->send("environment no more\r");
        }
      ]
    ) or die;

    #--- get the next prompt

    $exh->expect(5, [qr/# /]);

    #--- iterate over list of VPNs

    for my $vpn (@$vpns) {
      $result{$vpn} = {};
      $exh->send("show router $vpn interface\r");
      $exh->expect(30, [qr/# /]) or die;
      $result{$vpn}{'interfaces'} = $exh->exp_before();
      $exh->send("show router $vpn route-table\r");
      $exh->expect(30, [qr/# /]) or die;
      $result{$vpn}{'routes'} = $exh->exp_before();
    }

    #--- logout

    $exh->send("logout\r");
    sleep(1);

  } catch {
    return "Failed to communicate with router $host";
  };

  #--- finish

  return \%result;
}


#=============================================================================
# Iterate list of interface, match them to nexthop IP/name and call sub
# on each match
#=============================================================================

sub iter_interfaces
{
  #--- arguments

  my (
    $iflist,    # aref / interface list
    $nexthop,   # strg / nexthop (either IP or interface name)
    $cb         # sub  / callback
  ) = @_;

  #--- nexthop is IP or interface name

  my $nexthop_ip = new Net::IP($nexthop);

  #--- check for match

  for my $if (keys %$iflist) {
    my $if_net_ip = $iflist->{$if}{'if_net'} . '/' . $iflist->{$if}{'masklen'};
    if($nexthop_ip) {
      my $if_net = new Net::IP($if_net_ip) or die (Net::IP::Error());
      if($if_net->overlaps($nexthop_ip) == $IP_B_IN_A_OVERLAP) {
        $cb->($if);
      }
    } else {
      if($iflist->{$if}{'name'} eq $nexthop) {
        $cb->($if);
      }
    }
  }

}


#=============================================================================
#===================  _  =====================================================
#===  _ __ ___   __ _(_)_ __  ================================================
#=== | '_ ` _ \ / _` | | '_ \  ===============================================
#=== | | | | | | (_| | | | | | ===============================================
#=== |_| |_| |_|\__,_|_|_| |_| ===============================================
#===                           ===============================================
#=============================================================================
#=============================================================================

#--- we expect the configuration files to be present in the same directory
#--- as the script

my $work_dir = abs_path($0);
$work_dir =~ s/\/[^\/]*$//;

#--- initialize Log4perl

Log::Log4perl->init("$work_dir/logging.conf");
my $logger = get_logger('tufin-alu-rtget::Main');
$logger->info('tufin ALu 7750SR information scraper');

#--- read configuration

my $cfgpathname = "$work_dir/$cfgname";
if(! -f $cfgpathname) {
  $logger->fatal("$cfgname file does not exist or is not readable");
  die;
} else {
  local $/;
  my $fh;
   open($fh, '<', $cfgpathname) or do {
    $logger->fatal("Failed to open configuration file $cfgname");
    die;
  };
  my $cfg_json = <$fh>;
  close($fh);
  $cfg = $js->decode($cfg_json) or do {
    $logger->fatal("Failed to parse configuration file $cfgname");
    die;
  };
}

#--- read keyring

if(exists $cfg->{'keyfile'}) {
  local $/;
  my $fh;
  open($fh, '<', $work_dir . '/' . $cfg->{'keyfile'}) or do {
    $logger->fatal('Failed to open keyring file ' . $cfg->{'keyfile'});
    die;
  };
  my $keyring = <$fh>;
  close($fh);
  $cfg->{'keyring'} = $js->decode($keyring) or do {
    $logger->fatal('Failed to parse keyring file ' . $cfg->{'keyfile'});
    die;
  };
}

$cfg->{'credentials'}{'password'} = repl($cfg->{'credentials'}{'password'});

#--- iterate over configured routers

my %data;

for my $router (keys %{$cfg->{'routers'}}) {
  $logger->info("Getting info from router $router");
  my $rtr_data = run_expect_batch($router);
  $data{$router} = {};
  if(!ref($rtr_data)) {
    $logger->error('Failed to get information from router $router');
    $logger->error("Error: $rtr_data");
  } else {

#--- iterate over VPNs

    for my $vpn (keys %$rtr_data) {

#--- split the received text into lines, remove CR's

      my @interfaces
        = map { s/[\r\n]//g; $_; } split(/^/, $rtr_data->{$vpn}{'interfaces'});
      my @routes
        = map { s/[\r\n]//g; $_; } split(/^/, $rtr_data->{$vpn}{'routes'});

#--- state variables for the parsing

      my $flag = 0;
      my $second = 0;
      my ($if_name, $if_netip, $if_rt_proto, $if_rt_type);

#--- parse interfaces

      for my $l (@interfaces) {

        # $flag indicates we are in the range that contains the actual
        # interface listing (ie. between the ---- separators)

        if($l =~ /^-+$/) {
          $flag = !$flag;
          next;
        }

        # parsing the lines

        if($flag) {

          # interface name
          if($l =~ /^(\S+)\s/) {
            $if_name = $1;
          }

          # interface IP address
          if($l =~ /^\s+(\S+)\s/) {
            $if_netip = $1;
            $if_netip =~ /^(.+)\/(\d+)$/;
            my ($if_ip, $if_len) = ($1, $2);
            my $if_mask = ip_bintoip(ip_get_mask($if_len,4), 4);
            $data{$router}{$vpn}{'interfaces'}{$if_ip}
              = {
                  'name' => $if_name, 'mask' => $if_mask,
                  'masklen' => $if_len, 'if_net' => get_ip_net($if_ip, $if_len)
                };
          }

        }
      }

#--- parse route table

      $flag = 0;
      $second = 0;
      for my $l (@routes) {
        if($l =~ /^-+$/) {
          $flag = !$flag;
          next;
        }

        if($flag) {
          if(!$second) {
            $l =~ /^(\S+)\s+(\S+)\s+(\S+)\s/;
            ($if_netip, $if_rt_type, $if_rt_proto) = ($1, $2, $3);
          } else {
            $l =~ /^\s+(\S+)\s/;
            my $if_nexthop = $1;
            my $if_netip_obj = new Net::IP($if_netip);
            $data{$router}{$vpn}{'routes'}{$if_netip} = {
              'type' => $if_rt_type, 'proto' => $if_rt_proto,
              'next_ip' => $if_nexthop, 'ip' => $if_netip_obj->ip(),
              'mask' => $if_netip_obj->mask()
            };
          }
          $second = !$second;
        }
      }

#--- log some info

      $logger->info(
        sprintf(
          "[%s] VPN %d has %d interfaces, %d routes",
          $router, $vpn,
          scalar(keys %{$data{$router}{$vpn}{'interfaces'}}),
          scalar(keys %{$data{$router}{$vpn}{'routes'}})
        )
      );
    }
  }
}



#--- processing

my $outdir = $cfg->{'outdir'};
if($outdir !~ /^\//) {
  $outdir = "$work_dir/$outdir";
}

# iterate over routers
for my $router (keys %data) {

  # open the output file
  my $output_file = sprintf('%s/%s.txt', $outdir, lc($router));
  open(my $fh, '>', $output_file) or do {
    $logger->fatal(
      sprintf('[%s] Failed to write file %s', $router, $output_file)
    );
    die;
  };

  print $fh "Name, Ip, Mask, Vrf\n";

  # iterate over VPNs
  for my $vpn (keys %{$data{$router}}) {

    # iterate over interfaces
    for my $if (keys %{$data{$router}{$vpn}{'interfaces'}}) {
      my $ife = $data{$router}{$vpn}{'interfaces'}{$if};

      printf $fh "%s, %s, %s, %d\n",
        $ife->{'name'}, $if, $ife->{'mask'}, $vpn;
    }

  }

  printf $fh "\nDestination, Mask, Interface, Next-Hop, Vrf\n";

  # iterate over VPNs
  for my $vpn (keys %{$data{$router}}) {

    # iterate over routes
    for my $rt (keys %{$data{$router}{$vpn}{'routes'}}) {
      my $rte = $data{$router}{$vpn}{'routes'}{$rt};

      # the nexthop can be either IP address of interface name, here we decide
      # which case is current route entry and choose appropriate processing

      iter_interfaces(
        $data{$router}{$vpn}{'interfaces'}, $rte->{'next_ip'},
        sub {
          my $if = shift;
          my $ife = $data{$router}{$vpn}{'interfaces'}{$if};
          $rte->{'next_if'} = $if;
          $rte->{'next_if_name'} = $ife->{'name'};
        }
      ) if $rte->{'proto'} ne 'BGP';

      printf $fh "%s, %s, %s, %s, %d\n",
        $rte->{'ip'}, $rte->{'mask'}, $rte->{'next_if_name'} // '',
        $rte->{'next_if'} // $rte->{'next_ip'}, $vpn
        if $rte->{'proto'} ne 'BGP';
    }
  }

  close($fh);
}
