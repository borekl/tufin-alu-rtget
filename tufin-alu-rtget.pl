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
use JSON;


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
# MAIN
#=============================================================================

#--- read configuration

if(! -f $cfgname) {
  die "$cfgname file does not exist or is not readable";
} else {
  local $/;
  my $fh;
  open($fh, '<', $cfgname) or die 'Failed to open ' . $cfgname;
  my $cfg_json = <$fh>;
  close($fh);
  $cfg = $js->decode($cfg_json) or die;
}

#--- read keyring

if(exists $cfg->{'keyfile'}) {
  local $/;
  my $fh;
  open($fh, '<', $cfg->{'keyfile'}) 
    or die 'Failed to open ' . $cfg->{'keyfile'};
  my $keyring = <$fh>;
  close($fh);
  $cfg->{'keyring'} = $js->decode($keyring) or die;
}
