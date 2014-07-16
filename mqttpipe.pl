#!/usr/bin/perl

my $version = 'v0.128';
use strict;
use warnings;
use utf8;
binmode(STDOUT, ":utf8");

use LWP::UserAgent;
use JSON;

use constant LOG_FILE => '/var/log/mqttpipe.log';

use constant URL_JAUTH => 'http://127.0.0.1:8081';


my $o_log = 1;

# Flush output immediately.
$| = 1;


######## MAIN ########

log_to_file("Pipe start....");

# On startup, we have to inform c2s of the functions we can deal with. USER-EXISTS is not optional.
print "OK\n";

# MAIN LOOP
my $buf;
while(sysread (STDIN, $buf, 1024) > 0)
{
    my ($cmd, @args) = split ' ', $buf;
    log_to_file("DEBUG: $cmd @args");
    $cmd =~ tr/[A-Z]/[a-z]/;
    $cmd =~ tr/-/_/;

    eval "print _cmd_$cmd(\@args), '\n'";
}


# Compare the given password with the stored password.
sub _cmd_check_password
{
    my ($user, $pass) = @_;

    my %data = ();
    $data{op}   = 'check_password';
    $data{did}  = $user;
    $data{pass} = $pass;

    my $json = encode_json(\%data);

    log_to_file("DEBUG: CHECK-PASSWORD -> $json");
    my $ua = LWP::UserAgent->new;
    $ua->timeout(5);
    my $req = HTTP::Request->new(POST => URL_JAUTH);
    $req->content_type('application/json');
    $req->content($json);
    my $res = $ua->request($req);
    
    if($res->is_success)
    { 
        my $json_response = $res->content;
        log_to_file("DEBUG: CHECK-PASSWORD <- $json_response");
        my $json_response_ref = decode_json($json_response);
        my $code  = $json_response_ref->{code};
        my $alias = $json_response_ref->{alias};

        if ($code eq '0')
        {
            log_to_file("INFO: AUTH ok. $user($alias)");
            return 'OK';
        }
        elsif ($code eq '-1')
        {
            my $text = $json_response_ref->{text};
            log_to_file("INFO: AUTH fail. $user $text");
            return 'NO';
        }
        else
        {
            log_to_file("ERROR: please debug");
            return 'NO';
        }
    }
    else
    {
        my $error = $res->status_line;
        log_to_file("WARNING: CHECK-PASSWORD error connecting to dvalet AUTH. $error");
    }

    return 'NO';
}


#------------------------#
# For logging in file    #
#                        #
#------------------------#
sub log_to_file {
    my $t=shift;
    if ($o_log) {
        open(FH, ">>", LOG_FILE) or die "Can't open logfile".LOG_FILE."", $!; 
        my $log_line = time_now() . " $t\n";
        print FH $log_line;
        close(FH);
    }
    return;
}


#-------------------------------------------#
# Return a pretty time string.              #
# YYYY-MM-DD (iso 8601)                     #
#                                           #                         
#-------------------------------------------#
sub time_now {
    my ($sec,$min,$hour,$month_day,$month,$year,$wday,$yday,$isdst) = localtime(time);
    my $time_string = sprintf("%02d-%02d-%02d %02d:%02d:%02d", $year+1900, $month+1, $month_day, $hour, $min, $sec);
    return $time_string;
}



