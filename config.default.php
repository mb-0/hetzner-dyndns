<?php

// change this to "true" after amending the settings below
$htz_go=false;

// debug mode: this will make things verbose a lot.
// you may want to set this to false when running
// as production (or from cron);
$htz_debug=true;

// this overrides debug, will be absolutely silent
// (apart from pushover notifs)
$htz_quiet=false;

// Hetzner username and password configuration
$htz_user="<your_login_user_name";
$htz_pass="<very_secret_password>";

// SSL Cheat - this adds SSL_VERIFYHOST and SSL_VERIFYPEER
// this will allow you to get around untrusted or self-signed
// SSL certs (e.g. when you run your own whatismyip service).
$htz_curl_cheatssl=false;

// Data Directory
// Please ensure your PHP can write to this directory.
// This contains IP, cookie info and backups for your
// zone file(s) before modification attempt.
$htz_data=__DIR__."/data";
// You can set these too, using .data by default
// you may want to disable serving the .data files on your webserver
// should you be using this via the web.
$htz_data_ip="$htz_data/htz.ip.data";
$htz_data_zone="$htz_data/htz.zone.__DNSID__.data"; // __DNSID__ is replaced with hetzner DNSID integer
$htz_cookie_jar="$htz_data/htz.cookie.data";

// The following configuration allows you to set
// multiple domains and hosts to be updated in a single run.
// Structure:
// 'your-domain.com' => array('your_hetzner_dns_id', 'host1', 'host2', 'hostn')
//
// Example: update the www and vpn IN A records with your current IP for example.com
// e.g. www.example.com and vpn.example.com will point to your WAN address.
//
// $htz_allowed_domains = array(
//   'example.com' => array('123456', 'www');
// }
//
// Example: update multiple A records to point to your WAN IP address:
// e.g. dev.example.com, test.example.com, ftp.example.com, ftp.example.com will
// all point to your WAN (but be mindful, this is pretty much what CNAME is for ;))
//
// $htz_allowed_domains = array(
// 		'example2.com' => array('012345', 'dev', 'test', 'ftp', 'vpn')
// }
//
// For the Hetzner DNS ID you will need to login to robot.your-server.de via a web browser,
// navigate to robot.your-server.de/dns, click your desired domain, and view the source.
// Look for a <table entry that has an onclick JavaScript event that looks like:
// /dns/update/id/XXXXXX. The XXXXXX is a 6 (or probably 7 by the time you get this)
// digit integer. This is your internal Hetzner DNS ID you need to use in this setting.
//
// Note: there is a sec pause implemented on purpose between updating domains
// for the reason to be mindful about Hetzner's services. This means, you can reach
// a timeout for your PHP script when updating like 50 domains.
$htz_allowed_domains = array(
		'example.com' => array('123456', 'www'),
		'example2.com' => array('012345', 'dev', 'test', 'ftp', 'vpn')
);

// An array of what is my IP type services.
// The app iterates through these for as long as a valid IP address is not received.
// Adding more (or replacing) is possible, you only need to ensure that
// curl -s http://<yourmyipservice> provides an IP address back, nothing else
// Good source to update this list: https://raw.githubusercontent.com/rsp/scripts/master/externalip-benchmark
// TODO: run tests against all of these, remove those that stop funct.
$htz_myip_svc = array(
		'http://whatismyip.akamai.com',
		'http://ip.tyk.nu/',
		'http://l2.io/ip',
		'https://api.ipify.org',
		'https://wtfismyip.com/text',
		'http://ip.appspot.com/',
		'http://ipecho.net/plain',
		'http://ident.me/',
		'http://ipof.in/txt',
		'http://icanhazip.com/',
		'http://ifconfig.co',
		'http://wgetip.com/',
		'http://bot.whatismyipaddress.com/',
		'https://4.ifcfg.me',
		'http://ipecho.net/plain');

// PushOver notification integration
// In case you have access to pushover and want
// notifications when your IP address is being updated
// by this script, provide details here.
$htz_ntfy_push=false; // enabled by default
$htz_ntfy_push_url="https://api.pushover.net/1/messages.json"; // until pushover changes this, don't break :)
$htz_ntfy_push_appid="<app_token_hash>"; // limit notifications to a single app
$htz_ntfy_push_usrid="<user_hash>"; // limit notifications to a user (or group) id
$htz_ntfy_push_title="Hetzner DNS Updated"; // General title for all messages (TODO: dynamic to incl domain / ip?)
$htz_ntfy_push_prios="0";	// Priority for push messages

// Hetzner base URL
$htz_url="https://robot.your-server.de";

// User agent to use when executing hetzner calls with curl.
$htz_usrag="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.78 Safari/537.36";

?>
