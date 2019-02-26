<?php
// This is https://github.com/mb-0/hetzner-dyndns
// Don't forget to look into README.md
// You may want to create a copy of config.default.php to config.php and amend settings.

// Local functions
function htz_say($str,$code=0) {
  global $htz_quiet, $htz_debug;
  // handle newline breaks for apache-php fpm-fcgi cli and linux, darwin, windows.
  if (php_sapi_name() == "fpm-fcgi") { $s="<br>";
  } elseif ( php_sapi_name() == "cli") {
    if (strtolower(PHP_OS) == "linux") { $s="\n";
    } elseif (strtolower(PHP_OS) == "darwin") { $s="\r";
    } else { $s="\r\n";
    }
  }
  // Messaging now.
  if (!$htz_quiet) {
    // General communication function to handle debug/silent/loud errors operation (TODO: logging at a later point);
    // code: 0 just normal if debug on; 1 warning if debug on, quiet if debug off; 2 die loudly
    if ($code == "0" && $htz_debug) { echo "_debug: $code | ${str}${s}"; }
    if ($code == "1") { echo ("${s}[WARNING: $code] ${str}${s}${s}"); }
    if ($code == "2") { die ("[ERROR: $code] ${str}${s}"); }
  } else {
    if ($code == "2") { die(); }
  }
}
function htz_getip() {
  // This function iterates through 3rd party whatismyip type services to get
  // a valid external IP address to work with.
  global $htz_myip_svc;
  // Randomize IP services :)
  shuffle($htz_myip_svc);
  // iterate through IP services provided in config
  foreach ($htz_myip_svc as $ipsvc) {
    // hit service with curl
    $res_ip=htz_curl($ipsvc,false,false,false,false,false,"curl/7.51.0");
    // replace all the crap we don't need (TODO: this is ipv4 matching only,
    // will also safeguard ipv6 validation (will fail)).
    $ip_test=preg_replace('/[^0-9\.]/',"",$res_ip[0]);
    // validate response, needs to be valid IP, nothing else
    if (htz_validateip($ip_test)) {
        $ip_ok=$ip_test;
        break;
    } else {
      htz_say(__FUNCTION__. ": $ipsvc is down or fails validation ($ip_test).", 0);
    }
  }
  if (empty($ip_ok)) {
    // iterated through all the options, and didn't get a working ip.
    // wan interface may be down, exit.
    htz_say(__FUNCTION__. ": Couldn't detect your IP address, you may be off the network, or all ip services are failing.", 2);
  }
  htz_say(__FUNCTION__. ": IP service $ipsvc says $ip_ok you are.", 0);
  return $ip_ok;
}

function htz_getlocation($str) {
  // This function digs oauth location from response headers supplied and returns value to be used for future requests;
  global $htz_loc;
  if (preg_match_all("/Location: .*/",$str,$matches)) {
      $rawloc=$matches[0][0];
      $htz_loc=preg_replace("/Location: /", "", $rawloc);
      $htz_loc=trim($htz_loc);
      htz_say(__FUNCTION__. ": Location found: $htz_loc",0);
      return $htz_loc;
  } else {
      return false;
  }
}
function htz_getloginurl($url,$html) {
  // This function digs out and concats a login URL.
  $urlpiece=preg_replace('/\/oauth\/authorize.*/','',$url);
  preg_match("/action=\".*\"/", $html[0], $match);	
  $piece_a=preg_replace("/.*\//", "", $match[0]);
  $piece_b=preg_replace("/\".*/", "", $piece_a);
  $htz_loginurl=$urlpiece.'/'.$piece_b;
  return $htz_loginurl;
}
function htz_validateip($ip) {
  if (!filter_var($ip, FILTER_VALIDATE_IP) === false) { return true; }
}
function htz_validatefile($file) {
  // this function attempts to create an empty file. returns false when it fails (write check this is really)
  if (!file_exists($file)) {
      $fh = fopen($file, 'w') or htz_say(__FUNCTION__. ": Failed creating data file $file", 2);
      fclose($fh);
      htz_say(__FUNCTION__. ": File $file created.", 0);
  }
}
function htz_readfile($file,$limiter=false) {
  if (file_exists($file)) {
      if (filesize($file) < 1) { return false; }
      $fh = fopen($file, 'r') or htz_say(__FUNCTION__. ": Cannot read data file: $file", 1);
      if ($limiter) {
          $res=fgets($fh);
      } else {
          // TODO: some limitation should be handy here in case the file is too large (can kill php), for whatever the reason is.
          $res=fread($fh, filesize($file));
      }
      fclose($fh);
      return $res;
  }
}
function htz_compareip($ip) {
  // This function compares IP address received from htz_getip to IP address cached in IP Data file.
  global $htz_data, $htz_data_ip;
  // check if IP Data file exists and attempt to create it if it doesn't.
  htz_validatefile($htz_data_ip);
  // check if IP Data file exists and compare contents with the IP we have received as param here.
  $line=htz_readfile($htz_data_ip,true);
  // Compare
  if ($line != $ip) {
     // Update IP if we have a different one.
      htz_say(__FUNCTION__. ": IP is to be updated in IP Data file ($line != $ip)", 0);
      return true;
  } else {
    // No diff, exit successfully as there's nothing left to do at this time.
    htz_say(__FUNCTION__. ": IP we have matches with data in IP Data file ($line == $ip), exiting with success.", 0);
    exit(0);
  }
}
function htz_savenewip($ip) {
  // Save new IP Address after an update.
  // We can save ourselves the trouble to validate IP (done in htz_getip()
  // and IP Data file existence (done in $htz_compareip)
  global $htz_data, $htz_data_ip;
  // Try opening ip data file, warn if can't.
  $out=fopen($htz_data_ip, 'w') or htz_say(__FUNCTION__. ": Cannot open IP Data file: $htz_data_ip", 1);
  // Try saving ip data file, fail if can't.
  fwrite($out, $ip) or htz_say(__FUNCTION__. ": Cannot write IP ($ip) to IP Data file $htz_data_ip", 2);
  fclose($out);
  chmod($htz_data_ip, 0600) or htz_say(__FUNCTION__. ": Cannot change permission to 0600 on $htz_data_ip", 1);
  htz_say(__FUNCTION__. ": IP has been saved to IP Data file ($ip)", 0);
  return true;
}

// Hetzner functions
function htz_curl($url=false, $header=false, $cookie=false, $referer=false, $postdata=false, $httpheaders=false, $agent=false, $follow=true) {
  // General cURL wrapper to be paramed for actual needs.
  // Returns an array with [0]: response [1]: headers
  $ch = curl_init();
    // optional params below, set only when not false
    if ($url) {       curl_setopt($ch, CURLOPT_URL, "$url"); } else { return false; }
    if ($header) {    curl_setopt($ch, CURLOPT_HEADER, true); }
    if ($referer) {   curl_setopt($ch, CURLOPT_REFERER, "$referer"); }
    if ($cookie)  {   curl_setopt($ch, CURLOPT_COOKIE, "$cookie");
    global $htz_data_cookies;
                      curl_setopt($ch, CURLOPT_COOKIEJAR, $htz_data_cookies);
                      curl_setopt($ch, CURLOPT_COOKIEFILE, $htz_data_cookies);}
    if ($postdata) {  curl_setopt($ch, CURLOPT_POST, 1);
                      curl_setopt($ch, CURLOPT_POSTFIELDS, "$postdata");}
    if ($httpheaders) {curl_setopt($ch, CURLOPT_HTTPHEADER, $httpheaders);}
    if ($agent)       {
                      curl_setopt($ch, CURLOPT_USERAGENT, "$agent");
    } else {
                      global $htz_usrag;
                      curl_setopt($ch, CURLOPT_USERAGENT, "$htz_usrag");
    }
    global $htz_curl_cheatssl;
    if ($htz_curl_cheatssl) {
                      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
                      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    }
    // fix params
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, $follow);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 10);

  // exec
  $res = curl_exec($ch);
  $err = curl_error($ch);
  $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
  $newheaders = substr($res, 0, $header_size);
  curl_close ($ch);
  unset($ch);
  htz_say(__FUNCTION__. ": CURL executed params: URL:'$url',Header='$header',Cookie='$cookie',Referer='$referer',PostData='$postdata',HTTPHeaders=",0); 
  // validate && return data
  if ($httpcode == "200") {
      $ret=array($res,$newheaders);
      return $ret;
   } else {
     htz_say(__FUNCTION__. ": HTTP Exited with code: $httpcode for $url, says $err",1);
     return false;
   }
}
// Hetzner response validators
function htz_validate_login($str) {
  // This function confirms successful login based on response HTML.
  global $htz_user;
  if (!preg_match_all("/.*Welcome.*/",$str,$matches)) {
      htz_say(__FUNCTION__. ": Couldn't find the line in response: 'Welcome'",2);
  } else {
      htz_say(__FUNCTION__. ": Confirmed login to Hetzner as user $htz_user.",0); return true;
  }
}
function htz_validate_dnspg($str,$domain,$domainkey) {
  // This function validates if a correct DNSID has been provided, fails if Hetzner comes back with an error.
  if (preg_match_all("/.*This DNS entry cannot be updated due to an internal error..*/",$str,$matches)) {
      htz_say(__FUNCTION__. ": ERROR, the DNS ID ($domainkey) provided for $domain seems to be wrong.",2);
  }
  htz_say(__FUNCTION__. ": DNS page response for $domain ($domainkey) looks OK.",0);
  return true;
}
function htz_validate_dnsup($str=false) {
  // This function validated DNS update response from Hetzner.
  // Example of what's received on successful update:
  if (preg_match_all('/The DNS entry will be updated now./',$str,$matches)) { return true; }
  return false;
}

function htz_getcookie($str,$scope=1) {
  // This function digs cookie set from response headers supplied and returns value to be used for future requests;
 // scope 1 = only the first cookie
 // scope all = all cookies
  global $htz_cookie; $rawcookie="";
  if (preg_match_all("/Set-Cookie: .*;/",$str,$matches)) {
      if ($scope == "all") {
         foreach ($matches[0] as $cookpiece) {
	     $cookpiece=preg_replace("/Set-Cookie: /", "", $cookpiece);
	     $cookpiece=preg_replace("/; path=\/; secure;/", "", $cookpiece);
	     $rawcookie=$rawcookie.'; '.$cookpiece;
         }
         $cookie=preg_replace("/^; /", "", $rawcookie).'; path=/; secure;';
      } else if ($scope == 1) {
	 $cookie=preg_replace("/Set-Cookie: /", "", $matches[0][0]);
      }
      htz_say(__FUNCTION__. ": Cookie found: $cookie",0);
      return $cookie;
  } else {
    htz_say(__FUNCTION__. ": No new cookie, using previous $htz_cookie",0);
    return $htz_cookie;
  }
}
function htz_getcsrf($str=false,$domain=false,$domainkey=false) {
  // This function digs out _csrf data from Hetzner response html.
  // csrf (today, 2019-02-26) looks like a 43 chars long hash made of a-Z0-9_-
  // example: T_5cB-fNljGLa6HdS5ZkloKi5vdM7EZOv_unH4UiI7X
  $doc = new DOMDocument;
  @$doc->loadHTML($str);
  $xpath = new DOMXpath($doc);
  $val= $xpath->query('//input[@type="hidden" and @name = "_csrf_token"]/@value' );
  $htz_csrf=$val[0]->nodeValue;

  if (!preg_match_all("/[a-zA-Z0-9\_\-]/",$htz_csrf,$matches) && strlen($htz_csrf) == 43) {
      htz_say(__FUNCTION__. ": Interesting, the _csrf value ($htz_csrf) for $domain fails our validation.",1);
      htz_say(__FUNCTION__. ": You may want to look up $htz_url or $htz_url/dns/update/id/$domainkey manually to see what's up.",1);
  }
  htz_say(__FUNCTION__. ": Have csrf value as $htz_csrf for /dns/update/id/$domainkey.",0);
  return $htz_csrf;
}
function htz_getzonedata($str) {
  // This function grabs ZONE data from the DNS Zone page. Will be processed (comared, replaced) later.
  $doc = new DOMDocument();
  @$doc->loadHTML($str);
  $zonedata=$doc->getElementById('zonefile');
  $zonevalue=$zonedata->nodeValue;
  return $zonevalue;
}
function htz_getzonehost($str,$domain,$domainkey,$host) {
  // match desired host IN A in zone (line);
  preg_match("/^{$host}[\s]+IN A[\s]+(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/m", $str, $line_match);
  // the line match array must have a single item, having multiple hosts matching here means BAD.
  if (count($line_match) > 1) {
      $details=implode("<br>\n", $line_match);
      htz_say(__FUNCTION__. ": No shit, we have more than one matching host for $host for $domain ($domainkey)!!! $details",2);
      // TODO: add case when there's no match. Note, this can be valid when local zone cache is non-existent.
  } else if (count($line_match) == 1) {
    return $line_match;
  }
  return false;
}
function htz_getzonehostip($arr) {
  // This function grabs IP from zone host IN A line and returns it.
  // Remove anything until first digit.
  $htz_zoneip=preg_replace('/.*IN A[\s]+/','',$arr[0]);
  // Remove whitespace(s) if any.
  $htz_zoneip=preg_replace('/[\s]+/','',$htz_zoneip);
  if (htz_validateip($htz_zoneip)) {
     return $htz_zoneip;
   } else {
     htz_say(__FUNCTION__. ": Validation of IP $arr[0] failed.",2);
   }
}
function htz_getzonedatafromfile($domainkey,$domain) {
  global $htz_data_zone;
  $htz_zonecacheforhost=preg_replace("/__DNSID__/","$domainkey",$htz_data_zone);
  $htz_zonecacheforhost=preg_replace("/__DOMAIN__/","$domain",$htz_zonecacheforhost);
  // check if file exists, create if not.
  htz_validatefile($htz_zonecacheforhost);
  // read it up.
  $cachedzonedata=htz_readfile($htz_zonecacheforhost);
  return $cachedzonedata;
}
function htz_updatezonedata($ip=false,$host=false,$zone=false,$line=false) {
   if ($ip && $host && $zone && $line) {
     // note that whitespace it starts with - getting that back at " $ip".
     $new_line=preg_replace("/\s(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/", " $ip", $line);
     // swap the two lines in zone data
     $new_zone=preg_replace("/$line/", "$new_line", $zone);
     // make sure this is all OK with strict start/end matching.
     if (!preg_match("/^{$host}[\s]+IN A[\s]+$ip$/m", $new_zone)) {
        htz_say(__FUNCTION__. ": No IP didn't get into the zone? WTF, not changing.",1);
        return false;
      }
        return $new_zone;
   } else {
     htz_say(__FUNCTION__. ": Missing IP ($ip), Host ($host) Zone data or Matched hosts line. No modifications have been made.",1);
     return false;
   }
}
function htz_savenewzone($zonedata,$domainkey,$domain) {
  // This function writes local zone cache for a particular domain (incl all hosts).
  // Executes when local domain cache seems to be out of date (empty or new IP found for one or more hosts)
  global $htz_data_zone;
  $htz_zonecacheforhost=preg_replace("/__DNSID__/","$domainkey",$htz_data_zone);
  $htz_zonecacheforhost=preg_replace("/__DOMAIN__/","$domain",$htz_zonecacheforhost);
  // Create the backup
  if (!copy("$htz_zonecacheforhost", "{$htz_zonecacheforhost}_backup")) { htz_say(__FUNCTION__. ": Cannot create backup of $htz_zonecacheforhost", 1); }
  chmod("{$htz_zonecacheforhost}_backup", 0600) or htz_say(__FUNCTION__. ": Cannot change permission to 0600 on {$htz_zonecacheforhost}_backup", 1);
  // Update local zone cache
  $out=fopen("$htz_zonecacheforhost", 'w') or htz_say(__FUNCTION__. ": Cannot save zone data to $htz_zonecacheforhost", 1);
  fwrite($out, $zonedata);
  fclose($out);
  // chmod - makes sense for cli, not for fpm/apache
  chmod($htz_zonecacheforhost, 0600) or htz_say(__FUNCTION__. ": Cannot change permission to 0600 on $htz_zonecacheforhost", 1);
  htz_say(__FUNCTION__. ": Data updated in $htz_zonecacheforhost (backup is here: ${htz_zonecacheforhost}_backup)", 0);
}

function htz_getttlminutes($zonedata) {
  // digs out TTL value (seconds) and returns a calculated approx minute value.
  // only for messaging, no real value here.
  preg_match('/^\$TTL[\s][0-9]+/m',$zonedata,$ttl);
  $ttlvalue=preg_replace('/^\$TTL[\s]/', '', $ttl[0]);
  return floor($ttlvalue/60);
}
// Pushover notification functions
function notify_pushover($str=false) {
  // Sends notification message via pushover service.
  global $htz_ntfy_push, $htz_ntfy_push_url, $htz_ntfy_push_appid, $htz_ntfy_push_usrid, $htz_ntfy_push_title, $htz_ntfy_push_prios;
  if ($htz_ntfy_push && $str && !empty($htz_ntfy_push_appid) && !empty($htz_ntfy_push_usrid)) {
      $po_msg=htz_curl("$htz_ntfy_push_url", false, false, false,
                       "token=$htz_ntfy_push_appid&user=$htz_ntfy_push_usrid&title=$htz_ntfy_push_title&priority=$htz_ntfy_push_prios&message=$str", false);
      // no need to validate response, curl will return with code HTTP 400 if this is rejected.
  }
}
function notify_pushover_additem($ip=false, $domain=false, $htz_updatedhosts=false,$ttl=false,$success=false) {
  // This function adds details to the notification message when dealing with
  // multiple domains & hosts, attempts to send a single msg for the update
  // instead of bombing individual messages per host or per domain.
  global $pushover_msg;
  $pushover_hostline="";
  foreach ($htz_updatedhosts as $host) { $pushover_hostline="$pushover_hostline $host.$domain";}
  if ($success) {
      $pushover_newline="$ip added for$pushover_hostline. Available in $ttl minute(s).";
      htz_say(__FUNCTION__. ": Pushover message updates to: '$pushover_newline'", 0);
  } else {
      $pushover_newline="Failed to update Hetzner DNS with $ip for $hostmsg.";
      htz_say(__FUNCTION__. ": Pushover message updates with failed results: '$pushover_newline'", 0);
  }
  // If this is empty, get rid of empty line.
  if (empty($pushover_msg)) {
    $pushover_newmsg="$pushover_newline";
  } else {
  $pushover_newmsg="$pushover_msg
$pushover_newline";
  }
  return $pushover_newmsg;
}

// TODO: get tests;

// Pull in config & stuff
if (file_exists(__DIR__.'/config.php')) { require_once(__DIR__.'/config.php');
} else { require_once(__DIR__.'/config.default.php'); }
if (!$htz_go) { echo "No. You will check that config.php.\n"; die (); }

//
// Stage 0:
// Get current WAN IP
//

$ex_ip=htz_getip(); // assuming a single IP address for all the domains & hosts.
htz_compareip($ex_ip);

//
// Stage 1:
// Identify what hosts & domains we need to update based on changes to WAN IP
// compared to DNS zone cache.
// -- This results in to process called $htz_update_domains
// -- with the same structure of $htz_allowed_domains.
//

$pushover_msg="";
$htz_update_domains=array();
// Iterate through all the domains we have to take care of
foreach($htz_allowed_domains as $htz_domain => $htz_hosts) {
        // grab the first item of host configuration, that is the domain_id we need for Hetzner.
        $htz_domain_key=array_shift($htz_hosts);
        // grab zonecache file to see if there's a change we need to worry about.
        $cached_zonedata=htz_getzonedatafromfile($htz_domain_key,$htz_domain);
        // iterate through hosts from configuration
        foreach ($htz_hosts as $host) {
          // check if host file has a match in our zone cache. If not, we'll have false here -> in which case we need to update.
          $cached_zonehost=htz_getzonehost($cached_zonedata,$htz_domain,$htz_domain_key,$host);
          // failing to validate IP address will stop this script, so let's see if we have a $cached_zonehost first at all.
          // if not, likely we have an empty file we're dealing with.
          if ($cached_zonehost) {
              // dig IP out of $cached_zonehost so we can compare to WAN IP later.
              $cached_zoneip=htz_getzonehostip($cached_zonehost);
              if ($cached_zoneip != $ex_ip) {
                  // New IP address is available for the host, add this to the list so we can update when get to Hetzner.
                  htz_say("New IP ($ex_ip) found $host for domain $htz_domain ($htz_domain_key). Will update currently regged ($cached_zoneip) at Hetzner.",0);
                  // if we already have this domain in the array, we already have the domain key and at least one host added.
                  // we need to add an extra item to this.
                  if (array_key_exists($htz_domain, $htz_update_domains)) {
                      array_push($htz_update_domains[$htz_domain],$host);
                  } else {
                    // but in case it doesn't, we can go a bit wilder.
                    $htz_update_domains=array_merge($htz_update_domains,array($htz_domain => array($htz_domain_key, $host)));
                  }

              } else {
                // Same IP, not adding to the list of hosts :>
                htz_say("No change in IP address in cached zone file, skipping $host for domain $htz_domain($htz_domain_key) from updates.",0);
              }
          } else {
              // the Host isn't found in cached zone file. Marking for update, so when we get to hetzner,
              // and download the latest DNS data, we can save this for future.
              // A fault will be thrown there when the host turns out to be nonexistent in the zone.
              htz_say("Host ($host) wasn't found in cached zone file for $htz_domain ($htz_domain_key). Will grab new DNS data from Hetzner to see if it's zone cache outdated (after a manual update for example) or we don't have this record in the DNS data.",1);
              // if we already have this domain in the array, we already have the domain key and at least one host added.
              // we need to add an extra item to this.
              if (array_key_exists($htz_domain, $htz_update_domains)) {
                  array_push($htz_update_domains[$htz_domain],$host);
              } else {
                // but in case it doesn't, we can go a bit wilder.
                $htz_update_domains=array_merge($htz_update_domains,array($htz_domain => array($htz_domain_key, $host)));
              }
          }
        }
}

//
// Stage 2:
// See if there are any items in $htz_allowed_domains as a result of Stage 1.
// Update all of them at Hetzner.
//

// if we have anything to update on Hetzner...

function htz_clearcookies() {
   global $htz_data_cookies;
   fclose(fopen($htz_data_cookies,'w'));
}

if (!empty($htz_update_domains)) {
   // kick cookies file :)
   htz_clearcookies();
   // kick the robots page
   $ex_kick=htz_curl("$htz_url", true, true);
   $htz_logincheck_loc=htz_getlocation($ex_kick[1]); // location has wonders for openid.
   // kick login
   $htz_loginurl=htz_getloginurl($htz_logincheck_loc,$ex_kick);
   // get csrf token from login kick
   // debug print $ex_kick[0];
   $htz_csrf=htz_getcsrf($ex_kick[0]);
   $ex_login=htz_curl($htz_loginurl, true, true, false, "_username=$htz_user&_password=$htz_pass&_csrf_token=$htz_csrf");
   // validate successful login from response $ex_login[0]
   htz_validate_login($ex_login[0]);
   // iterate through domains we need to update at Hetzner.
   foreach($htz_update_domains as $htz_domain => $htz_hosts) {
           // let's grab the domain key :)
           $htz_domain_key=array_shift($htz_hosts);
           // grab the DNS page
           $ex_zone=htz_curl("$htz_url/dns/update/id/$htz_domain_key", true, true, "$htz_url/dns");
           // ensure what we have is correct, die if not. $ex_zone[0] is data, [1] is headers for cookies.
           htz_validate_dnspg($ex_zone[0],$htz_domain,$htz_domain_key);
           // grab csrf from response.
           $htz_csrf=htz_getcsrf($ex_zone[0],$htz_domain,$htz_domain_key);
           // grab zone data (txt) from response
           $htz_zonedata=htz_getzonedata($ex_zone[0]);
           // get an array ready for final list of updated hosts;
           $htz_updatedhosts=array();
           // Iterate through the hosts set for this domain and update IPs where appropriate.
           foreach ($htz_hosts as $host) {
              // dig out line for host from zone file.
              $htz_zonehost=htz_getzonehost($htz_zonedata,$htz_domain,$htz_domain_key,$host);
              // Check if we have a matching line.
              // If not, that means there's either a typo, or this host is not yet present in the zone configuration at hetzner.
              // We need the user to add a HOST IN A IP record manually first. We can update once it's there.
              if (!$htz_zonehost) {
                htz_say("Host $host is not found in Hetzner DNS. You need to add this IN A record manually first, we won't be adding new lines to DNS configuration with this script.", 1);
                continue;
              }
               // grab IP from host line.
               $htz_zoneip=htz_getzonehostip($htz_zonehost);
               // Compare IPs and continue to next host should this be matching.
               if ($htz_zoneip == $ex_ip) {
                   // No update needed, IPs are metching - outdated zone cache, likely.
                   htz_say("No update needed for host $host for $htz_domain ($htz_domain_key) as (WAN: $ex_ip == ZONE: $htz_zoneip).", 0);
               } else {
                   // Need to update zone on Hetzner.
                   htz_say("Update needed for $host for $htz_domain ($htz_domain_key) as (WAN: $ex_ip != ZONE: $htz_zoneip).", 0);
                   // Replace IP for host in zone data.
                   $htz_newzonedata=htz_updatezonedata($ex_ip,$host,$htz_zonedata,$htz_zonehost[0]);
                   // If successful, use new data as base, so we can make further changes to it if needed.
                   if ($htz_newzonedata) { $htz_zonedata=$htz_newzonedata; }
                   // Add host to updated Array
                   array_push($htz_updatedhosts,$host);
               }
            }
            // If we have an empty list for hosts to update, save the zone locally and get out of this loop.
            if (empty($htz_updatedhosts)) {
              htz_savenewzone($htz_zonedata,$htz_domain_key,$htz_domain);
              continue;
            }
            // Update hetzner DNS data when all the host specific changes have been amended.
            // can be done once per domain entry, no need to call this per host amended.
            // No additional validation is needed, replaced already existing data hetzner's own validation is sufficient).
            $ex_submitzone=htz_curl("$htz_url/dns/update", true, true, "$htz_url/dns", "id=$htz_domain_key&_csrf_token=$htz_csrf&_=&zonefile=$htz_zonedata");

            // Check response from Hetzner, warn if update has failed.
            if (!htz_validate_dnsup($ex_submitzone[0])) {
                htz_say(__FUNCTION__. ": Updating $htz_domain ($htz_domain_key) went titsup.", 1);
                $pushover_msg=notify_pushover_additem($ex_ip,$htz_domain,$htz_updatedhosts,htz_getttlminutes($htz_zonedata),false);
            } else {
            // On successful update"
            // Save zone data to zone cache.
            htz_savenewzone($htz_zonedata,$htz_domain_key,$htz_domain);
            $pushover_msg=notify_pushover_additem($ex_ip,$htz_domain,$htz_updatedhosts,htz_getttlminutes($htz_zonedata,$htz_updatedhosts),true);
           }
           htz_say("--------------------------------------------------------",0); // newline for debug view
           // This is where we sleep 1, let's not hammer hetzner services.
           sleep(1);
    }
    // Logout.
    $ex_logout=htz_curl("$htz_url/login/logout", true, true, "$htz_url/");
    // Save new IP after updating hosts (e.g. successful update should not trigger this until next IP update)
    htz_savenewip($ex_ip);
    // Send pushover message (messageconstruct)
    notify_pushover($pushover_msg);
}
// eof.
?>
