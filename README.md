# Hetzner-DynDNS
Once configured properly, this script can act as a dynamic DNS service for domains managed by Hetzner A.G. (https://www.hetzner.de).
It is possible to update multiple domains and multiple host entries with this tool at the same time.

Using this would only make sense where both of the following items are true:
- Your ISP is changing your IP address from time to time, but you want to access your computer remotely every once in a while.
- You have domains operated & configured at Hetzner.

# Motivation
Changing IP addresses can be looked at as a necessary troll-getaway these days, I tend to like it. This (and cost obviously) stops me from upgrading my home network to business or paying extra for FIX IP.
I'm paying for my domains already, not going to pay extra for a dynamic DNS service, and I don't have the time or the motivation to keep looking for what's actually free and when to register. This is how and why I ended up with this awfulness.

# Quick rundown of what's happening inside
1. Grabs your WAN IP address (reported back by one of many whatismyip type services online).
2. Maintains a local copy of your Zone file in the data directory (creates if doesn't exist, updates with new data, etc). This is the first point where your WAN IP is validated against.
Using a local cache of your zone avoids hitting Hetzner every time you run this script.
3. When a host is not found locally, or WAN IP differs from IP in cached zone, your credentials will be used to login to Hetzner, fetch the DNS zone file for each domain, and update configured host IP information with your actual WAN address.
4. When an update happens, zone cache files are updated per domain.

# Prerequisites
1. You need to see your domain(s) in Hetzner Robot (robot.your-server.de), Konsoleh won't work.
2. Configuration will need your specific domain ID(s), you need to dig this out from the source here: https://robot.your-server.de/dns. Look for table onclick javascript code /dns/update/id/XXXXXX. You need to place the XXXXX (usually a 6-7 digit integer) to htz.config.php.
3. PHP 5.6 (gentoo) only at this point (needs curl, ssl, filter compile flags).
4. You may want to set your DNS TTL to some low value, I'm using $TTL 300 (shame on me).

# Configuration
1. Rename config.default.php to config.php
2. $htz_debug is set to false by default. It is recommended to set it to true for the first couple of manual runs to see what's happening exactly. Otherwise it's safe to keep off (will be quiet apart from hard dies).
3. $htz_user and $htz_pass hold the credentials to be used for authenticating to robot.your-server.de
4. $htz_data, $htz_data_ip, $htz_data_zone: data storage configuration. You can leave it as is, but make sure your data directory is writable by the user you use to execute this with (nginx/apache/phpfpm user, as you like). The script requires no elevated privileges.
5. $htz_allowed_domains holds multidimensional array configuration for your domains, domain_id and hosts you want to update. Structure is:
  'yourdomain.com' => array('domain_id', 'myhost')
And this should update yourdomain.com's
  myhost      IN A    123.456.789.012
registered IP address with your actual WAN IP.
More examples can be found in the config file.
6. $htz_myip_svc holds a list of whatismyip like services that provide you with your own WAN address. The script randomizes these, so a different one will be hit every time, and keeps on going until an IP address is found that passes IPv4 validation. There's a 10 seconds timeout, so in case some of these become unavailable over time, it won't cause an immediate impact.
Feel free to add more of these, or replace this array with your own IP provider script (e.g. put this into a PHP on server and hit it: echo <?php $\_SERVER['REMOTE_ADDR'];).
7. $htz_ntfy_push, $htz_ntfy_push_url, $htz_ntfy_push_appid, $htz_ntfy_push_usrid, $htz_ntfy_push_title, $htz_ntfy_push_prios: pushover integration. If you have an account at pushover.net and want to receive notifications after successful updates, you can configure your API keys here.
No other notification is implemented given Hetzner will send you an e-mail confirmation about these updates anyway.
8. $htz_url and $htz_usrag - you probably want to avoid touching these.

Oh, and don't forget to change $htz_go to true, otherwise the script will lol at your face.

From this point on, you should be able to run this commandline PHP, or via your local httpd (in this latter case, you may want to put a restriction for serving up .data files from /data.)

# Risks and known issues
- Hetzner's two factor authentication will prevent this from achieving anything. You may want to keep that turned OFF.
- Having multiple WAN interfaces can cause trouble.
- Running this script from multiple machines for the same domain can lead to crap should IP change be synchronized.
- Hetzner changes their web UI, this stops working (may take some time for me to up to latest).
- PHP 5.6 only, I didn't have the chance to test with earkuer or newer versions.
- Yeah I know the code is awful. But hey, this is a proto.
- Should you run into validation failures reported by one of these functions: htz_validate_login, htz_validate_dnspg, htz_validate_dnsup, stop using this script until an update is released. This is likely caused by Hetzner changing their UI and proceeding with items in this script can cause damage.
- It takes some time for Hetzner to register the update & show it via their website. Not waiting for this with this script, we assume Hetzner won't change / reject our submission after accepting our post.

# Legal
- This is a prototype (:hankey:) fire & forget project.
- Provided as-is, no guarantees of any kind, no warranty.
- Any damage this may directly or indirectly cause, is your fault.
- You have been warned.
