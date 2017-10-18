# Hetzner-DynDNS
(Updated to follow UI changes at Hetzner).

This tool allows you to push new IP addresses to a range of domains you have configured at Hetzner.de.
Once configured, multiple domains and hosts can be updated in a single call.

Using this would make sense when the following statements are true:
- You have a dynamic IP at your ISP, but want to access your host.
- You have domains operated & configured at Hetzner.
- You've had enough of dyndns, no-ip and alike constanty looking for your  pocket.

# Quick rundown of what's happening inside
Unfortunately Hetzner doesn't provide a real API to their DNS Robot. The do provide an e-mail interface, but that comes with more limitation than a level of UI automation, so here goes.
The following things happen when you run this:
1. Grabbing your WAN IP address (reported back by one of many whatismyip type services; but you can use your own, of course).
2. Maintains a local copy of your Zone file in the data directory. This serves as first point of WAN IP validation, and avoids hitting hetzner unnecessarily.
3. When a host is not found locally, or WAN IP differs from IP in cached zone, a set of curl commends ensure that you login to hetzner's DNS robot (with your robot.your-server.de credentials), compare DNS zone files with your local copies, and update configured host IPs as required.
4. When an update happens, zone cache files are updated per domain.

# Prerequisites
1. You need to see your domain(s) in Hetzner Robot (robot.your-server.de), Konsoleh won't work.
2. Configuration will need your specific domain ID(s), you need to dig this out from the source here: https://robot.your-server.de/dns. Look for table onclick javascript code /dns/update/id/XXXXXX. You need to place the XXXXX (usually a 6-7 digit integer) to htz.config.php.
3. PHP 5.6 and 7.0 only at this point (needs curl, ssl, filter compile flags).
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
- Hetzner changes their web UI, this stops working (like they did on Oct 16/17, 2017; it may take some time to update, test and push to this repo).
- Should you run into validation failures reported by one of these functions: htz_validate_login, htz_validate_dnspg, htz_validate_dnsup, stop using this script until an update is released. This is likely caused by Hetzner changing their UI and proceeding with items in this script can cause damage.
- It takes up to a minute for Hetzner to register the update & show it via their website. Not waiting for this with this script, we assume Hetzner won't change / reject our submission after accepting our post.

# Legal
- This is a prototype (:hankey:) fire & forget project.
- Provided as-is, no guarantees of any kind, no warranty.
- Any damage this may directly or indirectly cause, is your fault.
- You have been warned.
