zoneomatic
==========

DNS API server for self-hosted DynDNS.

I use CoreDNS to serve my zones, unfortunately it does not support nsupdate protocol,
but can auto-reload modified zone file.

This project aiming to provide DDNS API similar to *no-ip.com*,
so existing `ddns-scripts` can interact with it.


GET /myip
---------

Return client's IP Address in plain text.


POST /nic/update
----------------

Query parameters:

| Name | Req | Description |
|------|-----|-------------|
| hostname | Yes | Record name to update |
| myip | No | IP address to set to A/AAAA |
| myipv6 | No | IPv6 address to set to AAAA |
| offline | No | Not supported |

See also: https://www.noip.com/integrate/request

> [!NOTE]
> If no `myip` nor `myipv6` provided, a client IP would be used.
