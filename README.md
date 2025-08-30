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


GET /nic/update
---------------

Update A/AAAA records.

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


POST /acme/update
-----------------

Update ACME DNS TXT records.

Required HTTP Headers:

| Name | Req | Description |
|------|-----|-------------|
| X-Api-User | Yes* | Username from the htpasswd file |
| X-Api-Key | Yes* | Password from the htpasswd file |
| Authorization | Yes* | HTTP Basic Auth, alternative to pair above |

JSON Object fields:

| Name | Req | Description | Example |
|------|-----|-------------|---------|
| subdomain | Yes | Record name without `_acme-challenge.`, *not a UUID* | `foo.example.com` |
| txt | Yes | Validation token content for the TXT record | `SomeRandomToken` |

See also: https://github.com/joohoi/acme-dns

> [!NOTE]
> Original ACME-DNS suppose to register custom API key for each record, then use CNAME alias.
> So in general more secure approach.

> [!NOTE]
> For `acme.sh` option `ACMEDNS_BASE_URL` should be like that: `https://nsapi.example.com/acme`,
> `ACMEDNS_USERNAME` & `ACMEDNS_PASSWORD` - valid user in htpasswd file,
> `ACMEDNS_SUBDOMAIN` - base domain name for which you requesting certificate.


GET /health
-----------

Health check endpoint.
