Zone-o-Matic
============

DNS API server for self-hosted DynDNS / ACME.

I use CoreDNS to serve my zones, unfortunately it does not support nsupdate protocol.
Hopefully is auto-reload modified zone file, so external service can update them.

This project aiming to provide DDNS API similar to *no-ip.com*,
so existing [ddns-scripts][ddns] can interact with it.

As a secondary feature it also provides API, which [acme-sh][acmesh] can use
to issue TLS certificates using `dns-01` challenge.

It also supports [LEGO HTTP-Request][legohttp] protocol for the same challenge.

You can use OpenWRT package from my feed: [vooon/my-openwrt-feed][owrtpkg].


Command line options
--------------------

```
Usage: zoneomatic --htpasswd=FILE --zone=FILE,... [flags]

DNS Zone file updater

Flags:
  -h, --help                        Show context-sensitive help.
      --listen="localhost:9999"     Server listen address ($ZM_LISTEN)
      --accept-proxy                Accept PROXY protocol ($ZM_ACCEPT_PROXY)
      --proxy-header-timeout=10s    Timeout for PROXY headers ($ZM_PROXY_HEADER_TIMEOUT)
  -p, --htpasswd=FILE               Passwords file (bcrypt only) ($ZM_HTPASSWD)
  -z, --zone=FILE,...               Zone files to update ($ZM_ZONE)
      --debug                       Enable debug logging ($ZM_DEBUG)
```

> [!NOTE]
> API description also available in OpenAPI 3 format on `/swagger`,
> e.g. http://localhost:9999/swagger


GET /myip
---------

Return client's IP Address in plain text.


GET /nic/update
---------------

Update A/AAAA records.

Required HTTP Headers:

| Name | Req | Description |
|------|-----|-------------|
| Authorization | Yes | HTTP Basic Auth |

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


POST /present
-------------

Update ACME DNS TXT record, in LEGO HTTP-request format.

Required HTTP Headers:

| Name | Req | Description |
|------|-----|-------------|
| Authorization | Yes | HTTP Basic Auth |

JSON Object fields:

| Name | Req | Description | Example |
|------|-----|-------------|---------|
| fqdn | Yes | Record name without `_acme-challenge.` | `foo.example.com` |
| value | Yes | Validation token content for the TXT record | `SomeRandomToken` |

See also: https://go-acme.github.io/lego/dns/httpreq/

> [!NOTE]
> Only HTTPREQ_MODE=default is supported


POST /cleanup
-------------

Remove ACME DNS TXT record, in LEGO HTTP-request format.

Required HTTP Headers:

| Name | Req | Description |
|------|-----|-------------|
| Authorization | Yes | HTTP Basic Auth |

JSON Object fields:

| Name | Req | Description | Example |
|------|-----|-------------|---------|
| fqdn | Yes | Record name without `_acme-challenge.` | `foo.example.com` |
| value | No | Validation token content for the TXT record, Ignored | `SomeRandomToken` |

See also: https://go-acme.github.io/lego/dns/httpreq/


POST /zm/update
---------------

Custom Zone-o-matic call.
Allow to update any existing record(s).
Match records by FQDN and type, then each value will be translated to a record.

Required HTTP Headers:

| Name | Req | Description |
|------|-----|-------------|
| Authorization | Yes | HTTP Basic Auth |

JSON Object fields:

| Name | Req | Description | Example |
|------|-----|-------------|---------|
| fqdn | Yes | Record domain name. | `foo.example.com` |
| type | Yes | Record type. | `NS` |
| values | Yes | List of records values | `["ns1", "ns2"]` |


GET /health
-----------

Health check endpoint.


[ddns]: https://openwrt.org/docs/guide-user/services/ddns/client
[acmesh]: https://openwrt.org/docs/guide-user/services/tls/acmesh
[legohttp]: https://go-acme.github.io/lego/dns/httpreq/
[owrtpkg]: https://github.com/vooon/my-openwrt-feed/tree/master/zoneomatic
