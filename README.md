Zone-o-Matic
============

DNS API server for self-hosted DynDNS / ACME.

I use CoreDNS to serve my zones, unfortunately it does not support nsupdate protocol.
It does auto-reload modified zone files, so an external service can update them.

This project aims to provide DDNS API similar to *no-ip.com*,
so existing [ddns-scripts][ddns] can interact with it.

As a secondary feature it also provides API, which [acme-sh][acmesh] can use
to issue TLS certificates using `dns-01` challenge.

It also supports [LEGO HTTP-Request][legohttp] protocol for the same challenge.

You can use OpenWRT package from my feed: [vooon/my-openwrt-feed][owrtpkg].

Quick start
-----------

Start server:

```bash
zoneomatic --htpasswd ./htpasswd --zone ./example.com.zone --listen 0.0.0.0:9999
```

Update DDNS A record:

```bash
curl -u "user:password" \
  "http://127.0.0.1:9999/nic/update?hostname=host.example.com&myip=203.0.113.10"
```

Update ACME TXT with `acme-dns` compatible endpoint:

```bash
curl -u "user:password" \
  -H "Content-Type: application/json" \
  -d '{"subdomain":"host.example.com","txt":"SomeRandomToken"}' \
  "http://127.0.0.1:9999/acme/update"
```

Security notes
--------------

- Authentication uses htpasswd entries with bcrypt hashes.
- The server does not terminate TLS by itself; run it behind a reverse proxy with HTTPS.
- If you enable `--accept-proxy`, only expose the service behind a trusted proxy/LB.


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

Response status codes:

| Code | Meaning |
|------|---------|
| 200 | Success |
| 500 | Unexpected server error |


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

Response status codes:

| Code | Meaning |
|------|---------|
| 200 | Updated |
| 400 | Bad request (e.g. missing `hostname`, invalid IP) |
| 401 | Unauthorized |
| 404 | Zone not found |
| 500 | Unexpected server error |


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
> Original ACME-DNS uses `X-Api-User`/`X-Api-Key` style authentication and typically a
> per-record API key + CNAME alias flow.
> This implementation additionally accepts HTTP Basic Auth for simplicity.

> [!NOTE]
> For `acme.sh` option `ACMEDNS_BASE_URL` should be like that: `https://nsapi.example.com/acme`,
> `ACMEDNS_USERNAME` & `ACMEDNS_PASSWORD` - valid user in htpasswd file,
> `ACMEDNS_SUBDOMAIN` - base domain name for which you are requesting certificate.

Auth examples:

`Authorization: Basic ...` mode:

```bash
curl -u "user:password" \
  -H "Content-Type: application/json" \
  -d '{"subdomain":"foo.example.com","txt":"SomeRandomToken"}' \
  "http://127.0.0.1:9999/acme/update"
```

`X-Api-User`/`X-Api-Key` mode:

```bash
curl \
  -H "X-Api-User: user" \
  -H "X-Api-Key: password" \
  -H "Content-Type: application/json" \
  -d '{"subdomain":"foo.example.com","txt":"SomeRandomToken"}' \
  "http://127.0.0.1:9999/acme/update"
```

Response status codes:

| Code | Meaning |
|------|---------|
| 200 | Updated |
| 400 | Bad request |
| 401 | Unauthorized |
| 404 | Zone not found |
| 500 | Unexpected server error |


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

Response status codes:

| Code | Meaning |
|------|---------|
| 200 | Updated |
| 400 | Bad request |
| 401 | Unauthorized |
| 404 | Zone not found |
| 500 | Unexpected server error |


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

Response status codes:

| Code | Meaning |
|------|---------|
| 200 | Updated |
| 400 | Bad request |
| 401 | Unauthorized |
| 404 | Zone not found |
| 500 | Unexpected server error |


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
| type | Yes | Record type, case-insensitive. | `NS` |
| values | Yes | List of records values | `["ns1", "ns2"]` |

> [!NOTE]
> `POST /zm/update` updates existing records only. If no matching record exists, it returns an error.

Response status codes:

| Code | Meaning |
|------|---------|
| 200 | Updated |
| 400 | Bad request |
| 401 | Unauthorized |
| 404 | Zone not found |
| 500 | Unexpected server error |


GET /health
-----------

Health check endpoint.

Response status codes:

| Code | Meaning |
|------|---------|
| 200 | Healthy |


dnsfmt behavior
---------------

- Multi-part `TXT` records are kept in parenthesized multiline form.
- `TLSA` records are kept on a single line.


[ddns]: https://openwrt.org/docs/guide-user/services/ddns/client
[acmesh]: https://openwrt.org/docs/guide-user/services/tls/acmesh
[legohttp]: https://go-acme.github.io/lego/dns/httpreq/
[owrtpkg]: https://github.com/vooon/my-openwrt-feed/tree/master/zoneomatic
