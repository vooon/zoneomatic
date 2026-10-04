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

OpenTelemetry
-------------

OpenTelemetry supports three explicit signals:

- `--otel-enable-traces`
- `--otel-enable-metrics`
- `--otel-enable-logs`

Use `--otel-endpoint` as a shared endpoint for enabled signals (recommended with OTEL Collector).
If needed, override per signal with `--otel-traces-endpoint`, `--otel-metrics-endpoint`, `--otel-logs-endpoint`.
You can enable any subset, or all three at once.

- Service name defaults to `zoneomatic`; override with `--otel-service-name`.
- Add custom HTTP headers (e.g. for authentication) with `--otel-header Key=Value` (repeatable, or via `ZM_OTEL_HEADER`).
- Control the minimum log level forwarded to the OTEL receiver with `--otel-logs-level` (`debug`|`info`|`warn`|`error`). Useful when you want quieter console output but richer data in the collector.

Example:

```bash
zoneomatic \
  --htpasswd ./htpasswd \
  --zone ./example.com.zone \
  --otel-endpoint http://127.0.0.1:4318 \
  --otel-enable-traces \
  --otel-enable-metrics \
  --otel-enable-logs \
  --otel-logs-level debug \
  --otel-header "Authorization=Bearer mytoken" \
  --otel-service-name zoneomatic-prod
```


Command line options
--------------------

```
Usage: zoneomatic --htpasswd=FILE --zone=FILE,... [flags]

DNS Zone file updater

Flags:
  -h, --help                              Show context-sensitive help.
      --listen="localhost:9999"           Server listen address ($ZM_LISTEN)
      --accept-proxy                      Accept PROXY protocol ($ZM_ACCEPT_PROXY)
      --proxy-header-timeout=10s          Timeout for PROXY headers ($ZM_PROXY_HEADER_TIMEOUT)
  -p, --htpasswd=FILE                     Passwords file (bcrypt only) ($ZM_HTPASSWD)
  -z, --zone=FILE,...                     Zone files to update ($ZM_ZONE)
      --acme-ttl=0                        TTL (seconds) for ACME challenge TXT records; 0 = use zone $TTL ($ZM_ACME_TTL)
      --ddns-manage-ptr                   Update PTR records in matching reverse zones on DDNS update; missing reverse zone is ignored ($ZM_DDNS_MANAGE_PTR)
      --rfc2136-acme-listen=STRING          Listen address for RFC2136 dynamic updates (host:port); empty disables the listener ($ZM_RFC2136_ACME_LISTEN)
      --rfc2136-acme-tsig-file=FILE         BIND-format TSIG key file (as produced by tsig-keygen); required when listen is set ($ZM_RFC2136_ACME_TSIG_FILE)
      --rfc2136-acme-allow=CIDR,...         Allowed client CIDRs (comma-separated or repeated); empty allows all ($ZM_RFC2136_ACME_ALLOW)
      --rfc2136-update-listen=STRING        Listen address for RFC2136 dynamic updates (host:port); empty disables the listener ($ZM_RFC2136_UPDATE_LISTEN)
      --rfc2136-update-tsig-file=FILE       BIND-format TSIG key file (as produced by tsig-keygen); required when listen is set ($ZM_RFC2136_UPDATE_TSIG_FILE)
      --rfc2136-update-allow=CIDR,...       Allowed client CIDRs (comma-separated or repeated); empty allows all ($ZM_RFC2136_UPDATE_ALLOW)
      --rfc2136-update-max-ttl=0            Cap the TTL (seconds) of records written through the full-update listener; 0 = honor the update packet TTL ($ZM_RFC2136_UPDATE_MAX_TTL)
      --debug                             Enable debug logging ($ZM_DEBUG)
      --version                           Print version and exit ($ZM_VERSION)
      --otel-endpoint=URL                 Shared OTLP/HTTP endpoint URL for enabled signals (typically collector URL) ($ZM_OTEL_ENDPOINT)
      --otel-header=KEY=VALUE;...         Additional HTTP headers for all OTLP exporters, repeatable (e.g. Authorization=Bearer token) ($ZM_OTEL_HEADER)
      --otel-enable-traces                Enable OpenTelemetry traces signal ($ZM_OTEL_ENABLE_TRACES)
      --otel-traces-endpoint=URL          OTLP/HTTP traces endpoint URL (e.g. http://127.0.0.1:4318/v1/traces) ($ZM_OTEL_TRACES_ENDPOINT)
      --otel-enable-metrics               Enable OpenTelemetry metrics signal ($ZM_OTEL_ENABLE_METRICS)
      --otel-metrics-endpoint=URL         OTLP/HTTP metrics endpoint URL (e.g. http://127.0.0.1:4318/v1/metrics) ($ZM_OTEL_METRICS_ENDPOINT)
      --otel-enable-logs                  Enable OpenTelemetry logs signal ($ZM_OTEL_ENABLE_LOGS)
      --otel-logs-endpoint=URL            OTLP/HTTP logs endpoint URL (e.g. http://127.0.0.1:4318/v1/logs) ($ZM_OTEL_LOGS_ENDPOINT)
      --otel-logs-level=""                Minimum log level forwarded to OTLP (debug|info|warn|error); defaults to same as console ($ZM_OTEL_LOGS_LEVEL)
      --otel-service-name="zoneomatic"    OpenTelemetry service name ($ZM_OTEL_SERVICE_NAME)
```

> [!NOTE]
> API description also available in OpenAPI 3 format on `/swagger`,
> e.g. http://localhost:9999/swagger


PowerDNS-Compatible API
-----------------------

Zone-o-matic exposes a PowerDNS-compatible API subset under `/api/v1`.
It is intended for clients that only need server discovery plus read/update access to existing zones,
such as Proxmox SDN.

Authentication:

- `X-API-Key` must contain base64-encoded `user:password`, using credentials from the htpasswd file.
- Regular HTTP Basic Auth with the same credentials is also accepted.
- The only server id is `localhost`.

Implemented operations:

- `GET /api/v1/servers`
- `GET /api/v1/servers/localhost`
- `GET /api/v1/servers/localhost/zones`
- `GET /api/v1/servers/localhost/zones/{zone_id}`
- `PATCH /api/v1/servers/localhost/zones/{zone_id}`

Notes:

- `PATCH` supports RRSet `REPLACE` and `DELETE` changes.
- Zone operations work on already configured zone files only; creating new zones through the API is not supported.
- Unsupported PowerDNS-compatible endpoints currently return `501 Not Implemented`.
- Other PowerDNS API areas such as config, metadata, export, search, and AXFR retrieval are not implemented.

`X-API-Key` example:

```bash
curl \
  -H "X-API-Key: $(printf 'user:password' | base64 -w0)" \
  "http://127.0.0.1:9999/api/v1/servers"
```


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

> [!NOTE]
> With `--ddns-manage-ptr` the matching reverse zones (`in-addr.arpa` / `ip6.arpa`)
> are updated too: each of the current addresses gets a single PTR record pointing
> to the hostname, and any stale PTR pointing to it from other addresses is removed.
> If no suitable reverse zone exists for an address, it is silently skipped.

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


POST /zm/update-ptr
-------------------

Custom Zone-o-matic call.
Update PTR records in matching reverse zones for the requested addresses, pointing them to the target host.
Reverse names (`in-addr.arpa` / `ip6.arpa`) are calculated from the addresses automatically.

Required HTTP Headers:

| Name | Req | Description |
|------|-----|-------------|
| Authorization | Yes | HTTP Basic Auth |

JSON Object fields:

| Name | Req | Description | Example |
|------|-----|-------------|---------|
| target | Yes | Hostname the addresses should resolve back to. | `hub.example.com.` |
| addresses | Yes | List of IP addresses to manage PTR records for. | `["192.0.2.55","2001:db8::1"]` |
| mode | No | PTR update mode: `append`, `replace` or `replace-all`. Defaults to `replace-all`. | `replace-all` |

`mode` semantics:

- `append` — add a PTR record only if it is missing, never remove anything.
- `replace` — set a single PTR record for each requested address in place, keeping
  unrelated PTR records on the same name.
- `replace-all` — fully sync the target: exactly one PTR record per requested
  address, and any other PTR pointing to the target that is no longer in the
  address list is removed (e.g. after the host moved to a new address).

> [!NOTE]
> Unlike `--ddns-manage-ptr`, this call returns `404` when no matching reverse
> zone exists for one of the addresses.

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


RFC2136 dynamic updates
-----------------------

Zone-o-matic can accept standard RFC2136 (DNS UPDATE) messages, so tools such as
`nsupdate` and cert-manager's built-in `rfc2136` solver can update records
directly, without any extra webhook component.

Two independent listeners can be enabled; each one is off unless its listen
address is set and requires a TSIG key file:

| Listener | Flag | Scope |
|----------|------|-------|
| ACME dns-01 | `--rfc2136-acme-listen` | only `_acme-challenge.*` TXT records |
| Full update | `--rfc2136-update-listen` | any record in configured zones |

Both listeners serve UDP and TCP on the same address.

On the ACME listener, adding a TXT value replaces the placeholder, removing a
value puts the placeholder back, and deleting the whole TXT RRset or name
(`nsupdate`'s `update delete _acme-challenge.example.com. [TXT]`) resets the
name to a single placeholder instead of removing it from the zone file.

### TSIG keys

Keys are read from a BIND-style key file, exactly as produced by `tsig-keygen`
(part of BIND). Multiple keys may be present in one file.

```bash
tsig-keygen -a hmac-sha256 certmanager.example.com > /etc/zoneomatic/tsig.conf
```

```text
key "certmanager.example.com" {
	algorithm hmac-sha256;
	secret "YlZQY3QDIVu4vaD+7ZXhCQJ0NOn35EIvPrR52PP14kQ=";
};
```

The algorithm is pinned per key: a client that signs with a different algorithm
is rejected.

### Example: full update listener

```bash
zoneomatic \
  --htpasswd ./htpasswd \
  --zone ./example.com.zone \
  --rfc2136-update-listen 10.0.0.1:15353 \
  --rfc2136-update-tsig-file /etc/zoneomatic/tsig.conf \
  --rfc2136-update-allow 10.0.0.0/8 \
  --rfc2136-update-max-ttl 300
```

With `--rfc2136-update-max-ttl 300`, records written through this listener
inherit the packet TTL, but are capped to 300 seconds when the packet TTL is
larger (or absent). By default (`0`) the packet TTL is honored as-is.

`nsupdate` example:

```bash
nsupdate -k /etc/zoneomatic/tsig.conf
> server 10.0.0.1 15353
> zone example.com
> update add host.example.com 60 A 192.0.2.10
> send
```

### Example: cert-manager (DNS-01 via rfc2136)

cert-manager's `rfc2136` solver runs inside the controller, so no webhook
deployment is needed. Point it at the ACME listener and, optionally, restrict
the propagation self-check to your authoritative nameserver:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: zoneomatic-tsig
  namespace: cert-manager
stringData:
  tsig-key: YlZQY3QDIVu4vaD+7ZXhCQJ0NOn35EIvPrR52PP14kQ=
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-rfc2136
spec:
  acme:
    email: admin@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-rfc2136-account-key
    solvers:
      - dns01:
          rfc2136:
            nameserver: 10.0.0.1:15353
            tsigKeyName: certmanager.example.com
            tsigAlgorithm: HMACSHA256
            tsigSecretSecretRef:
              name: zoneomatic-tsig
              key: tsig-key
          # Optional: query the authoritative server for the self-check
          # instead of public resolvers.
          # nameservers:
          #   - 10.0.0.2:53
```

The `tsig-key` value is the base64 secret from the key file (the `secret "..."`
content, without quotes).

### Security notes

RFC2136 with TSIG provides **authentication and integrity, but not
confidentiality** — the update payload (record names and values, including ACME
tokens) is sent in the clear. It also has **no protection against replay** beyond
the TSIG fudge window (300 seconds by default), which requires synchronized
clocks.

Therefore:

- **Bind to a private interface** (e.g. a VPN/WireGuard address) and do not
  expose these listeners to the public internet. Use `--rfc2136-*-allow` as a
  defense-in-depth allowlist.
- Keep clocks synchronized (NTP); large skew causes `BADTIME` failures.
- Prefer SHA-2 algorithms (`hmac-sha256`/`hmac-sha512`); the server pins the
  algorithm per key and rejects mismatches.
- The blast radius is limited: only pre-configured `--zone` files are writable,
  and the ACME listener additionally accepts only `_acme-challenge.*` TXT
  records.
- Use separate keys for the ACME and full-update listeners, and rotate by
  adding a new key and pointing clients at it.
- Treat the TSIG key file (and any Kubernetes Secret holding it) as sensitive: a
  leaked key allows updates within that key's scope.


dnsfmt behavior
---------------

- Multi-part `TXT` records are kept in parenthesized multiline form.
- `TLSA` records are kept on a single line.


[ddns]: https://openwrt.org/docs/guide-user/services/ddns/client
[acmesh]: https://openwrt.org/docs/guide-user/services/tls/acmesh
[legohttp]: https://go-acme.github.io/lego/dns/httpreq/
[owrtpkg]: https://github.com/vooon/my-openwrt-feed/tree/master/zoneomatic
