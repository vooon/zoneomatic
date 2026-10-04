# Zone-o-Matic

A small self-hosted service that **updates DNS zone files** on request.

Serve your zones from plain files (e.g. with [CoreDNS][coredns]'s `file`
plugin, which reloads them on change) and let zoneomatic be the write side:
routers update their addresses, ACME clients answer `dns-01` challenges,
cert-manager issues certificates, scripts and tools manage records, all
through protocols they already speak. The zone files stay yours: hand-written
comments are kept, and every write is verified before it lands.

## Features

| What | Protocol / API | Typical clients |
|------|----------------|-----------------|
| Dynamic DNS (A/AAAA, optional PTR) | no-ip style `GET /nic/update` | OpenWRT [ddns-scripts][ddns], routers, any DynDNS client |
| ACME `dns-01` challenges | acme-dns `POST /acme/update` | [acme.sh][acmesh] |
| | LEGO HTTP request `POST /present`, `/cleanup` | [lego][legohttp] and lego-based tools |
| | RFC2136 (DNS UPDATE) with TSIG | cert-manager `rfc2136` solver, `nsupdate` |
| Record management | PowerDNS API subset (`/api/v1`) | Proxmox SDN and other PowerDNS clients |
| | RFC2136 full-update listener | `nsupdate`, `knsupdate`, DNS tooling |
| | `POST /zm/update`, `/zm/update-ptr` | scripts |
| Observability | OpenTelemetry traces, metrics, logs | any OTLP collector |

An OpenWRT package is available in [vooon/my-openwrt-feed][owrtpkg].

## Quick start

A zone file needs a SOA record; its owner is the zone origin:

```dns
$ORIGIN example.com.
$TTL 300
@     IN SOA ns1.example.com. hostmaster.example.com. 1763822925 1H 10M 1W 1D
@     IN NS  ns1.example.com.
home  IN A   203.0.113.10   ; updated by the router
```

Users come from an htpasswd file with bcrypt hashes:

```bash
htpasswd -cbB ./htpasswd router 'secret'
zoneomatic --htpasswd ./htpasswd --zone ./example.com.zone --listen 0.0.0.0:9999
```

Serve the same file, e.g. with CoreDNS:

```text
example.com {
    file /etc/zoneomatic/example.com.zone {
        reload 10s
    }
}
```

Update a record:

```bash
curl -u router:secret "http://127.0.0.1:9999/nic/update?hostname=home.example.com&myip=203.0.113.20"
```

The HTTP API is also described in OpenAPI 3 format at `/swagger`
(e.g. http://localhost:9999/swagger).

## Integrations

### Routers and DynDNS clients

Point any no-ip compatible client at `/nic/update` (see the
[reference](#get-nicupdate)). Without `myip`/`myipv6` the client's address is
used. With `--ddns-manage-ptr` the matching reverse zones are updated too.

### acme.sh

Use the acme-dns plugin (`dns_acmedns`):

- `ACMEDNS_BASE_URL` — e.g. `https://nsapi.example.com/acme`
- `ACMEDNS_USERNAME`, `ACMEDNS_PASSWORD` — a user from the htpasswd file
- `ACMEDNS_SUBDOMAIN` — the domain you request the certificate for

### lego and lego-based tools

Use the `httpreq` provider in its default mode, with `HTTPREQ_ENDPOINT`
pointing at zoneomatic and `HTTPREQ_USERNAME`/`HTTPREQ_PASSWORD` from the
htpasswd file. It uses [`/present` and `/cleanup`](#post-present), which add
and remove single values, so a certificate for a name and its wildcard works.

### cert-manager

Enable the ACME listener with a TSIG key (see [TSIG keys](#tsig-keys)):

```bash
zoneomatic \
  --htpasswd ./htpasswd \
  --zone ./example.com.zone \
  --rfc2136-acme-listen 10.0.0.1:15353 \
  --rfc2136-acme-tsig-file /etc/zoneomatic/tsig.conf \
  --rfc2136-acme-allow 10.0.0.0/8
```

cert-manager's `rfc2136` solver runs inside the controller, so no webhook
deployment is needed. Point it at the ACME listener (tested with cert-manager
v1.21, see [Development](#development)):

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
```

The `tsig-key` value is the base64 secret from the key file (the `secret "..."`
content, without quotes). The `nameserver` may also be a hostname with port.

cert-manager checks that the challenge record is visible before asking the CA
to validate it. To run that check against your authoritative server instead of
public resolvers, set controller flags (Helm values):

```yaml
extraArgs:
  - --dns01-recursive-nameservers-only
  - --dns01-recursive-nameservers=10.0.0.2:53
```

cert-manager processes challenges for the same name one after another, so a
certificate for `example.com` and `*.example.com` takes two validation rounds.

See [RFC2136 listeners](#rfc2136-listeners) for the key file and the server
side.

### nsupdate and other DNS UPDATE tools

The full-update listener accepts changes to any record in the zones; give it
its own key:

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

### Proxmox SDN and PowerDNS clients

Configure a PowerDNS DNS plugin with the zoneomatic URL (`http://host:9999`)
and an API key of `base64(user:password)`; see
[PowerDNS-compatible API](#powerdns-compatible-api).

## Zone files

Each `--zone` file must contain a SOA record; its owner (resolved against
`$ORIGIN`) is the zone origin. Several `$ORIGIN` sections in one file are
supported.

On every change zoneomatic rewrites the whole file:

- **Comments are kept**, in every position: comment lines, at the end of a
  record, inside SOA or multi-line TXT parentheses. A replaced record keeps its
  comment; a deleted record takes its comment along.
- The **SOA serial is bumped**. Unix-time serials become the current time
  (always increasing, even for several changes within a second), `YYYYMMDDnn`
  serials are incremented. The serial line gets a date comment.
- The file is **re-laid out** in a compact, aligned format: owner names
  relative to `$ORIGIN`, values as written, blank lines kept. `$ORIGIN` is
  always written fully qualified.
- The result is **verified before it replaces the file**: it must contain
  exactly the intended records (checked with an independent parser,
  miekg/dns) and all comments. Otherwise the update fails and the file is left
  untouched. The file is replaced atomically.

The server that serves the zone (e.g. CoreDNS `file` plugin with `reload`)
picks up the change through the new serial.

### ACME challenge records

Challenge TXT records live at `_acme-challenge.<name>`. They are never removed
from the file; when no challenge is active the name holds a single
`"placeholder"` value:

- *present* replaces the placeholder with the token, or adds the token next to
  the others when another challenge for the same name is in flight (e.g. the
  apex and the wildcard of one certificate);
- *cleanup* removes the token and leaves exactly one placeholder once the last
  token is gone;
- names that are not in the zone yet are created on first use.

Challenge values must be ACME tokens (base64url: `A-Z a-z 0-9 - _`, as
RFC 8555 `dns-01` values are); anything else is rejected before the zone file
is touched. `--acme-ttl` sets the TTL of challenge records (default: the zone
`$TTL`).

To preview the layout of an existing file without changing it, use the bundled
formatter: `dnsfmt --no-inc example.com.zone` (`-r` rewrites in place).

## Reference

### Configuration

```
Usage: zoneomatic --zone=FILE,... --htpasswd=FILE [flags]

Updates DNS zone files on request: DDNS, ACME dns-01 (acme-dns, LEGO, RFC2136), PowerDNS-compatible API.

Flags:
  -h, --help       Show context-sensitive help.
      --debug      Enable debug logging ($ZM_DEBUG)
      --version    Print version and exit ($ZM_VERSION)

Zones
  -z, --zone=FILE,...      Zone files to manage (comma-separated or repeated); each needs a SOA record ($ZM_ZONE)
      --acme-ttl=0         TTL (seconds) of ACME challenge TXT records; 0 = zone $TTL ($ZM_ACME_TTL)
      --ddns-manage-ptr    On DDNS updates also update PTR records in matching reverse zones (skipped when none exists) ($ZM_DDNS_MANAGE_PTR)

HTTP API (DDNS, ACME, PowerDNS-compatible)
      --listen="localhost:9999"     HTTP API listen address ($ZM_LISTEN)
  -p, --htpasswd=FILE               htpasswd file with API users (bcrypt hashes only) ($ZM_HTPASSWD)
      --accept-proxy                Expect PROXY protocol headers (only behind a trusted proxy/LB) ($ZM_ACCEPT_PROXY)
      --proxy-header-timeout=10s    Timeout for reading PROXY protocol headers ($ZM_PROXY_HEADER_TIMEOUT)

RFC2136 ACME listener (only _acme-challenge TXT records, e.g. for cert-manager)
  --rfc2136-acme-listen=HOST:PORT    UDP and TCP listen address; empty disables the listener ($ZM_RFC2136_ACME_LISTEN)
  --rfc2136-acme-tsig-file=FILE      TSIG key file in BIND format (tsig-keygen output); required with listen ($ZM_RFC2136_ACME_TSIG_FILE)
  --rfc2136-acme-allow=CIDR,...      Allowed client CIDRs (comma-separated or repeated); empty allows all ($ZM_RFC2136_ACME_ALLOW)

RFC2136 full-update listener (any record in the zones)
  --rfc2136-update-listen=HOST:PORT    UDP and TCP listen address; empty disables the listener ($ZM_RFC2136_UPDATE_LISTEN)
  --rfc2136-update-tsig-file=FILE      TSIG key file in BIND format (tsig-keygen output); required with listen ($ZM_RFC2136_UPDATE_TSIG_FILE)
  --rfc2136-update-allow=CIDR,...      Allowed client CIDRs (comma-separated or repeated); empty allows all ($ZM_RFC2136_UPDATE_ALLOW)
  --rfc2136-update-max-ttl=0           Cap the TTL (seconds) of written records; 0 = use the TTL from the update ($ZM_RFC2136_UPDATE_MAX_TTL)

OpenTelemetry
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

#### OpenTelemetry

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

### PowerDNS-compatible API

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

### HTTP endpoints

#### GET /myip

Return client's IP Address in plain text.

Response status codes:

| Code | Meaning |
|------|---------|
| 200 | Success |
| 500 | Unexpected server error |

#### GET /nic/update

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

#### POST /acme/update

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
| txt | Yes | Validation token (base64url) for the TXT record | `SomeRandomToken` |

See also: https://github.com/joohoi/acme-dns

> [!NOTE]
> This call replaces all challenge values of the name with `txt`. To answer
> the apex and the wildcard of one
> certificate at the same time, use `/present`/`/cleanup` or RFC2136, which add
> and remove single values.

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
| 400 | Bad request (e.g. `txt` is not a valid ACME token) |
| 401 | Unauthorized |
| 404 | Zone not found |
| 500 | Unexpected server error |

#### POST /present

Add an ACME challenge TXT value, in LEGO HTTP-request format. Other values of
the same name are kept (see [ACME challenge records](#acme-challenge-records)).

Required HTTP Headers:

| Name | Req | Description |
|------|-----|-------------|
| Authorization | Yes | HTTP Basic Auth |

JSON Object fields:

| Name | Req | Description | Example |
|------|-----|-------------|---------|
| fqdn | Yes | Record name, with or without `_acme-challenge.` | `_acme-challenge.foo.example.com.` |
| value | Yes | Validation token (base64url) for the TXT record | `SomeRandomToken` |

See also: https://go-acme.github.io/lego/dns/httpreq/

> [!NOTE]
> Only HTTPREQ_MODE=default is supported

Response status codes:

| Code | Meaning |
|------|---------|
| 200 | Updated |
| 400 | Bad request (e.g. `value` is not a valid ACME token) |
| 401 | Unauthorized |
| 404 | Zone not found |
| 500 | Unexpected server error |

#### POST /cleanup

Remove an ACME challenge TXT value, in LEGO HTTP-request format.

Required HTTP Headers:

| Name | Req | Description |
|------|-----|-------------|
| Authorization | Yes | HTTP Basic Auth |

JSON Object fields:

| Name | Req | Description | Example |
|------|-----|-------------|---------|
| fqdn | Yes | Record name, with or without `_acme-challenge.` | `_acme-challenge.foo.example.com.` |
| value | No | Token to remove; other values of the name are kept. Empty resets the name to the placeholder. | `SomeRandomToken` |

See also: https://go-acme.github.io/lego/dns/httpreq/

Response status codes:

| Code | Meaning |
|------|---------|
| 200 | Updated |
| 400 | Bad request |
| 401 | Unauthorized |
| 404 | Zone not found |
| 500 | Unexpected server error |

#### POST /zm/update

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
| ttl | No | TTL for the records; omitted or `0` uses the zone `$TTL`. | `300` |
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

#### POST /zm/update-ptr

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

#### GET /health

Health check endpoint.

Response status codes:

| Code | Meaning |
|------|---------|
| 200 | Healthy |

### RFC2136 listeners

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

The ACME listener follows the [ACME challenge records](#acme-challenge-records)
rules: adding a TXT value presents a challenge, removing it cleans up, and
deleting the whole TXT RRset or name (`nsupdate`'s
`update delete _acme-challenge.example.com. [TXT]`) resets the name to a
single placeholder. Values that are not ACME tokens are refused (`REFUSED`).

On both listeners, every record must be inside the zone named in the update
(otherwise `NOTZONE`), and that zone must be one of the `--zone` files
(otherwise `NOTAUTH`).

#### TSIG keys

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

## Security

- Authentication uses htpasswd entries with bcrypt hashes.
- The server does not terminate TLS by itself; run it behind a reverse proxy
  with HTTPS.
- If you enable `--accept-proxy`, only expose the service behind a trusted
  proxy/LB.
- Updates can only touch the configured `--zone` files.

### RFC2136

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
- A key is not limited to certain names: anyone holding the ACME key can pass
  `dns-01` for any name in the configured zones, i.e. get certificates for
  them. Several clusters sharing one key can issue for each other's names.
- Treat the TSIG key file (and any Kubernetes Secret holding it) as sensitive: a
  leaked key allows updates within that key's scope.

## Development

```bash
go test ./...                                   # unit tests
go test -tags=e2e ./tests/e2e/...               # end-to-end: built binary, nsupdate/knsupdate if installed
go test ./internal/zone -update                 # rewrite zone golden files after a format change
go test ./internal/zone -run '^$' -fuzz FuzzZoneSave -fuzztime 5m
```

`pkg/dnsfmt` is a separate Go module: test it through a workspace
(`go work init . ./pkg/dnsfmt && go test ./pkg/dnsfmt/...`).

`make k3d` issues real certificates with cert-manager's `rfc2136` solver
against zoneomatic, Pebble and CoreDNS in a throwaway k3d cluster (needs
docker, k3d, kubectl, helm; `make k3d-clean` removes it). The cluster gets its
own kubeconfig file (`.k3d-kubeconfig`), the default kubectl context is never
used. CI runs the same targets.


[ddns]: https://openwrt.org/docs/guide-user/services/ddns/client
[acmesh]: https://openwrt.org/docs/guide-user/services/tls/acmesh
[legohttp]: https://go-acme.github.io/lego/dns/httpreq/
[owrtpkg]: https://github.com/vooon/my-openwrt-feed/tree/master/zoneomatic

[coredns]: https://coredns.io/plugins/file/
[ddns]: https://openwrt.org/docs/guide-user/services/ddns/client
[acmesh]: https://openwrt.org/docs/guide-user/services/tls/acmesh
[legohttp]: https://go-acme.github.io/lego/dns/httpreq/
[owrtpkg]: https://github.com/vooon/my-openwrt-feed/tree/master/zoneomatic
