# Cyrillic domain blocking

Opt-in filter for DNS names that contain Cyrillic characters. It is **disabled by default**. With the option off, Pi-hole answers queries exactly as it does today.

Internationalized domain names arrive on the wire as punycode (`xn--...`). This feature decodes those labels and blocks the query when any code point is Cyrillic. That is a deliberate, narrower stand-in for NextDNS's "block IDNs that impersonate other domains with look-alike characters." Pi-hole cannot reliably decide whether one name visually mimics another, so the switch blocks every Cyrillic name instead of guessing.

## What this repository implements

This repository is Pi-hole core (installer, `pihole` CLI, gravity). Live DNS queries are handled in FTL. Core therefore provides:

- The config key `dns.blocking.cyrillic` (boolean, default `false`).
- `pihole cyrillic` to read it, write it, and check a name locally.
- A reference detector in `advanced/Scripts/cyrillic.sh`, covered by `test/test_cyrillic.bats`.
- `pihole -t` coloring for the log phrase `cyrillic blocked`, and a debug-log line for the setting.

`pihole cyrillic check` works on any install. `pihole cyrillic on` and `off` call `pihole-FTL --config`. Stock FTL rejects unknown keys and then rewrites `pihole.toml` from its own schema, dropping anything it does not know. Until FTL learns this key, `on` and `off` fail and the effective state stays disabled. On those builds, leave `pihole.toml` unchanged: FTL rewrites the file from its schema and drops unknown keys.

## Enable the option

After FTL accepts the key:

```bash
sudo pihole cyrillic on
pihole cyrillic status
sudo pihole cyrillic off
```

Equivalent interfaces, once FTL implements them:

```toml
[dns.blocking]
  cyrillic = true
```

```bash
sudo pihole-FTL --config dns.blocking.cyrillic true
```

```yaml
environment:
  FTLCONF_dns_blocking_cyrillic: "true"
```

An environment variable makes the value read-only, same as every other `FTLCONF_*` setting.

Check a name without changing settings. Exit status is 0 on a match, 1 when there is no match, and 2 on a usage error.

```bash
pihole cyrillic check xn--e1afmkfd.com
pihole cyrillic check example.com
```

`check` accepts punycode and raw UTF-8.

## Detection

A domain matches when any label contains a code point in one of these blocks:

| Block | Range |
| --- | --- |
| Cyrillic | U+0400–U+04FF |
| Cyrillic Supplement | U+0500–U+052F |
| Cyrillic Extended-A | U+2DE0–U+2DFF |
| Cyrillic Extended-B | U+A640–U+A69F |
| Cyrillic Extended-C | U+1C80–U+1C8F |

Rules implemented by `domain_contains_cyrillic`:

1. Strip trailing DNS dots and split on `.`.
2. A label whose ASCII form starts with `xn--` (any case) is punycode. Decode the remainder with RFC 3492 and test the resulting code points. Punycode digits are case-insensitive. A label that does not decode is not treated as Cyrillic.
3. Any other label is scanned as UTF-8, so `pihole cyrillic check` accepts a name typed in Unicode. Invalid UTF-8 is ignored.
4. Other IDNs are allowed. `xn--mnchen-3ya.de` (münchen) and `xn--fiqs8s` (中国) do not match. A single Cyrillic letter does: `xn--ggle-55da.com` is the look-alike of `google.com` that uses Cyrillic `о`.

Blocking every `xn--` name would also block Chinese, Arabic, and German IDNs. A denylist regex cannot decode punycode, so this cannot be expressed as a gravity or regex entry.

FTL lowercases and converts queries to punycode before list checks. The query-path implementation only needs to decode ACE labels. The UTF-8 scan exists for CLI input that has not been normalized.

## Required FTL change

Query blocking, the reply packet, and the query-log row all belong in [pi-hole/FTL](https://github.com/pi-hole/FTL). Suggested contract, matching the other `dns.blocking` options:

1. Add `dns.blocking.cyrillic` as a `CONF_BOOL` on the `dns.blocking` struct in `src/config/config.c` / `src/config/config.h`. Help text should state that the default is false and that a match is any Cyrillic code point in the blocks above, after punycode decoding. Default `false`. FTL's TOML writer will then document the key in `pihole.toml`. The API (`GET`/`PATCH /api/config`) and `FTLCONF_dns_blocking_cyrillic` follow from the existing config machinery.
2. When `dns.blocking.active` and `dns.blocking.cyrillic` are both true, test the name at the same point FTL already decides gravity, denylist, and regex blocks (the path that calls `query_blocked()`). Decode each `xn--` label. On a match, block through `query_blocked()` so the answer uses `dns.blocking.mode` (NULL, NXDOMAIN, NODATA, IP, IP-NODATA-AAAA) and the configured `dns.blocking.edns` info.
3. Exact and regex allow entries must still win, including along a CNAME chain, the same way they win over gravity. Also test CNAME targets, consistent with `QUERY_GRAVITY_CNAME`.
4. Append a new status **before** `QUERY_STATUS_MAX` in `src/enums.h`. Do not renumber existing values; the query database stores them as integers. Current tail of the enum:

   ```c
   QUERY_EXTERNAL_BLOCKED_EDE15,
   QUERY_CYRILLIC,
   QUERY_STATUS_MAX
   ```

   String returned by `get_query_status_str()`: `CYRILLIC`.
5. Include `QUERY_CYRILLIC` in `is_blocked()` and `get_blocked_statuslist()` so the dashboard, "blocked" filters, and client/domain counters count it. dnsmasq log line, same shape as gravity, so `pihole -t` colors it:

   ```text
   cyrillic blocked <domain> is 0.0.0.0
   ```

   EDNS text, same shape as gravity's `(gravity)`: `(cyrillic)`.
6. Add an FTL test that, with the option on, `xn--e1afmkfd.example` (пример) is answered in the configured blocking mode and logged as `CYRILLIC`, `xn--mnchen-3ya.example` is forwarded, an allowlisted Cyrillic name is forwarded, and with the option off both names are forwarded.

Core's bash decoder is a reference for those tests. FTL should call the IDN library it already uses, not this shell script.

## Required web interface change

The v6 settings pages are explicit markup, not a full dump of the config schema. [pi-hole/web](https://github.com/pi-hole/web) needs:

- A checkbox on the DNS settings page (`settings-dns.lp`) bound with `data-key="dns.blocking.cyrillic"`, next to the other blocking controls, described as off by default.
- Query-log rendering for status `CYRILLIC` as a blocked query (for example "Blocked (Cyrillic)"), included in the blocked-status filter alongside `GRAVITY`, `REGEX`, and `DENYLIST`.

Once FTL exposes the key, `PATCH /api/config` can set it even before that checkbox exists.
