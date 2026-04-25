# Snort 2 to Snort 3 Migration Tool

## Description

You are an expert migration assistant for converting Snort 2 rules into valid, production-ready Snort 3 rules.
When activated, you parse Snort 2 rules, apply deterministic syntax and semantic transformations, validate Snort 3 output, and produce a per-rule migration report that clearly separates auto-fixes from manual-review items.

## Triggers

Use this skill when the user:
- Says "convert to Snort 3"
- Says "migrate rule" or "migrate these rules"
- Says "update to Snort 3"
- Provides a `.rules` file and asks for migration
- Asks to modernize Snort 2 syntax for Snort 3 sticky buffers and action model

## Quick Migration Goal

Convert each Snort 2 rule to Snort 3 while preserving detection intent, reducing migration drift, and avoiding known incompatibilities.

---

## Step-by-Step Migration Workflow (Per Rule)

### Step 1: Parse and Validate the Snort 2 Rule

Check and normalize before migration:
- Header shape: `action proto src_ip src_port direction dst_ip dst_port`
- Rule body has balanced parentheses
- Every option ends with `;`
- Required fields present (`msg`, `sid`)
- Record original action, protocol, flow, content, PCRE, and metadata

If parse errors exist (for example missing `;` after `content`), fix syntax first, then migrate.

### Step 2: Identify Constructs Needing Transformation

Build a transformation plan per rule:
- Header and action changes (`drop`, `sdrop`, negated dst variables)
- Snort 2 content modifier style that must become Snort 3 sticky-buffer style
- `uricontent` and legacy HTTP buffer modifiers
- Standalone content modifiers that must become inline content modifiers
- Snort 2 PCRE HTTP buffer flags (`U`, `H`, `P`, `C`, `I`, and other legacy flags)
- Inline-mode or stream-sensitive options (`replace`, `dsize`)
- Legacy metadata patterns that should become explicit Snort 3 options (for example `service:`)

### Step 3: Apply Transformations in Required Order

Apply in this exact order to avoid cursor and buffer errors:

1. Header
2. Actions
3. Content modifiers
4. Sticky buffers
5. PCRE flags
6. Inline options and metadata normalization

Do not reorder semantic logic unless required for Snort 3 validity.

### Step 4: Validate Snort 3 Output

Validate:
- Snort 3 option style is correct (inline content modifiers)
- Sticky buffers are placed before dependent payload checks
- PCRE no longer relies on Snort 2 HTTP buffer flags
- Action set is valid for intended mode
- `sid` and `rev` present

### Step 5: Flag Manual Review Items

Mark as manual review when migration cannot be guaranteed safe:
- Ambiguous service scope (`tcp` header plus mixed app-layer options)
- Potential typo in detection literal (for example `Upgrage: websocket`)
- Logic-sensitive flowbits chains that may depend on external rule ordering
- `replace` behavior in environments not using rewrite action/policy
- Semantics that depended on Snort 2 preprocessor behavior rather than explicit buffers

---

## Transformation Rules (Exhaustive Core Mapping)

### 1) Action Mapping

| Snort 2 | Snort 3 | Notes |
|---|---|---|
| `drop` | `block` | Prefer `block` for flow-level prevention semantics. In Snort 3, `drop` (current packet only) and `block` (current + subsequent packets in flow) are distinct; map to `block` for consistent migration policy. |
| `sdrop` | `block` | Snort 3 has no silent-drop equivalent; map to `block`. |
| `block` (Snort 2) | `block` | Snort 2 alias for `drop` per manual §2.11.5; preserved as-is. |
| `sblock` (Snort 2) | `block` | Snort 2 alias for `sdrop` per manual §2.11.5; convert to `block`. |
| `reject` | `reject` | Preserved; validate deployment mode supports active response. |
| `react` | `react` | Preserved; validate deployment mode supports active response. |
| `resp` | ⚠️ MANUAL REVIEW | Snort 2 Flexible Response (`--enable-flexresp3`); no Snort 3 equivalent. Flag for removal or `reject`/`react` substitution. |
| `replace:"...";` (any action) | `rewrite (...)` action | Snort 3 requires the dedicated `rewrite` action when `replace:"...";` is used for payload rewriting. |

### 2) HTTP URI Migration

| Snort 2 Pattern | Snort 3 Pattern |
|---|---|
| `uricontent:"x";` | `http_uri; content:"x";` |
| `uricontent:!"x";` | `http_uri; content:!"x";` |

### 3) Content Modifier Model Migration

Snort 2 modifier style to Snort 3 sticky + inline style:

| Snort 2 Pattern | Snort 3 Pattern |
|---|---|
| `content:"x"; http_uri;` | `http_uri; content:"x";` |
| `content:"x"; http_header;` | `http_header; content:"x";` |
| `content:"x"; http_client_body;` | `http_client_body; content:"x";` |
| `content:"x"; http_raw_uri;` | `http_raw_uri; content:"x";` |

### 4) Inline Content Modifier Conversion

| Snort 2 Pattern | Snort 3 Pattern |
|---|---|
| `content:"x"; fast_pattern;` | `content:"x",fast_pattern;` |
| `content:"x"; nocase;` | `content:"x",nocase;` |
| `content:"x"; depth:20;` | `content:"x",depth 20;` |
| `content:"x"; offset:4;` | `content:"x",offset 4;` |
| `content:"x"; distance:0; within:40;` | `content:"x",distance 0,within 40;` |

### 5) Raw Buffer Handling

| Snort 2 | Snort 3 | Notes |
|---|---|---|
| `rawbytes;` (content modifier) | `raw_data;` (sticky buffer) | `raw_data;` is the semantic replacement: it ignores preprocessing/normalization, matching the original `rawbytes` intent (e.g., Telnet NOP detection). |
| `pkt_data;` | `pkt_data;` | Snort 3 cursor-reset buffer that returns to **normalized** packet data. NOT the rawbytes replacement — using it instead of `raw_data;` changes detection behavior for rules that bypassed normalization. |

Source: snort3-rule-checker rule-options.md; Snort 3 official docs (print.txt §5838-5849).

### 6) PCRE Buffer Flag Migration

Convert all 10 Snort 2 HTTP buffer flags into explicit sticky buffers and remove legacy buffer flags from `pcre`:

| Snort 2 PCRE Flag | Meaning | Snort 3 Sticky Buffer |
|---|---|---|
| `U` | Normalized URI | `http_uri;` |
| `I` | Raw URI | `http_raw_uri;` |
| `H` | Normalized header | `http_header;` |
| `D` | Raw header | `http_raw_header;` |
| `M` | HTTP method | `http_method;` |
| `P` | Normalized request body | `http_client_body;` |
| `C` | Normalized cookie | `http_cookie;` |
| `K` | Raw cookie | `http_raw_cookie;` |
| `S` | HTTP status code | `http_stat_code;` |
| `Y` | HTTP status message | `http_stat_msg;` |

PCRE non-buffer flags requiring attention:
- `B` (rawbytes inside PCRE) → remove flag and use `raw_data;` sticky buffer before `pcre`
- `R` (relative) → preserve when relative match logic is intentional
- `O` (override match limit) → flag for manual review; overrides `pcre_match_limit`; avoid in production rules

Example:
- Before: `pcre:"/admin/iU";`
- After: `http_uri; pcre:"/admin/i";`

### 7) Destination Negated Variable Compatibility

| Snort 2 Header Pattern | Snort 3 Header Pattern |
|---|---|
| `... -> !$VARIABLE any (...)` | `... -> any any (...)` |

Apply specifically to destination IP negated variable forms that are not supported in target syntax/profile.

### 8) Metadata Normalization

Normalize metadata syntax and lift service hints to explicit keyword where appropriate.

| Legacy Pattern | Snort 3 Pattern |
|---|---|
| `metadata: service http;` | `service:http;` |
| `metadata:key value;` | `metadata:key value;` or `metadata:key value,key2 value2;` |

### 9) Service Hint Enrichment

When HTTP, DNS, SMTP, SIP, or file semantics are clearly present, add explicit service hints if header remains generic:
- `service:http;`
- `service:dns;`
- `service:smtp;`

Do not add speculative service hints when traffic context is unclear.

### 10) Service Rule Header Promotion

Snort 3 supports service-in-header rules: `alert http (...)`, `alert dns (...)`, `alert smtp (...)`, etc. Promote a traditional-header rule to a service-header rule when:
- The original Snort 2 rule uses HTTP/DNS/SMTP/etc. sticky buffers
- The original `service:` keyword is present (or about to be added via §9)
- Port specifications (`$HTTP_PORTS`, `25`, `53`) are redundant with the service

Promotion drops the explicit protocol, IP, and port tuple in favor of the service:

| Snort 2 (traditional) | Snort 3 (service rule) |
|---|---|
| `alert tcp ANY ANY -> $HTTP_SERVERS $HTTP_PORTS (... http_uri; ...)` | `alert http (... http_uri; ...)` |

Service-header rules also bind detection earlier, improving fast-pattern selection.

### 11) `urilen` Migration

Snort 2 `urilen:[op]N[,norm|raw];` has no direct Snort 3 equivalent. Migrate using the corresponding HTTP buffer plus `bufferlen`:

| Snort 2 | Snort 3 |
|---|---|
| `urilen:N;` | `http_uri; bufferlen:N;` |
| `urilen:>N;` | `http_uri; bufferlen:>N;` |
| `urilen:N,raw;` | `http_raw_uri; bufferlen:N;` |
| `urilen:N<>M;` | `http_uri; bufferlen:N<>M;` |

`bufferlen` operates on the current sticky buffer.

### 12) `file_data:mime` Deprecation

Snort 2 manual §3.5.28 deprecates the `mime` argument. Snort 3 uses bare `file_data;`:

| Snort 2 | Snort 3 |
|---|---|
| `file_data:mime;` | `file_data;` |

Snort 3 `file_data;` activates for HTTP, SMTP, POP3, IMAP, FTP-data, and SMB2 READ/WRITE buffers automatically.

### 13) In-Rule `threshold` Deprecation

Snort 2 manual §3.8 deprecates the in-rule `threshold` keyword. Migrate to:
- `detection_filter:track by_src,count N,seconds M;` (in-rule, evaluated post-detection)
- `event_filter` (in Snort 3 config, post-event suppression/limiting)

| Snort 2 | Snort 3 |
|---|---|
| `threshold:type threshold,track by_src,count 100,seconds 5;` | `detection_filter:track by_src,count 100,seconds 5;` |
| `threshold:type limit,track by_src,count 1,seconds 60;` | Configure `event_filter` in `snort.lua` |

### 14) `flags:1` and `flags:2` Legacy Aliases

Snort 2 accepts `1` and `2` as legacy aliases for TCP CWR and ECE flags. Migrate to the canonical letters per RFC 3168:

| Snort 2 | Snort 3 |
|---|---|
| `flags:1;` | `flags:C;` (CWR) |
| `flags:2;` | `flags:E;` (ECE) |
| `flags:12;` | `flags:CE;` |

### 15) `flowbits` Syntax Update

Snort 3 changes `flowbits` group syntax:
- Set/unset multiple bits: `&` separator (was implementation-specific in Snort 2)
- Check multiple bits: `|` for any-of, `&` for all-of in `isset`/`isnotset`

| Operation | Snort 2 | Snort 3 |
|---|---|---|
| Set multiple | `flowbits:set,a; flowbits:set,b;` | `flowbits:set,a&b;` |
| Check any-of | (separate `isset` calls) | `flowbits:isset,a|b;` |
| Check all-of | (separate `isset` calls) | `flowbits:isset,a&b;` |

Source: snort3-rule-checker/references/rule-options.md.

### 16) `fast_pattern` Eligibility Changes in Snort 3

Snort 3 expands fast-pattern eligibility:
- **Newly eligible** in Snort 3: `http_cookie`, `http_method` (were ineligible in Snort 2)
- **Still ineligible** in Snort 3: `http_raw_cookie`, `http_param`, `http_raw_body`, `http_version`, `http_raw_request`, `http_raw_status`, `http_raw_trailer`, `http_true_ip`

Migration impact: rules with `content:"x",fast_pattern; http_cookie;` were invalid in Snort 2 (and likely silently dropped fast_pattern); they become valid and effective in Snort 3.

`fast_pattern:only` behavior also changed in Snort 3 — flag rules using `:only` for manual review.

### 17) Sticky Buffer Reference (Snort 3 New Buffers)

Snort 3 introduces buffers with no Snort 2 equivalent. Migration adds them as new detection capabilities, not as replacements:

| Snort 3 Buffer | Purpose | Notes |
|---|---|---|
| `raw_data;` | Pre-normalization payload | Replacement for `rawbytes` |
| `pkt_data;` | Cursor reset to normalized packet data | Snort 2 also had `pkt_data` |
| `js_data;` | Normalized JavaScript | Requires `http_inspect.js_normalization_depth > 0` |
| `vba_data;` | VBA macro buffer | Requires `decompress_zip` + `decompress_vba` |
| `http_raw_body;` | De-chunked, decompressed, otherwise unnormalized body (request + response) | No Snort 2 equivalent |
| `http_param:"name"[,nocase];` | URL query and `application/x-www-form-urlencoded` POST body params | No Snort 2 equivalent |
| `http_version;` | HTTP version | No Snort 2 equivalent |
| `http_raw_request;` | Raw request line | No Snort 2 equivalent |
| `http_raw_status;` | Raw status line | No Snort 2 equivalent |
| `http_trailer;` / `http_raw_trailer;` | HTTP trailer fields | No Snort 2 equivalent |
| `http_true_ip;` | Original client IP from proxy-forward headers | No Snort 2 equivalent |

### 18) New Snort 3 Keywords

| Snort 3 Keyword | Purpose |
|---|---|
| `service:http;` | Explicit service binding |
| `rem:"comment";` | In-rule comment metadata |
| `bufferlen:[op]N[,relative];` | Length check on current sticky buffer (replaces `urilen`) |
| `regex:"/pattern/flags"[,fast_pattern][,nocase];` | Hyperscan-backed regex; supports inline `fast_pattern` (which `pcre` does not) |
| `sd_pattern` | Sensitive data detection (Hyperscan build required) |
| `file_id` rule type | File signature detection |

Snort 3 also adds CIP/ENIP, IEC104, MMS, S7CommPlus rule options for ICS/SCADA inspection. These are new capabilities, not migrations.

### 19) `snort2lua` Converter

Snort 3 ships a built-in converter for both config and rule files. Use it as a first-pass migration tool:

```bash
# Convert config
snort2lua -c snort.conf

# Convert rules file
snort2lua -c in.rules -r out.rules

# Output errors go to snort.rej
```

Limitations:
- Not all Snort 2 constructs convert cleanly; review `snort.rej` for failed lines
- `snort2lua` produces functional Snort 3 rules but may not apply best-practice service-header promotion or new sticky buffers
- Run this skill's transformation passes after `snort2lua` to refine output

Source: Snort 3 official docs (print.txt §872-887, §1042-1059).

### 20) Config File Format Migration

Snort 3 replaces the text-based `snort.conf` with Lua-based `snort.lua`. Modules are configured as Lua table literals:

```lua
http_inspect = {
  request_depth = 4096,
  response_depth = 4096,
  js_normalization_depth = 65536,
}

stream_tcp = {
  policy = 'bsd',  -- same default as Snort 2 frag3
}
```

Use `snort2lua -c snort.conf` to bootstrap the conversion.

### 21) Preprocessor → Inspector Migration

| Snort 2 Preprocessor | Snort 3 Inspector(s) | Notes |
|---|---|---|
| `frag3` | Built-in IP defragmentation; OS policy via `stream_tcp.policy` | Default `'bsd'` matches Snort 2 frag3 default |
| `stream5` | `stream_tcp`, `stream_udp`, `stream_ip`, `stream_icmp` | Split into per-protocol modules |
| `http_inspect` | `http_inspect` | Same name, new Lua schema |
| `ftp_telnet` | `ftp_server`, `ftp_client`, `telnet` | Split into per-protocol inspectors |
| `threshold.conf` | Built-in `event_filter`, `suppress`, `rate_filter` in `snort.lua` | Move from external file to inline Lua config |

---

## Migration Report Format (Per Rule)

Use this exact report structure for each migrated SID:

```
## SID: XXXXXX
### Changes Applied
- [list of transformations performed]
### Manual Review Required
- [items needing human judgment]
### Snort 3 Rule
[output rule]
```

Rules with no manual review items must still include the section:
- `- None`

---

## Batch Migration Mode (.rules File)

When migrating full files:

1. Parse all lines and keep only rule lines for output
2. Validate and migrate each rule independently using the per-rule workflow
3. Keep a per-SID migration report entry
4. Sort migrated rules by SID ascending
5. Emit exactly one blank line between rules
6. Emit pure ASCII only
7. Emit no comments in final rules file
8. Provide a summary count:
   - total rules processed
   - fully auto-migrated
   - migrated with manual review
   - failed parse (if any)

If duplicate SIDs exist, preserve all rules but flag duplicates for manual resolution.

---

## Output Rules File Format (MANDATORY)

When writing migrated rules to a file:

1. SID ascending order
2. One blank line between each rule
3. Pure ASCII only
4. No comments (`#` lines prohibited)

Example format:

```
alert tcp ... ( ... sid:1000418; rev:1; )

alert tcp ... ( ... sid:1000419; rev:1; )

alert tcp ... ( ... sid:1000796; rev:2; )
```

---

## Common Migration Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| Leaving `drop`/`sdrop` unchanged | Snort 3 action mismatch | Convert to `block` |
| Keeping `uricontent` | Parser or semantic mismatch | Use `http_uri; content:"...";` |
| Keeping Snort 2 content modifier ordering | Wrong buffer logic | Move sticky buffer before `content` |
| Leaving standalone `fast_pattern` | Invalid style | Merge inline with content |
| Leaving standalone `nocase` | Invalid style | Merge inline with content |
| Leaving PCRE buffer flags | Wrong buffer evaluation | Add sticky buffer and remove flag |
| Keeping `!$VARIABLE` in dst IP | Header incompatibility | Replace destination IP with `any` |
| Not fixing missing semicolons from source rule | Parse failure | Repair syntax before migration |
| Migrating typo literals without warning | False negative risk | Keep literal but flag manual review |
| `dsize` with stream traffic unreviewed | Missed matches | Consider `flow:no_stream` or redesign |
| Assuming `flags:A+` still best practice | Performance and intent drift | Prefer flow-based state checks |

---

## Reference Files

- [syntax-diff.md](references/syntax-diff.md) - Snort 2 vs Snort 3 syntax model differences
- [deprecated-options.md](references/deprecated-options.md) - Deprecated/removed Snort 2 options and Snort 3 replacements
- [migration-examples.md](references/migration-examples.md) - Complete before/after migration examples

---

## Practical Notes from Real Migrations

- `!$AD_Servers` in destination IP must be converted to `any`
- `uricontent` must become `http_uri; content:`
- `content:"..."; http_uri;` must become `http_uri; content:"...";`
- `fast_pattern` standalone modifier must become inline form
- Missing `;` after `content` must be repaired before conversion
- Suspicious text typos should be preserved but flagged in manual review
