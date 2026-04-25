# Snort 2 vs Snort 3 Syntax Differences

This reference focuses on rule-writing differences that matter during migration.

## 1) Header Model

| Topic | Snort 2 | Snort 3 | Migration Impact |
|---|---|---|---|
| Traditional header | `action proto src_ip src_port -> dst_ip dst_port` | Same traditional form still supported | Usually retained unless service-header conversion is desired |
| Service header | Not native in classic Snort 2 style | `alert http (...)`, `alert dns (...)`, and others | Prefer service header when app protocol is known |
| File rules | Not first-class header type | `action file (...)` and `file_id (...)` | File-centric detections can be promoted to file rule types |
| Direction operators | `->`, `<>` | `->`, `<>` | No change |
| Negated destination variable | Commonly seen in legacy rulebases | Can be unsupported/problematic in target style | Replace with `any` when incompatible |

## 2) Action Vocabulary

| Topic | Snort 2 | Snort 3 | Migration Impact |
|---|---|---|---|
| IDS actions | `alert`, `log`, `pass` | `alert`, `log`, `pass` | No major change |
| IPS drop (current packet) | `drop` | `drop` exists; affects only the current packet | Map to `block` if flow-level drop semantics are desired |
| IPS block (flow-level) | `block` (alias for `drop` in Snort 2) | `block` drops current packet AND blocks subsequent packets in the flow | Distinct from `drop` in Snort 3; choose intentionally |
| Silent drop | `sdrop`, `sblock` | Removed; use `block` (suppress alerting via `event_filter`/`suppress` in `snort.lua`) | Convert `sdrop` and `sblock` to `block` |
| Stream rewriting | `replace:"..."` content modifier (any action) | `replace` requires `rewrite` action header | Change action to `rewrite` when `replace` is present |
| Active responses | `reject`, `react`, `resp` | `reject`, `react` supported; `resp` (Flexible Response) has NO Snort 3 equivalent — manual review required | `resp` rules must be redesigned around `reject` or stream rewriting |

## 3) Rule Body and Option Style

| Topic | Snort 2 | Snort 3 | Migration Impact |
|---|---|---|---|
| Option terminator | `;` | `;` | No change |
| Content modifiers | Often separate tokens after content (`content:"x"; nocase; fast_pattern;`) | Inline content option style (`content:"x",nocase,fast_pattern;`) | Rewrite modifier style inline |
| Relative/absolute modifiers | `offset:`, `depth:`, `distance:`, `within:` as separate options | Inline with content (`offset 2`, `within 20`) | Convert formatting and keep semantics |
| Metadata syntax | Commonly free-form one pair per metadata token | Metadata supports comma-separated key/value entries | Normalize metadata formatting |

## 4) Content Detection Model

| Topic | Snort 2 | Snort 3 | Migration Impact |
|---|---|---|---|
| Core `content` | Same keyword | Same keyword | Content survives but modifier format changes |
| `fast_pattern` usage | Standalone option or parameterized forms | Inline modifier with content | Convert to inline style |
| `nocase` usage | Standalone modifier after content | Inline with content | Convert to inline style |
| Negated content | `content:!"x";` | `content:!"x";` with inline modifiers possible | Keep negation, adjust style only |

## 5) Buffer Handling Model

| Topic | Snort 2 | Snort 3 | Migration Impact |
|---|---|---|---|
| HTTP buffer selection | Often used as content modifiers (`content:"x"; http_uri;`) | Sticky buffers set first (`http_uri; content:"x";`) | Reorder to sticky-buffer-first pattern |
| URI keyword | `uricontent` legacy keyword | Use `http_uri; content:` pattern | Replace every `uricontent` occurrence |
| Raw bytes handling | `rawbytes` content modifier | `raw_data;` sticky buffer ONLY (NOT `pkt_data;`) | Convert every `rawbytes` to a `raw_data;` sticky buffer placed before the content it scopes |
| Cursor reset | `pkt_data` exists | `pkt_data;` is the cursor-reset / normalized payload buffer — distinct from `raw_data;` | Use `pkt_data;` when returning from a sticky buffer to scan normalized payload, not as a `rawbytes` replacement |

## 6) PCRE and Regex Model

| Topic | Snort 2 | Snort 3 | Migration Impact |
|---|---|---|---|
| PCRE option | `pcre:"/.../flags";` | Same general syntax | Keep pattern and standard flags |
| HTTP PCRE buffer flags | Legacy flags (`U`,`H`,`P`,`C`,`I`,`D`,`K`,`S`,`Y`) used to select buffers | Sticky buffers select context; legacy HTTP flags should be removed | Add sticky buffer then strip legacy buffer flag |
| Relative PCRE flag | `R` supported | `R` still meaningful | Preserve when logical |
| Alternate regex engine | Not standard in classic Snort 2 | Snort 3 introduces `regex` (Hyperscan-backed) | Optional optimization after successful migration |

## 7) New Keywords and Capabilities in Snort 3

| Area | Snort 3 Additions | Migration Relevance |
|---|---|---|
| Explicit service scoping | `service:http;` and other service values | Move service intent out of legacy metadata |
| Service headers | `alert http (...)` and similar | Candidate refactor for cleaner app-layer rules |
| Additional sticky buffers | Expanded HTTP and file-centric buffers | Enables more precise migrated rules |
| `regex` keyword | Hyperscan-backed regex option | Optional performance enhancement |
| File rule forms | `action file`, `file_id` | Useful for file signature migrations |

## 8) Removed or Deprecated Migration Targets

| Snort 2 Construct | Snort 3 Migration Direction |
|---|---|
| `uricontent` | Replace with `http_uri; content:` |
| HTTP buffer flags inside PCRE | Replace with sticky buffers before `pcre` |
| `sdrop` | Replace with `block` |
| Standalone content modifiers | Convert to inline content modifier style |
| Legacy service metadata usage | Use `service:` keyword |

## 9) Validation Checklist After Conversion

Use this quick checklist after transforming a rule:

1. Header is syntactically valid for Snort 3 (consider promoting to a service header — e.g. `alert http (...)` — when app protocol is known).
2. Action is valid and aligned with migration policy (`drop`/`sdrop`/`sblock` converted to `block`; `replace` rules converted to `rewrite` action).
3. `uricontent` has been removed (replaced by `http_uri; content:`).
4. HTTP buffer modifiers were converted to sticky buffers.
5. `content` modifiers are inline.
6. Legacy PCRE HTTP buffer flags were removed and replaced with sticky buffers (`C`→`http_cookie;`, `K`→`http_raw_cookie;`, `B`→`raw_data;`).
7. Destination negated variable incompatibilities were normalized to `any`.
8. Output rule keeps `sid` and `rev`.
9. Rule remains pure ASCII.
10. `rawbytes` was converted to `raw_data;` (NOT `pkt_data;`).
11. `urilen:N` was converted to `http_uri; bufferlen:N`.
12. `file_data:mime` was converted to plain `file_data;`.
13. In-rule `threshold:type ...` was converted to `detection_filter` (per-rule) or moved to `event_filter`/`rate_filter` in `snort.lua` (global).
14. `flags:1` / `flags:2` legacy aliases were replaced with `C` / `E`.
15. `fast_pattern:only` placements were reviewed — Snort 3 evaluates the rule even when the fast-pattern matches; behavior differences should be confirmed.
16. PCRE `B` flag was replaced by `raw_data;` sticky buffer + plain `pcre`; PCRE `O` flag occurrences were reviewed (overrides match limit, avoid in production).
17. `resp` rules were flagged for manual redesign (no Snort 3 equivalent).

## 10) Infrastructure Migration

Rule files are only one half of a Snort 2 → Snort 3 migration. The runtime configuration must move from `snort.conf` to `snort.lua`, and preprocessors must be replaced by inspectors.

### 10.1 Configuration Format

| Snort 2 | Snort 3 | Notes |
|---|---|---|
| `snort.conf` (custom DSL) | `snort.lua` (Lua table literals) | Inspector params become Lua table fields |
| `var HOME_NET ...`, `ipvar`, `portvar` | `HOME_NET = '...'` Lua assignments | IP/port variables become Lua strings or tables |
| `include classification.config` | `include 'classification.lua'` | Helper files also Lua |
| `output unified2: ...` | `alert_csv = { ... }`, `alert_fast = { ... }`, `unified2 = { ... }` | Outputs are inspector-style Lua tables |

### 10.2 Preprocessor → Inspector Mapping

| Snort 2 Preprocessor | Snort 3 Inspector(s) | Notes |
|---|---|---|
| `frag3` | `stream_ip` (defragmentation moved into stream) | Policy field (`bsd`, `linux`, `windows`, ...) preserved |
| `stream5` | `stream`, `stream_tcp`, `stream_udp`, `stream_ip`, `stream_icmp`, `stream_user`, `stream_file` | Per-protocol inspectors; `stream_tcp.policy` default is `bsd` |
| `http_inspect` (Snort 2) | `http_inspect` (Snort 3, redesigned with new schema) | NHI; many new fields including `js_normalization_depth`, `decompress_zip`, `decompress_vba` |
| `ftp_telnet` | `ftp_server`, `ftp_client`, `telnet` | Split into separate inspectors |
| `dns`, `ssl`, `sip`, `dnp3`, `modbus`, `imap`, `pop`, `smtp` | Same names as inspectors | Mostly direct rename with Lua schema |
| `threshold.conf` | `event_filter`, `suppress`, `rate_filter` in `snort.lua` | In-rule `threshold` also moved to `detection_filter` |
| `reputation` | `reputation` inspector | Schema rewritten in Lua |

### 10.3 `snort2lua` Converter

Snort 3 ships with a `snort2lua` tool to automate most of the conversion.

| Use | Command |
|---|---|
| Convert config | `snort2lua -c snort.conf -o snort.lua` |
| Convert rules | `snort2lua -c in.rules -r out.rules` |
| Convert both | `snort2lua -c snort.conf -r in.rules -o snort.lua` |
| Strict mode | `snort2lua --error-mode -c snort.conf -o snort.lua` |

Errors are written to `snort.rej`. Limitations: not every Snort 2 construct converts cleanly — review `snort.rej` and handle the rules above (`rawbytes`, `urilen`, in-rule `threshold`, `resp`, `replace`, `sblock`, etc.) manually.

## 11) New Snort 3 Rule Types

Beyond the traditional `alert tcp ...` style, Snort 3 introduces purpose-built rule headers.

### 11.1 Service Rules

```snort
alert http (msg:"HTTP attack"; flow:to_server,established; http_uri; content:"/exploit"; sid:1000001; rev:1;)
alert smtp (msg:"SMTP MIME"; flow:to_server,established; file_data; content:"EICAR"; sid:1000002; rev:1;)
alert ssl  (msg:"SSL probe"; ssl_state:client_hello; sid:1000003; rev:1;)
alert dns  (msg:"DNS exfil"; dns_query:"badc2.example.com"; sid:1000004; rev:1;)
```

Service rules dispatch via the inspector regardless of port. Use them whenever the rule depends on protocol-aware buffers.

### 11.2 File Rules

```snort
alert file (msg:"Malware EICAR"; file_data; content:"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR"; sid:1000010; rev:1;)
```

File rules match across protocols once the file inspector reassembles a file (HTTP download, SMTP attachment, SMB transfer, FTP-DATA).

### 11.3 `file_id` Rules

```snort
file_id (msg:"PE download"; file_meta:type PE,id 1,category executable; file_data; content:"MZ",depth 2; sid:1000020; rev:1;)
file_id (msg:"PDF download"; file_meta:type PDF,id 2,category document; file_data; content:"%PDF-",depth 5; sid:1000021; rev:1;)
```

`file_id` rules declare file types via `file_meta` so the file inspector can label and act on identified files.
