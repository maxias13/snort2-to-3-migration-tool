# Snort 2 to Snort 3 Migration Examples

This file provides complete before/after migrations for common Snort 2 patterns.

## Example 1: HTTP URI detection

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP admin path probe"; flow:to_server,established; content:"/admin"; http_uri; sid:2000001; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP admin path probe"; flow:to_server,established; http_uri; content:"/admin"; sid:2000001; rev:1;)
```

## Example 2: HTTP header detection

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP suspicious UA"; flow:to_server,established; content:"sqlmap"; nocase; http_header; sid:2000002; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP suspicious UA"; flow:to_server,established; http_header; content:"sqlmap",nocase; sid:2000002; rev:1;)
```

## Example 3: HTTP body detection

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP command injection in body"; flow:to_server,established; content:"cmd="; http_client_body; content:"wget"; nocase; distance:0; within:100; http_client_body; sid:2000003; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP command injection in body"; flow:to_server,established; http_client_body; content:"cmd="; content:"wget",nocase,distance 0,within 100; sid:2000003; rev:1;)
```

## Example 4: PCRE with URI buffer flag

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP traversal regex"; flow:to_server,established; pcre:"/\.\.\//Ui"; sid:2000004; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP traversal regex"; flow:to_server,established; http_uri; pcre:"/\.\.\//i"; sid:2000004; rev:1;)
```

## Example 5: Multi-content rule with inline modifiers

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP SQLi UNION SELECT"; flow:to_server,established; content:"UNION"; nocase; fast_pattern; http_client_body; content:"SELECT"; nocase; distance:0; within:20; http_client_body; sid:2000005; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP SQLi UNION SELECT"; flow:to_server,established; http_client_body; content:"UNION",nocase,fast_pattern; content:"SELECT",nocase,distance 0,within 20; sid:2000005; rev:1;)
```

## Example 6: Negated content in URI

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP missing expected token"; flow:to_server,established; content:!"token="; http_uri; sid:2000006; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP missing expected token"; flow:to_server,established; http_uri; content:!"token="; sid:2000006; rev:1;)
```

## Example 7: flowbits set and check pair

### Snort 2 (setter)
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB stage1 marker"; flow:to_server,established; content:"|FF|SMB"; depth:4; flowbits:set,smb.stage1; flowbits:noalert; sid:2000007; rev:1;)
```

### Snort 3 (setter)
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB stage1 marker"; flow:to_server,established; content:"|FF|SMB",depth 4; flowbits:set,smb.stage1; flowbits:noalert; sid:2000007; rev:1;)
```

### Snort 2 (checker)
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB stage2 payload"; flow:to_server,established; flowbits:isset,smb.stage1; content:"|90 90 90 90|"; sid:2000008; rev:1;)
```

### Snort 3 (checker)
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB stage2 payload"; flow:to_server,established; flowbits:isset,smb.stage1; content:"|90 90 90 90|"; sid:2000008; rev:1;)
```

## Example 8: drop to block action migration

### Snort 2
```snort
drop tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH brute force packet"; flow:to_server,established; content:"SSH-"; sid:2000009; rev:1;)
```

### Snort 3
```snort
block tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH brute force packet"; flow:to_server,established; content:"SSH-"; sid:2000009; rev:1;)
```

## Example 9: uricontent migration

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP login endpoint access"; flow:to_server,established; uricontent:"/login.php"; sid:2000010; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP login endpoint access"; flow:to_server,established; http_uri; content:"/login.php"; sid:2000010; rev:1;)
```

## Example 10: fast_pattern style change

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP shell upload attempt"; flow:to_server,established; content:"multipart/form-data"; fast_pattern; http_header; content:"filename=\"shell.php\""; nocase; http_client_body; sid:2000011; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP shell upload attempt"; flow:to_server,established; http_header; content:"multipart/form-data",fast_pattern; http_client_body; content:"filename=\"shell.php\"",nocase; sid:2000011; rev:1;)
```

## Example 11: Negated destination variable fix

### Snort 2
```snort
alert tcp $HOME_NET any -> !$AD_Servers 445 (msg:"Possible lateral SMB to non-AD host"; flow:to_server,established; content:"|FF|SMB"; sid:2000012; rev:1;)
```

### Snort 3
```snort
alert tcp $HOME_NET any -> any 445 (msg:"Possible lateral SMB to non-AD host"; flow:to_server,established; content:"|FF|SMB"; sid:2000012; rev:1;)
```

## Example 12: PCRE header/body/cookie flag migration set

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP suspicious auth chain"; flow:to_server,established; pcre:"/Authorization\x3a\s+Basic\s+[A-Za-z0-9+\/=]{20,}/Hi"; pcre:"/sessionid=[A-F0-9]{32}/Ci"; pcre:"/(cmd|exec)=/Pi"; sid:2000013; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP suspicious auth chain"; flow:to_server,established; http_header; pcre:"/Authorization\x3a\s+Basic\s+[A-Za-z0-9+\/=]{20,}/i"; http_cookie; pcre:"/sessionid=[A-F0-9]{32}/i"; http_client_body; pcre:"/(cmd|exec)=/i"; sid:2000013; rev:1;)
```

## Example 13: Legacy metadata service to service keyword

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Generic HTTP attack marker"; flow:to_server,established; content:"/wp-admin"; http_uri; metadata:service http; sid:2000014; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Generic HTTP attack marker"; flow:to_server,established; service:http; http_uri; content:"/wp-admin"; sid:2000014; rev:1;)
```

## Example 14: Missing semicolon fix before migration

### Snort 2 (input with syntax error)
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WebSocket upgrade probe"; flow:to_server,established; content:"Upgrade: websocket" http_header; sid:2000015; rev:1;)
```

### Snort 3 (after syntax repair and migration)
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WebSocket upgrade probe"; flow:to_server,established; http_header; content:"Upgrade: websocket"; sid:2000015; rev:1;)
```

## Example 15: rawbytes to raw_data migration

### Snort 2
```snort
alert tcp any any -> any 23 (msg:"Telnet NOP"; content:"|FF F1|"; rawbytes; sid:2000020; rev:1;)
```

### Snort 3
```snort
alert tcp any any -> any 23 (msg:"Telnet NOP"; raw_data; content:"|FF F1|"; sid:2000020; rev:1;)
```

Note: `rawbytes` (a per-content modifier in Snort 2) maps to the `raw_data;` sticky buffer in Snort 3, NOT `pkt_data;`. Place `raw_data;` before the `content` it scopes.

## Example 16: urilen to bufferlen migration

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Long URI"; flow:to_server,established; urilen:>500; sid:2000021; rev:1;)
```

### Snort 3
```snort
alert http (msg:"Long URI"; flow:to_server,established; http_uri; bufferlen:>500; sid:2000021; rev:1;)
```

Note: `urilen` is removed in Snort 3. Use `http_uri;` to set the cursor on the URI buffer, then `bufferlen:` to test its length.

## Example 17: Service rule header promotion

### Snort 2 (traditional 5-tuple header)
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"HTTP attack"; flow:to_server,established; http_uri; content:"/exploit"; sid:2000022; rev:1;)
```

### Snort 3 (service rule, preferred for HTTP/SMTP/etc.)
```snort
alert http (msg:"HTTP attack"; flow:to_server,established; http_uri; content:"/exploit"; sid:2000022; rev:1;)
```

Note: Snort 3 prefers service-based headers (`alert http`, `alert smtp`, `alert ssl`, `alert dns`, ...) over traditional 5-tuple headers when the rule depends on protocol-aware buffers. Service rules let the inspector dispatch the rule regardless of port.

## Example 18: in-rule threshold to detection_filter migration

### Snort 2 (deprecated in-rule threshold)
```snort
alert tcp any any -> $HTTP_SERVERS 80 (msg:"HTTP flood"; flow:to_server,established; content:"GET"; http_method; threshold:type threshold,track by_src,count 100,seconds 5; sid:2000023; rev:1;)
```

### Snort 3
```snort
alert http (msg:"HTTP flood"; flow:to_server,established; http_method; content:"GET"; detection_filter:track by_src,count 100,seconds 5; sid:2000023; rev:1;)
```

Note: The in-rule `threshold` keyword is removed. Use `detection_filter` for per-rule rate gating, or `event_filter` / `rate_filter` in `snort.lua` for global policy.

## Example 19: file_data:mime to file_data migration

### Snort 2 (deprecated mime argument)
```snort
alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"SMTP malware"; flow:to_server,established; file_data:mime; content:"EICAR"; sid:2000024; rev:1;)
```

### Snort 3
```snort
alert smtp (msg:"SMTP malware"; flow:to_server,established; file_data; content:"EICAR"; sid:2000024; rev:1;)
```

Note: `file_data` no longer takes the `mime` argument. The SMTP inspector populates `file_data` automatically for MIME attachments.

## Example 20: sblock to block migration

### Snort 2
```snort
sblock tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB exploit (silent)"; flow:to_server,established; content:"|FF|SMB"; sid:2000025; rev:1;)
```

### Snort 3
```snort
block tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB exploit (silent)"; flow:to_server,established; content:"|FF|SMB"; sid:2000025; rev:1;)
```

Note: `sblock` (silent block) and `sdrop` (silent drop) are both removed. Use `block` in Snort 3; alert suppression is configured via `event_filter` or `suppress` in `snort.lua`, not via the action.

## Example 21: replace with rewrite action

### Snort 2 (replace modifier)
```snort
alert tcp any any -> any 80 (msg:"Sanitize Server header"; flow:to_server,established; content:"Apache/2.2"; replace:"Apache/X.X"; sid:2000026; rev:1;)
```

### Snort 3 (rewrite action + replace)
```snort
rewrite tcp any any -> any 80 (msg:"Sanitize Server header"; flow:to_server,established; content:"Apache/2.2"; replace:"Apache/X.X"; sid:2000026; rev:1;)
```

Note: In Snort 3, in-stream content rewriting requires the `rewrite` action. The `replace` keyword still names the substitute bytes, but the rule must use the `rewrite` action header to actually modify the stream.

## Example 22: js_data sticky buffer (Snort 3 new capability)

### Snort 2 (no equivalent — would search the raw HTTP body)
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Suspicious JS eval in body"; flow:to_server,established; content:"eval("; nocase; http_client_body; sid:2000027; rev:1;)
```

### Snort 3 (normalized JavaScript via http_inspect JS normalizer)
```snort
alert http (msg:"Suspicious JS eval in body"; flow:to_server,established; js_data; content:"eval(",nocase; sid:2000027; rev:1;)
```

Note: `js_data` exposes JavaScript that has been normalized by the HTTP inspector's JS normalizer (whitespace collapsed, identifiers stable). It catches obfuscated payloads that raw-body search would miss. Requires the JS normalizer to be enabled in `http_inspect`.

## Example 23: file_id rule type (Snort 3 new rule category)

### Snort 2 (no equivalent — file content matched as generic content)
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"PE download"; flow:to_client,established; content:"MZ"; depth:2; sid:2000028; rev:1;)
```

### Snort 3 (dedicated file_id rule)
```snort
file_id (msg:"PE download"; file_meta:type PE,id 1,category executable; file_data; content:"MZ",depth 2; sid:2000028; rev:1;)
```

Note: Snort 3 introduces dedicated `file_id` rules for file-type identification, decoupled from the 5-tuple header. The file inspector matches across protocols (HTTP, SMTP, SMB, FTP) automatically once a file is reassembled. Use `file_meta` to declare the file type and category.

## Notes

1. Keep one rule per SID and preserve SID/rev identity unless explicitly instructed.
2. Sort final output by SID ascending in migrated `.rules` files.
3. Place exactly one blank line between rules.
4. Keep output pure ASCII and comment-free for management system compatibility.
5. PCRE buffer flags map as follows: `U`→`http_uri;`, `H`→`http_header;`, `P`→`http_client_body;`, `C`→`http_cookie;` (normalized), `K`→`http_raw_cookie;`, `I`→`http_raw_uri;`, `D`→`http_raw_header;`, `M`→`http_method;`, `S`→`http_stat_code;`, `Y`→`http_stat_msg;`, `B`→`raw_data;`, `R` (relative)→`distance 0`, `O` (override)→remove (default in Snort 3).
