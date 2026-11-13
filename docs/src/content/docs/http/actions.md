---
title: HTTP actions
---

## forward

Forwards the HTTP request to one or more backend servers. Supports connection
reuse and header manipulation; WebSocket upgrades remain H1-to-H1 only.

```yaml
http_action:
  type: forward
  upstream_protocol: http1        # http1 (default) or http2
  locations: [string | object]     # Backend address(es) -- round-robin if multiple
  replacement_path: string         # Rewrite the request path
  request_header_patch:            # Modify request headers
    default_headers:               #   Add if not already present
      X-Forwarded-For: "..."
    overwrite_headers:             #   Set unconditionally
      Host: backend.internal
    remove_headers:                #   Remove
      - X-Debug
  response_header_patch:           # Modify response headers (same structure)
    overwrite_headers:
      X-Served-By: tobaru
  request_id_header_name: string   # Add a unique request ID header to the request
  response_id_header_name: string  # Add a unique request ID header to the response
```

The `address`, `addresses`, and `location` field names are accepted as aliases for `locations`.

`replacement_path` replaces the selected route's mount prefix, preserving the
remaining path and query. For example, a `/api/` route with `replacement_path: /v1/`
maps `/api/users?active=1` to `/v1/users?active=1`. It does not decode or normalize
path segments.

Backend reuse is local to a client connection and the selected HTTP action.
Changing Host/header rules to select another action opens a different backend
connection, even when the path prefix is unchanged. Round-robin selection occurs
when a backend connection is opened, not on every request.

Header names in patches are case-insensitive. Repeated received fields retain
their value order; an overwrite replaces all values for that name. Patches must
not change the received body's framing (for example, changing Content-Length or
removing chunked Transfer-Encoding). Such requests/responses are rejected and the
connection is closed; body bytes are not rewritten to match a patched length or
transfer-coding stack. Transfer-Encoding fields with parameters must remain
unchanged; their quoted values are not normalized. Patches also cannot manufacture
or relabel a successful protocol upgrade: the original and forwarded handshakes
must agree, including the case-sensitive protocol version when present.

Forwarding supports HEAD/bodyless responses, informational responses including
100 Continue and 103 Early Hints, and close-delimited response bodies. An early
final response during an unfinished upload is forwarded and both connections are
closed rather than reused on the existing H1-to-H1 path. New H2 paths continue
upload alongside successful response DATA for duplex streaming. H1 backend error
responses stop upload through write-side shutdown while the response drains.
See [HTTP/2 Policy and Limits](/http/http2/) for protocol selection,
cancellation, and unsupported features. CONNECT remains unsupported.

## serve-message

Returns a static HTTP response. `status_code` must be a final status from 200
through 599, for both HTTP/1 and HTTP/2. Custom reason phrases apply only to HTTP/1.

```yaml
http_action:
  type: serve-message
  status_code: 200                 # HTTP status code (required)
  status_message: "OK"             # Custom status text (optional)
  content: "Hello, world!"        # Response body (default: "")
  response_headers:                # Custom response headers
    Content-Type: "text/plain"
  response_id_header_name: string  # Add a unique request ID header
```

## serve-directory

Serves static files from a directory. MIME types are automatically detected.

Missing files and directory indexes return 404. By default the response body is
empty. Setting `not_found_content` supplies a plain-text body and
`Content-Type: text/plain`; HEAD returns the same headers without a body.
File `response_headers` do not apply to 404 responses, but the response ID header
is retained. `tobaru static` sets `not_found_content` to `Not Found`.
When `not_found_content` is set, `response_id_header_name` cannot be `Content-Type`
(case-insensitive). HTTP/2 preflight also checks the generated 404 headers,
including the response ID, against HTTP/2 field restrictions and the configured
header-list limit.

After route selection, the query is removed and the file path is percent-decoded.
Decoded parent-directory segments and NUL bytes are rejected; names such as
`report..final.txt` are allowed. Both the requested file and a directory's
`index.html` must resolve inside the canonical serving root. Keep serving trees
immutable or trusted: canonicalization does not eliminate concurrent symlink
replacement races.

```yaml
http_action:
  type: serve-directory
  path: /var/www/static            # Directory path (required)
  not_found_content: "Not Found"   # Optional plain-text 404 body (default: absent)
  response_headers:                # Custom response headers
    Cache-Control: "max-age=3600"
  response_id_header_name: string  # Add a unique request ID header
```

## close

Immediately closes the connection.

```yaml
http_action:
  type: close

# Shorthand string form
http_action: close
```
