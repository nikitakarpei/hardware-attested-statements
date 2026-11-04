# Predicate type `urn:signed-capture:http-response:v1` (draft)

An HTTPS response, with the request and connection it was fetched with: the server at this address, presenting this
certificate, sent this response to this request. It only shows that the server sent it, not that it is true. The
core spec's conventions (section 0) apply, and responses carry their bundle in headers (section 6).

```json
{ "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "body", "digest": { "sha256": "…" }, "mediaType": "text/html; charset=utf-8" }],
  "predicateType": "urn:signed-capture:http-response:v1",
  "predicate": {
    "request":    { "method": "GET", "url": "https://example.com/", "headers": [["Host", "example.com"], ["…", "…"]],
                    "cookies": "none" },
    "connection": { "route": "direct", "connectedTo": "<IP>:443", "protocol": "http/1.1",
                    "tlsVersion": "TLSv1.3", "cipherSuite": "…", "serverCertificateSha256": "…" },
    "response":   { "statusLine": "HTTP/1.1 200 OK", "status": 200, "headers": [["…", "…"]] },
    "startedAfter": { "drand": { "…": "…" } } } }
```

- `body`: the response body (section 6).
- `request`: as sent on the wire; `headers` are name and value pairs, in order.
- `connection`: the server's address, the protocol, TLS version and cipher suite, and the SHA-256 of the server's
  certificate (DER).
- `response`: the status line, status and headers as received.

`request.url` and `response.status` MUST be present. Besides section 6, a verifier MUST check that a saved
response's status equals `response.status`, and its headers equal `response.headers`: compared as sorted
`name: value` lines, names lowercased, both trimmed of whitespace, without `Connection`, `Content-Length`,
`Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding` and `Attested-*` headers.
