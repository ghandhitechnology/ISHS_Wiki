# Upload security deployment

- Deploy the upload authentication guard and `/image/` response changes together.
- Confirm anonymous GET and POST requests to `/upload` redirect to `/login`, and signed-in uploads work for raster and SVG files.
- Confirm SVG files under `/image/` return `image/svg+xml` with `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and the sandbox CSP. Pages still show the image; opening the file directly downloads it.
- Purge any cached `/image/` responses at the reverse proxy or CDN when deploying, because cached responses from before this change carry no CSP.

SVG uploads stay enabled. The file keeps its real type so `<img>` renders it, but the response is always an attachment, so a script inside it never runs with a wiki session. The CSP is the second layer for clients that ignore the header. Existing files keep their sha224 storage paths.

Verified without changes: `/upload` is covered by the global per-IP limit of 40 requests per 10 seconds. The configured upload size check and the 16 MB total request cap remain active.

Follow-up: serve uploads from `files.ishswiki.xyz` with no wiki session cookies, and update rendered file URLs to that origin. That removes the per-type rules entirely.
