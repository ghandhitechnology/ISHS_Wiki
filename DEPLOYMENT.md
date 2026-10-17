# Upload security deployment

- Deploy the upload authentication guard and `/image/` response changes together.
- Run this SQL against the live wiki database and commit the transaction:

  ```sql
  DELETE FROM html_filter WHERE kind = 'extension' AND LOWER(html) = 'svg';
  ```

- Confirm anonymous GET and POST requests to `/upload` redirect to `/login`, signed-in raster uploads work, and embedded images still display.
- Confirm existing SVG files under `/image/` return `image/svg+xml` inline with `X-Content-Type-Options: nosniff` and the sandbox CSP, display in pages, and do not run embedded script. Purge any cached `/image/` responses at the reverse proxy or CDN when deploying, because the old cached type is `image/svg+xml` without the CSP.

The SVG code guard rejects uploads even if an administrator adds SVG back to the whitelist. Existing files keep their sha224 storage paths.

Verified without changes: `/upload` is covered by the global per-IP limit of 40 requests per 10 seconds. The configured upload size check and the 16 MB total request cap remain active.

Follow-up: serve uploads from `files.ishswiki.xyz` with no wiki session cookies, and update rendered file URLs to that origin.
