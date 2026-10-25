# YourBrand Media Downloader — backend starter

This project adds a Node.js API for **permitted direct media-file URLs**. It does not extract video from social-media pages, bypass logins, defeat DRM, or circumvent platform restrictions.

## Included
- `POST /api/inspect` — checks a public URL and returns media metadata.
- `POST /api/download` — streams a supported direct media file to the browser.
- `GET /api/health` — health check.
- `public/index.html` — your website front-end (copy the supplied HTML into this folder).
- Basic security headers, request rate limiting, DNS/IP checks, redirect revalidation, timeout and size limits.

## Requirements
- Node.js 20 or newer
- npm

## Run locally
1. Copy the `yourbrand_media_downloader.html` file into this folder as `public/index.html` (create the `public` folder first).
2. Open a terminal in this project folder.
3. Run `npm install`
4. Run `npm start`
5. Visit `http://localhost:3000`

## Connect the front-end
In the front-end JavaScript, replace the current direct-link download handler with a POST request to `/api/download`. Example:

```js
const response = await fetch('/api/download', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ url: input.value.trim() })
});

if (!response.ok) {
  const error = await response.json().catch(() => ({ error: 'Download failed' }));
  throw new Error(error.error || 'Download failed');
}

const blob = await response.blob();
const disposition = response.headers.get('Content-Disposition') || '';
const match = disposition.match(/filename="?([^";]+)"?/i);
const filename = match?.[1] || 'download.bin';
const objectUrl = URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = objectUrl;
a.download = filename;
document.body.appendChild(a);
a.click();
a.remove();
URL.revokeObjectURL(objectUrl);
```

For large files, prefer a backend-generated short-lived download URL or redirect to a protected object-storage URL rather than buffering the whole response in browser memory.

## Important deployment notes
- This is a starter implementation. Review and test it before production deployment.
- Keep Node and dependencies patched. Add monitoring, abuse detection, per-user quotas if accounts are introduced, and a clear privacy/retention policy.
- The API intentionally accepts only public HTTP(S) hosts and standard web ports. Some legitimate sources may fail due to CORS-like source restrictions, hotlink protection, signed URLs, unsupported media types, or servers requiring cookies/authentication.
- The URL is fetched server-side, so SSRF defenses are critical. This implementation validates DNS answers and pins the selected IP for each request, but have a security engineer review networking edge cases before public launch.
- Do not allow arbitrary protocols, private-network targets, or unrestricted redirects.
- The download endpoint permits media MIME types and `application/octet-stream`; confirm your hosting and business needs before making it public.
- The backend cannot download from a webpage that embeds a video unless you implement a lawful, source-specific integration. Do not bypass DRM, access controls, or platform terms.
