import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dns from "node:dns/promises";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { request, Agent } from "undici";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_BYTES = Number(process.env.MAX_DOWNLOAD_BYTES || 250 * 1024 * 1024);
const TIMEOUT_MS = Number(process.env.DOWNLOAD_TIMEOUT_MS || 30000);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.disable("x-powered-by");
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(express.json({ limit: "8kb" }));
app.use(rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: "draft-7", legacyHeaders: false }));
app.use(express.static(path.join(__dirname, "public")));

const ALLOWED_MIME = new Set([
  "video/mp4", "video/webm", "video/quicktime", "video/x-m4v",
  "audio/mpeg", "audio/mp4", "audio/aac", "audio/wav", "audio/x-wav",
  "audio/ogg", "audio/flac", "image/jpeg", "image/png", "image/gif",
  "image/webp", "image/avif", "application/octet-stream"
]);

function ipv4ToInt(ip) {
  return ip.split(".").reduce((n, octet) => ((n << 8) | Number(octet)) >>> 0, 0);
}
function inV4Range(ip, base, bits) {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}
function isPublicIPv4(ip) {
  if (net.isIP(ip) !== 4) return false;
  const blocked = [
    ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10],
    ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
    ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16],
    ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
    ["224.0.0.0", 4], ["240.0.0.0", 4]
  ];
  return !blocked.some(([base, bits]) => inV4Range(ip, base, bits));
}
function isPublicIPv6(ip) {
  if (net.isIP(ip) !== 6) return false;
  const v = ip.toLowerCase().split("%")[0];
  // Permit global unicast only; reject loopback, link-local, unique-local,
  // IPv4-mapped IPv6 and special-use ranges.
  if (v === "::" || v === "::1" || v.startsWith("fe8") || v.startsWith("fe9") ||
      v.startsWith("fea") || v.startsWith("feb") || v.startsWith("fc") ||
      v.startsWith("fd") || v.startsWith("ff") || v.startsWith("::ffff:")) return false;
  return v.startsWith("2") || v.startsWith("3");
}
function isPublicIP(ip) {
  return net.isIP(ip) === 4 ? isPublicIPv4(ip) : isPublicIPv6(ip);
}
async function resolvePublicHost(hostname) {
  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local")) {
    throw new Error("Local hostnames are not allowed.");
  }
  const literalVersion = net.isIP(hostname);
  if (literalVersion) {
    if (!isPublicIP(hostname)) throw new Error("Private or reserved IP addresses are not allowed.");
    return [{ address: hostname, family: literalVersion }];
  }
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!records.length || records.some(record => !isPublicIP(record.address))) {
    throw new Error("The host must resolve only to public IP addresses.");
  }
  return records;
}
function validateUrl(raw) {
  let url;
  try { url = new URL(raw); } catch { throw new Error("Enter a valid URL."); }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS links are supported.");
  if (url.username || url.password) throw new Error("URLs containing credentials are not allowed.");
  if (url.port && !["80", "443"].includes(url.port)) throw new Error("Only standard web ports are allowed.");
  if (url.href.length > 4096) throw new Error("The URL is too long.");
  return url;
}
function safeFilename(url, mime) {
  const raw = path.posix.basename(decodeURIComponent(url.pathname || "").replace(/\\/g, "/"));
  let name = raw.replace(/[\u0000-\u001f\u007f"<>:|?*]/g, "_").replace(/^\.+$/, "");
  if (!name || name.length > 150) name = "download";
  if (!path.extname(name)) {
    const ext = ({
      "video/mp4": ".mp4", "video/webm": ".webm", "video/quicktime": ".mov",
      "audio/mpeg": ".mp3", "audio/wav": ".wav", "audio/ogg": ".ogg",
      "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp",
      "image/gif": ".gif", "image/avif": ".avif"
    })[mime] || ".bin";
    name += ext;
  }
  return name;
}
function attachmentHeader(filename) {
  const safe = filename.replace(/[^A-Za-z0-9._-]/g, "_");
  return `attachment; filename="${safe}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}
async function requestPinned(url, records, method = "GET") {
  // Pin DNS resolution to a previously checked public address to reduce SSRF/DNS-rebinding risk.
  const selected = records[0];
  const dispatcher = new Agent({
    connect: {
      lookup(host, options, callback) {
        if (host !== url.hostname) return dns.lookup(host, options, callback);
        if (options && options.all) return callback(null, records);
        return callback(null, selected.address, selected.family);
      }
    }
  });
  try {
    return await request(url, {
      method,
      dispatcher,
      maxRedirections: 0,
      headersTimeout: TIMEOUT_MS,
      bodyTimeout: TIMEOUT_MS,
      headers: { "user-agent": "YourBrand-MediaDownloader/1.0", "accept": "video/*,audio/*,image/*,application/octet-stream;q=0.8,*/*;q=0.1" }
    });
  } catch (err) {
    await dispatcher.close().catch(() => {});
    throw err;
  }
}
async function openSafeResponse(raw) {
  let url = validateUrl(raw);
  for (let hop = 0; hop <= 4; hop++) {
    const records = await resolvePublicHost(url.hostname);
    const response = await requestPinned(url, records, "GET");
    if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
      const location = response.headers.location;
      response.body.destroy();
      if (!location) throw new Error("The source returned an invalid redirect.");
      if (hop === 4) throw new Error("Too many redirects.");
      url = validateUrl(new URL(location, url).href);
      continue;
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      response.body.destroy();
      throw new Error(`The source server returned HTTP ${response.statusCode}.`);
    }
    return { url, response };
  }
  throw new Error("Could not follow the source URL.");
}

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "YourBrand Downloader API" }));

app.post("/api/inspect", async (req, res) => {
  try {
    if (typeof req.body?.url !== "string") return res.status(400).json({ error: "Provide a URL string." });
    const url = validateUrl(req.body.url.trim());
    await resolvePublicHost(url.hostname);
    const result = await openSafeResponse(url.href);
    const mime = String(result.response.headers["content-type"] || "application/octet-stream").split(";")[0].toLowerCase();
    const length = Number(result.response.headers["content-length"] || 0);
    result.response.body.destroy();
    if (!ALLOWED_MIME.has(mime) && !mime.startsWith("video/") && !mime.startsWith("audio/") && !mime.startsWith("image/")) {
      return res.status(415).json({ error: "The URL does not appear to point to a supported media file.", contentType: mime });
    }
    return res.json({ ok: true, contentType: mime, sizeBytes: length || null, filename: safeFilename(result.url, mime), downloadable: true });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Could not inspect this URL." });
  }
});

app.post("/api/download", async (req, res) => {
  let source;
  try {
    if (typeof req.body?.url !== "string") return res.status(400).json({ error: "Provide a URL string." });
    source = await openSafeResponse(req.body.url.trim());
    const headers = source.response.headers;
    const mime = String(headers["content-type"] || "application/octet-stream").split(";")[0].toLowerCase();
    const length = Number(headers["content-length"] || 0);
    if (!ALLOWED_MIME.has(mime) && !mime.startsWith("video/") && !mime.startsWith("audio/") && !mime.startsWith("image/")) {
      source.response.body.destroy();
      return res.status(415).json({ error: "Only direct video, audio, image, or binary media files are supported." });
    }
    if (length > MAX_BYTES) {
      source.response.body.destroy();
      return res.status(413).json({ error: `File exceeds the ${Math.round(MAX_BYTES / 1024 / 1024)} MB limit.` });
    }
    res.setHeader("Content-Type", mime);
    res.setHeader("Content-Disposition", attachmentHeader(safeFilename(source.url, mime)));
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");
    if (length) res.setHeader("Content-Length", String(length));
    let total = 0;
    source.response.body.on("data", chunk => {
      total += chunk.length;
      if (total > MAX_BYTES) {
        source.response.body.destroy(new Error("File size limit exceeded."));
        if (!res.headersSent) res.status(413);
        res.destroy();
      }
    });
    source.response.body.on("error", () => { if (!res.destroyed) res.destroy(); });
    source.response.body.pipe(res);
  } catch (err) {
    if (source?.response?.body) source.response.body.destroy();
    if (!res.headersSent) res.status(400).json({ error: err.message || "Download failed." });
    else res.destroy();
  }
});

app.use((err, _req, res, _next) => {
  console.error("Request error:", err.message);
  if (!res.headersSent) res.status(500).json({ error: "Unexpected server error." });
});

app.listen(PORT, () => console.log(`YourBrand API listening on http://localhost:${PORT}`));
const path = require('path');app.use(express.static(path.join(__dirname, 'public')));
