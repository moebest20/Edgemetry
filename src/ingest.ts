/**
 * Event ingestion. One pageview should cost exactly one row written, so this
 * path does no UPDATEs, touches no indexed table, and never reads back what it
 * just wrote.
 */

import { RAW_COLUMNS, alterRawTable, createRawTableSql, rawTable } from './db';
import { partsForTs } from './time';
import { isBot, parseUa } from './ua';
import { computeVisitor } from './visitor';
import { lookupIp, cnCountryToCode } from './geo';


/** Beacon bodies are tiny; anything larger is not one of ours. */
const MAX_BODY_BYTES = 4096;
const MAX_PATH_LENGTH = 512;
const MAX_FIELD_LENGTH = 255;

interface EventPayload {
  n?: unknown;
  d?: unknown;
  u?: unknown;
  r?: unknown;
  w?: unknown;
}

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
  'access-control-max-age': '86400',
} as const;

function beaconResponse(status: number, message?: string): Response {
  return new Response(message ?? null, {
    status,
    headers: { ...CORS_HEADERS, 'cache-control': 'no-store' },
  });
}

export function corsPreflight(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

function clamp(value: string, max: number): string {
  return value.length > max ? value.slice(0, max) : value;
}

function normalizeDomain(raw: string): string {
  return clamp(raw.trim().toLowerCase().replace(/^www\./, ''), MAX_FIELD_LENGTH);
}

function normalizePath(pathname: string): string {
  const trimmed = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  return clamp(trimmed === '' ? '/' : trimmed, MAX_PATH_LENGTH);
}

/**
 * Only the referrer's host is kept. Full referrer URLs routinely carry search
 * terms, session tokens and internal paths — storing them would undercut the
 * whole point of the project.
 */
function referrerHost(referrer: string, siteDomain: string): string {
  if (referrer === '') return '';
  try {
    const host = new URL(referrer).hostname.toLowerCase().replace(/^www\./, '');
    return host === siteDomain ? '' : clamp(host, MAX_FIELD_LENGTH);
  } catch {
    return '';
  }
}

/**
 * Screen width, kept as one of four buckets.
 *
 * The exact pixel width is a meaningful fingerprinting signal and we have no
 * use for it, so it is thrown away at the door rather than stored and bucketed
 * later.
 */
function screenBucket(raw: unknown): string {
  const width = typeof raw === 'number' ? raw : Number.parseInt(String(raw ?? ''), 10);
  if (!Number.isFinite(width) || width <= 0) return '';
  if (width >= 1440) return '≥ 1440px';
  if (width >= 1024) return '1024–1439';
  if (width >= 768) return '768–1023';
  return '< 768px';
}

async function insertEvent(db: D1Database, table: string, values: unknown[]): Promise<void> {
  const placeholders = RAW_COLUMNS.split(',').map(() => '?').join(', ');
  const sql = `INSERT INTO ${table} (${RAW_COLUMNS}) VALUES (${placeholders})`;

  try {
    await db.prepare(sql).bind(...values).run();
    return;
  } catch (error) {
    const message = String(error);
    // Always recover from a missing table, even if this isolate believed it
    // existed — the rollup job drops tables, and a cached belief must never be
    // the reason an event is lost.
    if (/no such table/i.test(message)) {
      await db.prepare(createRawTableSql(table)).run();
    } else if (/no such column|has no column named/i.test(message)) {
      // The hour in flight was created by an older build. Widening it is DDL,
      // so it costs nothing and the event still lands in its own hour.
      await alterRawTable(db, table);
    } else {
      throw error;
    }
  }

  await db.prepare(sql).bind(...values).run();
}

/**
 * Read a body of at most `limit` bytes, or null if it runs past that.
 *
 * The Content-Length check upstream only catches clients that declare their
 * size honestly. Reading the stream chunk by chunk and cancelling it at the
 * cap is what stops a chunked or mislabelled body from being buffered whole.
 */
async function readBounded(request: Request, limit: number): Promise<string | null> {
  if (!request.body) return '';

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

// ---- 国内 CDN 回源：还原真实访客 IP / 国家 ----

function ipToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const b = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (b.some((x) => x > 255)) return null;
  return (b[0] * 16777216 + b[1] * 65536 + b[2] * 256 + b[3]) >>> 0;
}

function ipInCidr(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf("/");
  if (slash < 0) return ip === cidr;
  const base = cidr.slice(0, slash);
  const bits = Number(cidr.slice(slash + 1));
  const ipInt = ipToInt(ip);
  const baseInt = ipToInt(base);
  if (ipInt === null || baseInt === null) return false;
  if (bits <= 0) return true;
  if (bits >= 32) return ipInt === baseInt;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function ipInCidrs(ip: string, cidrs: string[]): boolean {
  return cidrs.some((c) => ipInCidr(ip, c.trim()));
}

function isPublicV4(ip: string): boolean {
  const n = ipToInt(ip);
  if (n === null) return false;
  for (const priv of ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8"]) {
    if (ipInCidr(ip, priv)) return false;
  }
  return true;
}

/**
 * 当直接连到 Cloudflare 的是受信的国内 CDN 出口时，真实访客 IP 位于
 * X-Forwarded-For 中。取「最右一个非信任且为公网」的条目（即 CDN 追加的客户端 IP）。
 * 取最右而非最左，可规避访客自行伪造 XFF 头。
 */
function realClientIp(request: Request, trustedCidrs: string[]): string {
  const connecting = request.headers.get("cf-connecting-ip") ?? "";
  const xff = request.headers.get("x-forwarded-for");
  if (connecting && trustedCidrs.length && ipInCidrs(connecting, trustedCidrs) && xff) {
    const ips = xff.split(",").map((s) => s.trim()).filter(Boolean);
    for (let i = ips.length - 1; i >= 0; i--) {
      const ip = ips[i];
      if (!ipInCidrs(ip, trustedCidrs) && isPublicV4(ip)) return ip;
    }
    if (ips.length) return ips[ips.length - 1]; // 兜底：最右
  }
  return connecting;
}

/**
 * 国家判定：优先用真实访客 IP 在本地 ip2region 库里反查（解决国内被错归为 CDN 出口国），
 * 拿不到或异常时回退到 Cloudflare 自带的 cf.country（海外本来就是准的）。
 */
async function resolveCountry(request: Request, realIp: string, geoKv?: KVNamespace): Promise<string> {
  const cfCountry = (request.cf?.country as string | undefined) ?? "";
  if (geoKv) {
    try {
      const g = await lookupIp(geoKv, realIp);
      if (g) {
        const code = cnCountryToCode(g.country);
        if (code) return code; // 国内 IP：用本地库定的国家，准确
        if (cfCountry) return cfCountry; // 国外真实 IP：仍用 cf.country
      }
    } catch {
      // 地理库任何异常都不能影响统计，回退 cf.country
    }
  }
  return cfCountry;
}

export async function handleIngest(request: Request, env: Env): Promise<Response> {
  const declaredLength = Number(request.headers.get('content-length') ?? '0');
  if (declaredLength > MAX_BODY_BYTES) return beaconResponse(413, 'payload too large');

  const raw = await readBounded(request, MAX_BODY_BYTES);
  if (raw === null) return beaconResponse(413, 'payload too large');

  let payload: EventPayload;
  try {
    payload = JSON.parse(raw) as EventPayload;
  } catch {
    return beaconResponse(400, 'invalid payload');
  }

  const userAgent = request.headers.get('user-agent') ?? '';
  // Bots are dropped before any write so they never touch the row budget.
  if (isBot(userAgent)) return beaconResponse(204);

  if (typeof payload.d !== 'string' || typeof payload.u !== 'string') {
    return beaconResponse(400, 'invalid payload');
  }

  const domain = normalizeDomain(payload.d);
  const site = await env.DB.prepare('SELECT id FROM sites WHERE domain = ?')
    .bind(domain)
    .first<{ id: number }>();

  // A clear 404 here is worth the enumeration risk: "I pasted the snippet and
  // nothing showed up" is the single most common self-hosting failure, and the
  // usual cause is a domain mismatch.
  if (!site) return beaconResponse(404, `site not registered: ${domain}`);

  let target: URL;
  try {
    target = new URL(payload.u);
  } catch {
    return beaconResponse(400, 'invalid url');
  }

  const now = Math.floor(Date.now() / 1000);
  const parts = partsForTs(now);
  const trustedCidrs = (env.TRUSTED_PROXY_CIDRS ?? "")  
    .split(",").map((s) => s.trim()).filter(Boolean);  
  const ip = realClientIp(request, trustedCidrs);
  const visitor = await computeVisitor(env.DB, parts, site.id, ip, userAgent);

  const { browser, os, device } = parseUa(userAgent);
  const name = typeof payload.n === 'string' && payload.n !== '' ? clamp(payload.n, 64) : 'pageview';
  const referrer = typeof payload.r === 'string' ? payload.r : '';
  const params = target.searchParams;
  const country = await resolveCountry(request, ip, env.GEO_KV);


  await insertEvent(env.DB, rawTable(parts.suffix), [
    site.id,
    now,
    visitor,
    name,
    normalizePath(target.pathname),
    referrerHost(referrer, domain),
    clamp(country, 8),
    browser,
    os,
    device,
    screenBucket(payload.w),
    clamp(params.get('utm_source') ?? '', MAX_FIELD_LENGTH),
    clamp(params.get('utm_medium') ?? '', MAX_FIELD_LENGTH),
    clamp(params.get('utm_campaign') ?? '', MAX_FIELD_LENGTH),
  ]);

  return beaconResponse(204);
}
