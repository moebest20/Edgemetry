/**
 * Event ingestion. One pageview should cost exactly one row written, so this
 * path does no UPDATEs, touches no indexed table, and never reads back what it
 * just wrote.
 *
 * CN-FIX (edgemetry-cn-fix): 当请求来自受信的国内 CDN 回源时，从
 * X-Forwarded-For 还原真实访客 IP，并用 ip2region 对真实 IP 做本地地理反查，
 * 覆盖按 CDN 出口算出的 cf.country。海外直连流量不受影响。
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
    if (/no such table/i.test(message)) {
      await db.prepare(createRawTableSql(table)).run();
    } else if (/no such column|has no column named/i.test(message)) {
      await alterRawTable(db, table);
    } else {
      throw error;
    }
  }

  await db.prepare(sql).bind(...values).run();
}

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

/**
 * CN-FIX: 还原真实访客 IP。
 * 仅当「直接连到 Cloudflare 的那台机器」(cf-connecting-ip) 落在你信任的 CDN
 * 回源出口段内时，才相信 X-Forwarded-For，并取最左端（= 原始访客）。
 * 否则（海外直连 / 不可信）保持使用 cf-connecting-ip，行为与原版一致。
 */
function parseCidr(cidr: string): { base: number; mask: number } | null {
  const [addr, bitsStr] = cidr.trim().split('/');
  const bits = bitsStr === undefined ? 32 : Number(bitsStr);
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
  if (!m) return null;
  const b = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (b.some((x) => x > 255) || Number.isNaN(bits) || bits < 0 || bits > 32) return null;
  const base = (b[0] * 16777216 + b[1] * 65536 + b[2] * 256 + b[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base, mask };
}

function ipToUint32(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const b = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (b.some((x) => x > 255)) return null;
  return (b[0] * 16777216 + b[1] * 65536 + b[2] * 256 + b[3]) >>> 0;
}

function realClientIp(request: Request, trustedCidrs: string[]): string {
  const connecting = request.headers.get('cf-connecting-ip') ?? '';
  const xff = request.headers.get('x-forwarded-for');
  if (!xff || !connecting) return connecting;
  const connInt = ipToUint32(connecting);
  if (connInt === null) return connecting;
  const trusted = trustedCidrs
    .map(parseCidr)
    .filter((x): x is { base: number; mask: number } => x !== null);
  const isTrusted = trusted.some(({ base, mask }) => (connInt & mask) === (base & mask));
  if (!isTrusted) return connecting;
  // XFF 最左端是原始访客（CDN 追加在右端），访客自填的最左条目会被忽略。
  const first = xff.split(',')[0]?.trim();
  return first && first.length > 0 ? first : connecting;
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
  if (isBot(userAgent)) return beaconResponse(204);

  if (typeof payload.d !== 'string' || typeof payload.u !== 'string') {
    return beaconResponse(400, 'invalid payload');
  }

  const domain = normalizeDomain(payload.d);
  const site = await env.DB.prepare('SELECT id FROM sites WHERE domain = ?')
    .bind(domain)
    .first<{ id: number }>();

  if (!site) return beaconResponse(404, `site not registered: ${domain}`);

  let target: URL;
  try {
    target = new URL(payload.u);
  } catch {
    return beaconResponse(400, 'invalid url');
  }

  const now = Math.floor(Date.now() / 1000);
  const parts = partsForTs(now);

  // CN-FIX: 还原真实访客 IP（受信 CDN 出口时才读 XFF）
  const trustedCidrs = (env.TRUSTED_PROXY_CIDRS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const ip = realClientIp(request, trustedCidrs);

  const visitor = await computeVisitor(env.DB, parts, site.id, ip, userAgent);

  const { browser, os, device } = parseUa(userAgent);
  const name = typeof payload.n === 'string' && payload.n !== '' ? clamp(payload.n, 64) : 'pageview';
  const referrer = typeof payload.r === 'string' ? payload.r : '';
  const params = target.searchParams;

  // CN-FIX: 用真实 IP 做 ip2region 反查，得到 ISO 国家码；查不到再回退 cf.country
  let country = (request.cf?.country as string | undefined) ?? '';
  try {
    const g = await lookupIp(env.GEO_KV, ip);
    if (g) {
      const code = cnCountryToCode(g.country);
      if (code) country = code;
    }
  } catch {
    // KV 未配置 / xdb 缺失时静默回退，不影响统计
  }

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
