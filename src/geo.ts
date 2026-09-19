/**
 * GeoIP resolution for requests arriving through a CDN (lightcdn, etc.).
 *
 * When the Worker sits behind a CDN, `cf-connecting-ip` and `request.cf?.country`
 * describe the CDN's edge node, not the visitor. For edgemetry that means:
 *   - every visitor is counted as coming from the CDN's country (e.g. US), and
 *   - every visitor shares the CDN's IP, so the visitor hash collapses and UV
 *     is undercounted to ~1.
 *
 * This module reads the real client IP from the headers the CDN injects
 * (X-Real-IP / X-Forwarded-For) and resolves the country from that IP via a
 * cached GeoIP lookup. The raw IP is used only in memory to derive the country
 * and the visitor hash — it is never persisted, matching edgemetry's GDPR shape.
 */

/**
 * Headers that may carry the real client IP, in priority order.
 *
 * `X-Real-IP` is set by the CDN to the connection it received — it overwrites
 * anything the client sent, so it is trusted first. `True-Client-IP` is the
 * Cloudflare Access / Akamai equivalent. `cf-connecting-ip` is the direct
 * connection (no CDN in front) and is checked last so a spoofed X-Real-IP from
 * a direct request cannot override it — if X-Real-IP is present at all, we
 * assume the request came through the CDN.
 */
const REAL_IP_HEADERS = [
  'x-real-ip',
  'true-client-ip',
];

/**
 * Extract the visitor's real IP.
 *
 * `X-Forwarded-For` is checked last because it is a chain and the leftmost
 * entry is the most easily spoofed — a client can prepend `1.2.3.4, ` to it
 * and a CDN that appends rather than overwrites will leave the fake in front.
 * `X-Real-IP` is set by the CDN to the connection it received, so it is
 * trusted first.
 */
export function getRealIp(request: Request): string {
  for (const header of REAL_IP_HEADERS) {
    const value = request.headers.get(header);
    if (value) {
      const ip = value.trim();
      if (isValidIp(ip)) return ip;
    }
  }

  // X-Forwarded-For: "client, proxy1, proxy2" — take the first entry.
  const xff = request.headers.get('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first && isValidIp(first)) return first;
  }

  // Direct connection (no CDN in front of the Worker).
  const cf = request.headers.get('cf-connecting-ip');
  if (cf) return cf;

  return '';
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-f:]+$/i;

function isValidIp(ip: string): boolean {
  if (!ip) return false;
  if (IPV4.test(ip)) {
    return ip.split('.').every((octet) => {
      const n = Number(octet);
      return n >= 0 && n <= 255;
    });
  }
  return IPV6.test(ip);
}

/** Loopback / private / link-local ranges have no country. */
function isPrivateIp(ip: string): boolean {
  return (
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip.startsWith('169.254.') ||
    ip.startsWith('fc') ||
    ip.startsWith('fd') ||
    ip === '::'
  );
}

/**
 * Bounded per-isolate cache. The edge cache (via `cf: { cacheTtl }`) already
 * deduplicates across requests, but this saves a subrequest round-trip when
 * the same IP hits the same isolate twice in quick succession — common for a
 * visitor loading multiple pages.
 */
const countryCache = new Map<string, string>();
const COUNTRY_CACHE_MAX = 2000;

/**
 * Resolve a country code (ISO 3166-1 alpha-2) from an IP.
 *
 * Uses ipwho.is (free, HTTPS, no API key, no documented rate limit) with
 * Cloudflare edge caching (`cacheTtl: 86400`) so each unique IP is queried at
 * most once per day per colo. Falls back to `request.cf?.country` — which
 * behind a CDN is the CDN node's country — only if the lookup fails or times
 * out. An empty string is returned for private/loopback IPs.
 *
 * The lookup has a 2-second timeout. If it elapses, the request proceeds with
 * the fallback country rather than blocking the beacon response.
 */
export async function getCountry(request: Request, ip: string): Promise<string> {
  if (!ip || isPrivateIp(ip)) {
    return (request.cf?.country as string | undefined) ?? '';
  }

  const cached = countryCache.get(ip);
  if (cached !== undefined) return cached;

  let country = '';
  try {
    const resp = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      cf: { cacheTtl: 86400, cacheEverything: true },
      signal: AbortSignal.timeout(2000),
    });
    if (resp.ok) {
      const data = (await resp.json()) as {
        success?: boolean;
        country_code?: string;
      };
      if (data.success && data.country_code) {
        country = data.country_code.toUpperCase();
      }
    }
  } catch {
    // Timeout, DNS failure, or bad JSON — fall through to the CDN-derived
    // country. Better a US label than a dropped beacon.
  }

  if (!country) {
    country = (request.cf?.country as string | undefined) ?? '';
  }

  if (countryCache.size > COUNTRY_CACHE_MAX) countryCache.clear();
  countryCache.set(ip, country);

  return country;
}
