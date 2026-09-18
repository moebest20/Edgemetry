// src/geo.ts
// ip2region v2.0 (xdb) IPv4 离线地理查询，数据放在 Cloudflare KV。
// 整个 xdb（约 11 MiB）在每个 isolate 冷启动时整体读入并缓存在模块级变量，
// 之后每次查询都是纯内存 CPU，无额外网络延迟。

const HEADER_LEN = 256;
const VECTOR_INDEX_SIZE = 8; // 4 起始指针 + 4 结束指针
const VECTOR_INDEX_ROWS = 256;
const SEG_INDEX_SIZE = 14; // IPv4 段索引: start(4) + end(4) + len(2) + ptr(4)

let dbCache: Uint8Array | null = null;

function ipToUint32(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const b = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (b.some((x) => x > 255)) return null;
  return (b[0] * 16777216 + b[1] * 65536 + b[2] * 256 + b[3]) >>> 0;
}

function u32(buf: Uint8Array, off: number): number {
  return (buf[off] * 16777216 + buf[off + 1] * 65536 + buf[off + 2] * 256 + buf[off + 3]) >>> 0;
}
function u16(buf: Uint8Array, off: number): number {
  return buf[off] * 256 + buf[off + 1];
}

export interface GeoResult {
  country: string; // ip2region 原始国家名，如 "中国"
  region: string; // 省份
  city: string; // 城市
  isp: string;
  raw: string;
}

export async function loadDb(kv: KVNamespace): Promise<Uint8Array> {
  if (dbCache) return dbCache;
  const buf = await kv.get("ip2region.xdb", { type: "arrayBuffer" });
  if (!buf) throw new Error("ip2region.xdb 未上传到 GEO_KV");
  dbCache = new Uint8Array(buf);
  return dbCache;
}

export async function lookupIp(kv: KVNamespace, ip: string): Promise<GeoResult | null> {
  const ipInt = ipToUint32(ip);
  if (ipInt === null) return null; // IPv6 / 非法 -> 由调用方回退
  const db = await loadDb(kv);

  const il0 = (ipInt >>> 24) & 255;
  const il1 = (ipInt >>> 16) & 255;
  const idx = (il0 * VECTOR_INDEX_ROWS + il1) * VECTOR_INDEX_SIZE;
  const sPtr = u32(db, HEADER_LEN + idx);
  const ePtr = u32(db, HEADER_LEN + idx + 4);
  if (sPtr === 0 || ePtr === 0) return null;

  let l = 0;
  let h = Math.floor((ePtr - sPtr) / SEG_INDEX_SIZE);
  let dataLen = 0;
  let dataPtr = 0;
  while (l <= h) {
    const m = (l + h) >> 1;
    const p = sPtr + m * SEG_INDEX_SIZE;
    const segStart = u32(db, p);
    const segEnd = u32(db, p + 4);
    if (ipInt < segStart) h = m - 1;
    else if (ipInt > segEnd) l = m + 1;
    else {
      dataLen = u16(db, p + 8);
      dataPtr = u32(db, p + 10);
      break;
    }
  }
  if (dataLen === 0) return null;
  const region = new TextDecoder().decode(db.subarray(dataPtr, dataPtr + dataLen));
  const parts = region.split("|");
  return {
    country: parts[0] ?? "",
    region: parts[2] ?? "",
    city: parts[3] ?? "",
    isp: parts[4] ?? "",
    raw: region,
  };
}

// ip2region 国家名 -> ISO 3166-1 alpha-2（与 Cloudflare cf.country 对齐）
export function cnCountryToCode(name: string): string {
  switch (name) {
    case "中国":
      return "CN";
    case "香港":
      return "HK";
    case "台湾":
      return "TW";
    case "澳门":
      return "MO";
    default:
      return "";
  }
}
