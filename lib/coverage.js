// 流内字节来源（审计凭据）的区间工具。
// 一条 coverage 记录 = { packet, start, end }：原始包 packet 实际承载了
// 流内（或数据报/TCP 载荷内，视上下文）半开区间 [start, end) 的字节。
// 同一字节允许被多条记录覆盖——对应“内容完全相同的重叠分片/重传段”，
// 两份原始包凭据都必须保留；任一字节不同则应在更上层直接判冲突。

// 把 coverage 裁剪到半开区间 [lo, hi) 后按 packet 归并，
// 返回 [{ packet, ranges: [[起, 止), …] }]（packet 升序、区间升序、相邻已合并）。
export function sourcesFor(coverage, lo, hi) {
  const byPacket = new Map();
  for (const iv of coverage) {
    const s = Math.max(iv.start, lo);
    const e = Math.min(iv.end, hi);
    if (s < e) {
      if (!byPacket.has(iv.packet)) byPacket.set(iv.packet, []);
      byPacket.get(iv.packet).push([s, e]);
    }
  }
  return [...byPacket.keys()].sort((a, b) => a - b).map((packet) => {
    const raw = byPacket.get(packet).sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    const ranges = [];
    for (const [s, e] of raw) {
      const last = ranges[ranges.length - 1];
      if (last && s <= last[1]) {
        if (e > last[1]) last[1] = e;
      } else {
        ranges.push([s, e]);
      }
    }
    return { packet, ranges };
  });
}

// 覆盖指定偏移的全部原始包号（升序）。
export function coveringPackets(coverage, pos) {
  const ps = new Set();
  for (const iv of coverage) {
    if (iv.start <= pos && pos < iv.end) ps.add(iv.packet);
  }
  return [...ps].sort((a, b) => a - b);
}

// 整条流按原始包汇总的实际承载区间（包号升序）。
export function groupByPacket(coverage) {
  return sourcesFor(coverage, 0, Infinity);
}
