import { fail } from './errors.js';

// IPv4 分片重组：键 = (源, 目的, 协议, 标识)。
// 检测：同偏移分片内容冲突、末片缺失、中间缺片（空洞）。
// 重组后的数据报保留“每个分片实际承载的数据报区间”作为审计凭据：
// 内容完全相同的重叠分片会同时留下两份区间，任一字节不同即冲突拒绝。

class FragmentGroup {
  constructor(key, firstPacket, src, dst) {
    this.key = key;
    this.firstPacket = firstPacket;
    this.src = src;
    this.dst = dst;
    this.fragments = []; // {packet, start(字节), end, bytes}
    this.finalEnd = null; // 末片（MF=0）给出的数据报总长度
    this.lastPacket = null;
  }

  add(ip) {
    const start = ip.fragOffset * 8;
    const end = start + ip.payload.length;
    // 同偏移/重叠分片：逐字节比较，任何字节不同即拒绝（定位首个相异字节）
    for (const f of this.fragments) {
      const lo = Math.max(start, f.start);
      const hi = Math.min(end, f.end);
      if (lo < hi) {
        for (let i = lo; i < hi; i++) {
          if (ip.payload[i - start] !== f.bytes[i - f.start]) {
            const [p1, p2] = f.packet < ip.num ? [f.packet, ip.num] : [ip.num, f.packet];
            throw fail('FRAGMENT_CONFLICT',
              `分片字节冲突：包 ${p1} 与包 ${p2} 在同一 IP 数据报偏移 ${i} 处字节不同，禁止任选其一拼接`, {
                packet: p1,
                packet2: p2,
                offset: i,
                range: conflictRun(ip.payload, start, f.bytes, f.start, lo, hi),
              });
          }
        }
      }
    }
    this.fragments.push({ packet: ip.num, start, end, bytes: ip.payload });
    if (this.firstPacket > ip.num) this.firstPacket = ip.num;
    if (!ip.mf) {
      if (this.finalEnd !== null && this.finalEnd !== end) {
        throw fail('FRAGMENT_CONFLICT',
          `同一组分片出现两个长度不一致的末片（包 ${this.lastPacket} 与包 ${ip.num}）`, {
            packet: Math.min(this.lastPacket, ip.num),
            packet2: Math.max(this.lastPacket, ip.num),
            offset: Math.min(this.finalEnd, end),
          });
      }
      this.finalEnd = end;
      this.lastPacket = ip.num;
    }
  }
}

function conflictRun(aBytes, aOff, bBytes, bOff, lo, hi) {
  let s = lo;
  while (s < hi && aBytes[s - aOff] === bBytes[s - bOff]) s++;
  let e = s;
  while (e < hi && aBytes[e - aOff] !== bBytes[e - bOff]) e++;
  return [s, e];
}

export function reassembleDatagrams(ipPackets) {
  const datagrams = [];
  const groups = new Map();

  for (const ip of ipPackets) {
    if (!ip.mf && ip.fragOffset === 0) {
      datagrams.push({
        kind: 'single', firstPacket: ip.num, packets: [ip.num],
        src: ip.src, dst: ip.dst, data: ip.payload,
        // 单包数据报：整段载荷均由该原始包实际承载
        coverage: [{ packet: ip.num, start: 0, end: ip.payload.length }],
      });
      continue;
    }
    const key = `${[...ip.src, ...ip.dst, ip.proto, ip.id >>> 8, ip.id & 0xff].join('.')}`;
    let g = groups.get(key);
    if (!g) {
      g = new FragmentGroup(key, ip.num, ip.src, ip.dst);
      groups.set(key, g);
    }
    g.add(ip);
  }

  const ordered = [...groups.values()].sort((a, b) => a.firstPacket - b.firstPacket);
  for (const g of ordered) {
    const frags = g.fragments.sort((a, b) => a.start - b.start || a.packet - b.packet);
    // 扫描空洞
    let expect = 0;
    for (const f of frags) {
      if (f.start > expect) break; // 空洞，跳出后统一报告
      if (f.end > expect) expect = f.end;
    }
    if (g.finalEnd === null || expect < (g.finalEnd ?? Infinity)) {
      const holeEnd = g.finalEnd === null
        ? expect // 末片缺失，空洞起点之后长度未知
        : (() => {
            // 找到空洞后的下一个已到分片起点
            let e = expect;
            for (const f of frags) if (f.start > expect) { e = f.start; break; }
            return e;
          })();
      const next = frags.find((f) => f.start >= expect);
      throw fail('MISSING_FRAGMENT',
        g.finalEnd === null
          ? `IP 分片组（首包 ${g.firstPacket}）缺少末片：偏移 ${expect} 起的数据未捕获，不得用残片拼流`
          : `IP 分片组（首包 ${g.firstPacket}）在数据报偏移 ${expect} 处缺片，存在空洞`,
        {
          packet: g.firstPacket,
          ...(next ? { packet2: next.packet } : {}),
          offset: expect,
          range: g.finalEnd === null ? null : [expect, holeEnd],
          extra: { fragmentPackets: frags.map((f) => f.packet) },
        });
    }
    const data = new Uint8Array(g.finalEnd);
    // 每个分片按其真实的数据报区间写入；重叠部分内容此前已逐字节核对为相同。
    for (const f of frags) {
      for (let i = Math.max(0, f.start); i < Math.min(g.finalEnd, f.end); i++) {
        data[i] = f.bytes[i - f.start];
      }
    }
    // 审计凭据：每个分片（含内容相同的重叠分片）各自保留其真实承载区间。
    const coverage = frags
      .filter((f) => f.end > f.start && f.start < g.finalEnd && f.end > 0)
      .map((f) => ({
        packet: f.packet,
        start: Math.max(0, f.start),
        end: Math.min(g.finalEnd, f.end),
      }))
      .sort((a, b) => a.start - b.start || a.packet - b.packet);
    datagrams.push({
      kind: 'fragment',
      firstPacket: g.firstPacket,
      packets: [...new Set(frags.map((f) => f.packet))].sort((a, b) => a - b),
      src: g.src,
      dst: g.dst,
      data,
      coverage,
    });
  }

  datagrams.sort((a, b) => a.firstPacket - b.firstPacket);
  return datagrams;
}
