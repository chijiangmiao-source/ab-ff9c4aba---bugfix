// 生成“本题捕获样例”：
//  - good.pcap.b64           ：多条指令、TCP 数据报跨多个 IPv4 分片且乱序到达、
//                              32 位序号回绕、相同字节的 TCP 重传，
//                              并额外加入一片与已有分片重叠但内容完全相同的有效分片
//                              （结论仍通过，且保留两份原始包对重叠区间的审计凭据）
//  - conflict.pcap.b64       ：TCP 同序号重传但字节被篡改，必须 CONFLICT 拒绝
//  - fragconflict.pcap.b64  ：与已到分片重叠但重叠字节不同，必须 FRAGMENT_CONFLICT 拒绝
//  - manifest.json           ：期望结论（指令文本/流内区间/每包实际承载区间/冲突定位），供 verify 比对
import { writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { arpFrame, makeSession, pcap } from '../verify/builder.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(__dirname, '..', 'public', 'samples');

const TUPLE = { srcIp: '10.20.30.40', dstIp: '10.20.30.99', srcPort: 5001, dstPort: 9100 };
const COMMANDS = ['NAV FIX A1', 'THR 87 PCT', 'HOLD LEVEL', 'CHK 0x4F2A'];
const ISN = 0xffffffe0;
const ORDER = [2, 4, 0, 5, 1, 3]; // 6 片的乱序到达次序

// 把承载 stream[rel,rel+len) 的 TCP 段按 8 字节切成 IP 分片（末片 4 字节）
function datagramFrags(s, rel, len, fragId) {
  const seg = s.tcpSegment(rel, len);
  const frags = [];
  for (let off = 0; off < seg.length; off += 8) {
    const n = Math.min(8, seg.length - off);
    frags.push(s.ipFrag(seg.subarray(off, off + n), off / 8, off + n < seg.length, { fragId }));
  }
  return frags;
}

// 乱序 + 相同内容重叠分片 + 回绕 + TCP 同字节重传；4 条指令各 12 帧字节，共 48
function buildGood() {
  const s = makeSession({
    srcIpS: TUPLE.srcIp, dstIpS: TUPLE.dstIp,
    sport: TUPLE.srcPort, dport: TUPLE.dstPort,
    isn: ISN, id: 0x3300, commands: COMMANDS,
  });
  const a = datagramFrags(s, 0, 24, 0x3300);  // IP 载荷 44 字节 → 6 片
  const b = datagramFrags(s, 24, 24, 0x3301); // 第二个 TCP 段（seq 越过回绕点）
  const segB = s.tcpSegment(24, 24);
  // 额外分片：IP 偏移 16、长 16 字节，与 b 的 off16/off24 两片重叠且逐字节相同
  // （横跨 TCP 头尾与流内 [24,36)）。必须通过，且两份原始包凭据都保留。
  const dup = s.ipFrag(segB.subarray(16, 32), 2, true, { fragId: 0x3301 });
  const frames = [];
  frames.push(arpFrame());                  // #1 无关噪声
  frames.push(s.syn());                     // #2 SYN（ISN）
  frames.push(s.synack());                  // #3 反向 SYN/ACK
  for (const i of ORDER) frames.push(a[i]); // #4..#9 数据报 A 乱序
  frames.push(dup);                         // #10 数据报 B 的相同内容重叠分片（先到）
  for (const i of ORDER) frames.push(b[i]); // #11..#16 数据报 B 乱序（含与 #10 相同的一片）
  frames.push(s.data(16, 16));              // #17 相同字节 TCP 重传 [16,32)
  frames.push(s.fin(48));                   // #18 FIN
  frames.push(s.serverFin());               // #19 反向 FIN
  return pcap(frames);
}

// TCP 层冲突：同序号段字节被篡改
function buildConflict() {
  const s = makeSession({
    srcIpS: TUPLE.srcIp, dstIpS: TUPLE.dstIp,
    sport: TUPLE.srcPort, dport: TUPLE.dstPort,
    isn: ISN, id: 0x4400, commands: COMMANDS,
  });
  const tampered = Buffer.from(s.stream.subarray(24, 40));
  tampered[6] ^= 0xff; // 流内绝对偏移 30 的字节被改
  const frames = [];
  frames.push(arpFrame());                       // #1
  frames.push(s.syn());                          // #2
  frames.push(s.synack());                       // #3
  const frags = s.dataFrags(0, 16, 8);
  for (const i of [2, 0, 4, 1, 3]) frames.push(frags[i]); // #4..#8
  frames.push(s.data(16, 16));                   // #9 持有原始偏移 30
  frames.push(s.data(8, 8));                     // #10 正常重传
  frames.push(s.data(32, 16));                   // #11
  frames.push(s.data(24, 16, { data: tampered }));// #12 同序号、字节冲突
  frames.push(s.fin(48));                        // #13
  frames.push(s.serverFin());                    // #14
  return pcap(frames);
}

// IP 层冲突：#10 重叠片与 #13（本组 offset 0 的分片）在数据报偏移 6 处字节不同
function buildFragConflict() {
  const s = makeSession({
    srcIpS: TUPLE.srcIp, dstIpS: TUPLE.dstIp,
    sport: TUPLE.srcPort, dport: TUPLE.dstPort,
    isn: ISN, id: 0x5500, commands: COMMANDS,
  });
  const a = datagramFrags(s, 0, 24, 0x5500);
  const b = datagramFrags(s, 24, 24, 0x5501);
  const segB = s.tcpSegment(24, 24);
  // 与 b 的 off16/off24 两片重叠的额外分片，但在数据报偏移 22（=流内偏移 26）处字节不同
  const evil = Buffer.from(segB.subarray(16, 32));
  evil[22 - 16] ^= 0xa5;
  const dup = s.ipFrag(evil, 2, true, { fragId: 0x5501 });
  const frames = [];
  frames.push(arpFrame());                  // #1
  frames.push(s.syn());                     // #2
  frames.push(s.synack());                  // #3
  for (const i of ORDER) frames.push(a[i]); // #4..#9
  frames.push(dup);                         // #10 重叠但内容不同（先到）
  for (const i of ORDER) frames.push(b[i]); // #11..#16；#13 安放时与 #10 冲突
  frames.push(s.data(16, 16));              // #17
  frames.push(s.fin(48));                   // #18
  frames.push(s.serverFin());               // #19
  return pcap(frames);
}

const good = buildGood();
const conflict = buildConflict();
const fragConflict = buildFragConflict();
await mkdir(OUT, { recursive: true });
await writeFile(path.join(OUT, 'good.pcap.b64'), good.toString('base64') + '\n');
await writeFile(path.join(OUT, 'conflict.pcap.b64'), conflict.toString('base64') + '\n');
await writeFile(path.join(OUT, 'fragconflict.pcap.b64'), fragConflict.toString('base64') + '\n');

const streamLength = COMMANDS.reduce((n, c) => n + 2 + c.length, 0);
// good 样例每个原始包在流内的实际承载半开区间（含相同内容重叠分片的双份凭据）
const packetCoverage = [
  [4, [[0, 4]]], [5, [[12, 20]]], [7, [[20, 24]]], [9, [[4, 12]]], [10, [[24, 36]]],
  [11, [[24, 28]]], [12, [[36, 44]]], [14, [[44, 48]]], [16, [[28, 36]]], [17, [[16, 32]]],
].map(([packet, ranges]) => ({ packet, ranges }));
// 每条指令的流内区间与“每个原始包实际承载的流内半开区间”；
// 指令三的 [24,36) 同时由重叠分片 #10 与原分片 #11/#16 承载（两份审计凭据都保留）。
const commandExpectations = [
  { byteRange: [0, 12], payloadRange: [2, 12], sources: [
    { packet: 4, ranges: [[0, 4]] }, { packet: 9, ranges: [[4, 12]] }] },
  { byteRange: [12, 24], payloadRange: [14, 24], sources: [
    { packet: 5, ranges: [[12, 20]] }, { packet: 7, ranges: [[20, 24]] },
    { packet: 17, ranges: [[16, 24]] }] },
  { byteRange: [24, 36], payloadRange: [26, 36], sources: [
    { packet: 10, ranges: [[24, 36]] }, { packet: 11, ranges: [[24, 28]] },
    { packet: 16, ranges: [[28, 36]] }, { packet: 17, ranges: [[24, 32]] }] },
  { byteRange: [36, 48], payloadRange: [38, 48], sources: [
    { packet: 12, ranges: [[36, 44]] }, { packet: 14, ranges: [[44, 48]] }] },
].map((e, i) => ({ index: i, text: COMMANDS[i], ...e }));

const manifest = {
  tuple: TUPLE,
  isn: ISN >>> 0,
  good: {
    file: 'good.pcap.b64',
    ok: true,
    packetCount: 19,
    synPacket: 2,
    finPacket: 18,
    streamLength,
    packetCoverage,
    commands: commandExpectations,
  },
  conflict: {
    file: 'conflict.pcap.b64',
    ok: false,
    code: 'CONFLICT',
    packet: 9,
    packet2: 12,
    offset: 30,
    range: [30, 31],
  },
  fragconflict: {
    file: 'fragconflict.pcap.b64',
    ok: false,
    code: 'FRAGMENT_CONFLICT',
    packet: 10,
    packet2: 11,
    offset: 22,
    range: [22, 23],
  },
};
await writeFile(path.join(OUT, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`samples written to ${OUT}`);
