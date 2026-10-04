import { fail } from './errors.js';
import { sourcesFor, coveringPackets } from './coverage.js';

// 长度前缀 ASCII 指令解析。
// 帧格式：[2 字节大端长度 n][n 字节 ASCII 载荷]，帧首尾相接。
// 要求：
//  - n 必须恰好被剩余字节容纳（长度不完整即截断指令，拒绝）；
//  - 载荷全部为可见 ASCII（0x20-0x7E）；
//  - 整段流必须被指令恰好耗尽，任何尾随残字节（连一个长度前缀都凑不齐）也拒绝。
// coverage 为流内字节的原始包承载区间（同一字节可有多个包凭据）。
export function parseCommands(stream, coverage) {
  const commands = [];
  let pos = 0;
  const total = stream.length;
  const packetAt = (i) => coveringPackets(coverage, i)[0] ?? null;
  while (pos < total) {
    if (total - pos < 2) {
      throw fail('TRAILING_BYTES',
        `流尾残留 ${total - pos} 字节，凑不出 2 字节长度前缀，拒绝输出任何半截指令`, {
          offset: pos,
          range: [pos, total],
          packet: packetAt(pos),
        });
    }
    const n = (stream[pos] << 8) | stream[pos + 1];
    const prefixStart = pos;
    const payloadStart = pos + 2;
    const payloadEnd = payloadStart + n;
    if (n === 0) {
      throw fail('INVALID_COMMAND', '长度前缀为 0：空指令不构成有效 ASCII 指令', {
        offset: prefixStart,
        range: [prefixStart, payloadStart],
        packet: packetAt(prefixStart),
      });
    }
    if (payloadEnd > total) {
      throw fail('TRUNCATED_COMMAND',
        `偏移 ${prefixStart} 处长度前缀声明 ${n} 字节载荷，但 FIN 前流只剩 ${total - payloadStart} 字节，指令被截断`, {
          offset: prefixStart,
          range: [prefixStart, total],
          packet: packetAt(prefixStart),
          extra: { declaredLength: n, remaining: total - payloadStart },
        });
    }
    let text = '';
    for (let i = payloadStart; i < payloadEnd; i++) {
      const b = stream[i];
      if (b < 0x20 || b > 0x7e) {
        throw fail('NON_ASCII',
          `第 ${commands.length + 1} 条指令载荷偏移 ${i} 处字节 0x${b.toString(16).padStart(2, '0')} 不是可见 ASCII，拒绝输出`, {
            offset: i,
            range: [i, i + 1],
            packet: packetAt(i),
          });
      }
      text += String.fromCharCode(b);
    }
    // 该指令（含前缀）流内区间内，每个原始包实际承载的半开区间；
    // 相同内容的重叠分片会让同一字节同时出现在两个包的 ranges 中（两份审计凭据）。
    const sources = sourcesFor(coverage, prefixStart, payloadEnd);
    commands.push({
      index: commands.length,
      text,
      length: n,
      byteRange: [prefixStart, payloadEnd],      // 含 2 字节长度前缀（流内半开区间）
      payloadRange: [payloadStart, payloadEnd],  // ASCII 载荷区间
      packets: sources.map((s) => s.packet),     // 承载该指令任意字节的全部原始包号
      sources,                                   // 每个原始包在该指令区间内的实际承载区间
    });
    pos = payloadEnd;
  }
  return commands;
}
