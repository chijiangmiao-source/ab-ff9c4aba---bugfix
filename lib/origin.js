// 逐字节来源包号（审计依据）工具。
// 重组链路上每个字节都记录“实际承载过它的全部原始包号”：
// 内容完全相同的重叠分片 / 重传段，其包号必须全部保留，供审查员复算。
// 约定：每个标签都是升序、无重复的包号数组；合并总是返回新数组，
// 绝不原地修改——因此同一标签实例可以安全地被多个字节共享。

export function tagPacket(packet) {
  return [packet];
}

export function mergeTags(a, b) {
  if (a == null) return b;
  if (b == null) return a;
  let extra = null;
  for (const p of b) {
    if (!a.includes(p)) {
      if (extra === null) extra = [];
      extra.push(p);
    }
  }
  if (extra === null) return a;
  return [...a, ...extra].sort((x, y) => x - y);
}
