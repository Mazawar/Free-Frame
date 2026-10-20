import type { Packet } from '../types'

/** 层着色:低饱和、深底可读(GitHub Dark 语法色系)。 */
export const LAYER_COLORS = ['#79c0ff', '#d2a8ff', '#7ee787', '#ffa657', '#ff7b72', '#56d4dd']

export function layerColor(index: number): string {
  return LAYER_COLORS[index % LAYER_COLORS.length]!
}

/** 层在帧中的色(按协议 id 稳定取色,同一协议列表/详情/hex 一致)。 */
export function layerColorOf(packet: Packet, layerIndex: number): string {
  return layerColor(layerIndex)
}

export function fmtTime(ts: number): string {
  const d = new Date(ts)
  const pad = (n: number, w = 2) => String(n).padStart(w, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`
}

export interface Endpoints { src: string; dst: string }

/** 提取五元组的源/目的:ipv4 → arp → ethernet 兜底。 */
export function endpoints(p: Packet): Endpoints {
  const ip = p.layers.find(l => l.id === 'ipv4' || l.id === 'ipv6')
  if (ip && ip.fields.sourceIp != null) {
    return { src: String(ip.fields.sourceIp), dst: String(ip.fields.destinationIp ?? '?') }
  }
  const arp = p.layers.find(l => l.id === 'arp')
  if (arp) return { src: String(arp.fields.senderIp ?? '?'), dst: String(arp.fields.targetIp ?? '?') }
  const eth = p.layers.find(l => l.id === 'ethernet')
  if (eth) return { src: String(eth.fields.srcMac ?? '-'), dst: String(eth.fields.dstMac ?? '-') }
  return { src: '-', dst: '-' }
}

/** 最深一层协议 id(列表"协议"列)。 */
export function protocolOf(p: Packet): { id: string; index: number } {
  const i = p.layers.length - 1
  return { id: p.layers[i]?.id ?? '-', index: i }
}

/** 信息列(Wireshark 风格)。 */
export function info(p: Packet): string {
  const tp = p.layers.find(l => l.id === 'udp' || l.id === 'tcp')
  const app = p.layers[p.layers.length - 1]
  if (tp) {
    let s = `${tp.fields.srcPort} → ${tp.fields.dstPort}`
    if (app && !['ethernet', 'ipv4', 'udp', 'tcp', 'icmp'].includes(app.id)) {
      const tail = p.len - (app.offset + app.headerLen)
      s += tail > 0 ? ` [${app.name},后续 ${tail} B 无已注册子协议]` : ` [${app.name}]`
    }
    return s
  }
  const arp = p.layers.find(l => l.id === 'arp')
  if (arp) {
    const op = Number(arp.fields.operation)
    return op === 1
      ? `Who has ${arp.fields.targetIp}? Tell ${arp.fields.senderIp}`
      : `${arp.fields.senderIp} is at ${arp.fields.senderMac}`
  }
  const icmp = p.layers.find(l => l.id === 'icmp')
  if (icmp) {
    const t = Number(icmp.fields.type)
    if (t === 8) return 'Echo (ping) request'
    if (t === 0) return 'Echo (ping) reply'
    return `type=${icmp.fields.type} code=${icmp.fields.code}`
  }
  // 兜底:最深层名;若其后仍有字节,显式提示「只解析已注册协议」机制停在此层
  const last = p.layers[p.layers.length - 1]
  if (last) {
    const tail = p.len - (last.offset + last.headerLen)
    return tail > 0 ? `${last.name}, 后续 ${tail} B 无已注册子协议` : last.name
  }
  return p.path
}

export interface HexRow {
  offset: number
  cells: { hex: string; ascii: string; color: string | null }[]
}

export function hexRows(p: Packet): HexRow[] {
  const bytes = p.hex.length / 2
  const hexUpper = p.hex.toUpperCase()
  const spans = p.layers.map((l, i) => ({
    start: l.offset, end: l.offset + Math.max(1, l.headerLen), color: layerColor(i),
  }))
  const rows: HexRow[] = []
  for (let base = 0; base < bytes; base += 16) {
    const cells: HexRow['cells'] = []
    for (let i = 0; i < 16 && base + i < bytes; i++) {
      const idx = base + i
      const hexByte = hexUpper.substr(idx * 2, 2)
      const code = parseInt(hexByte, 16)
      const span = spans.find(s => idx >= s.start && idx < s.end)
      cells.push({
        hex: hexByte,
        ascii: code >= 32 && code < 127 ? String.fromCharCode(code) : '.',
        color: span?.color ?? null,
      })
    }
    rows.push({ offset: base, cells })
  }
  return rows
}

/** 层摘要行(Wireshark 风格):Ethernet II, Src: …, Dst: … */
export function layerSummary(l: { id: string; name: string; fields: Record<string, unknown> }): string {
  const f = l.fields
  switch (l.id) {
    case 'ethernet':
      return `Ethernet II, Src: ${f.srcMac ?? '?'}, Dst: ${f.dstMac ?? '?'}`
    case 'ipv4':
      return `Internet Protocol Version 4, Src: ${f.sourceIp ?? '?'}, Dst: ${f.destinationIp ?? '?'}`
    case 'ipv6':
      return `Internet Protocol Version 6, Src: ${f.sourceIp ?? '?'}, Dst: ${f.destinationIp ?? '?'}`
    case 'udp':
      return `User Datagram Protocol, Src Port: ${f.srcPort ?? '?'}, Dst Port: ${f.dstPort ?? '?'}`
    case 'tcp':
      return `Transmission Control Protocol, Src Port: ${f.srcPort ?? '?'}, Dst Port: ${f.dstPort ?? '?'}`
    case 'arp':
      return `Address Resolution Protocol (${Number(f.operation) === 1 ? 'request' : 'reply'})`
    case 'icmp':
      return `Internet Control Message Protocol (type ${f.type ?? '?'})`
    default:
      return l.name
  }
}

/** 剪贴板(localhost 为安全上下文,clipboard API 可用;失败退回 execCommand)。 */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    try {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      const ok = document.execCommand('copy')
      ta.remove()
      return ok
    } catch {
      return false
    }
  }
}

export function fmtValue(v: unknown): string {
  if (v === null || v === undefined) return 'null'
  if (Array.isArray(v)) return v.map(x => (typeof x === 'object' && x !== null ? JSON.stringify(x) : String(x))).join(', ')
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}
