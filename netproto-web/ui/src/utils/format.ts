import type { Packet } from '../types'

export const LAYER_COLORS = ['#38bdf8', '#a78bfa', '#4ade80', '#fbbf24', '#fb7185', '#2dd4bf']

export function layerColor(index: number): string {
  return LAYER_COLORS[index % LAYER_COLORS.length]!
}

/** 概要:优先 IP 五元组,其次 ARP,退化到协议路径。字段值已由服务端格式化(MAC/IP 可读)。 */
export function summary(p: Packet): string {
  const ipv4 = p.layers.find(l => l.id === 'ipv4')
  const tp = p.layers.find(l => l.id === 'udp' || l.id === 'tcp')
  const app = p.layers[p.layers.length - 1]
  if (ipv4) {
    let s = `${ipv4.fields.sourceIp ?? '?'} → ${ipv4.fields.destinationIp ?? '?'}`
    if (tp) s += ` :${tp.fields.srcPort}→${tp.fields.dstPort}`
    if (app && !['ethernet', 'ipv4', 'udp', 'tcp', 'icmp'].includes(app.id)) s += ` [${app.name}]`
    return s
  }
  const arp = p.layers.find(l => l.id === 'arp')
  if (arp) return `ARP ${arp.fields.operation === 1 ? 'request' : 'reply'} ${arp.fields.senderIp} → ${arp.fields.targetIp}`
  const icmp = p.layers.find(l => l.id === 'icmp')
  if (icmp) return `ICMP type=${icmp.fields.type} code=${icmp.fields.code}`
  return p.path
}

export function fmtTime(ts: number): string {
  const d = new Date(ts)
  const pad = (n: number, w = 2) => String(n).padStart(w, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`
}

export function fmtValue(v: unknown): string {
  if (v === null || v === undefined) return 'null'
  if (Array.isArray(v)) return v.map(x => (typeof x === 'object' && x !== null ? JSON.stringify(x) : String(x))).join(', ')
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

/** hex dump 行(16B/行),按层着色。 */
export interface HexRow {
  offset: number
  cells: { hex: string; ascii: string; color: string | null }[]
}

export function hexRows(p: Packet): HexRow[] {
  const bytes = p.hex.length / 2
  const spans = p.layers.map((l, i) => ({
    start: l.offset, end: l.offset + Math.max(1, l.headerLen), color: layerColor(i),
  }))
  const rows: HexRow[] = []
  for (let base = 0; base < bytes; base += 16) {
    const cells: HexRow['cells'] = []
    for (let i = 0; i < 16 && base + i < bytes; i++) {
      const idx = base + i
      const hexByte = p.hex.substr(idx * 2, 2)
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

export function fmtBytes(n: number): string {
  return n >= 1024 * 1024 ? (n / 1024 / 1024).toFixed(1) + ' MB' : n >= 1024 ? (n / 1024).toFixed(1) + ' KB' : `${n}`
}
