import { reactive, computed } from 'vue'
import type { Iface, Packet, ProtocolMeta } from './types'
import { api } from './api'

const MAX_PACKETS = 2000

export const store = reactive({
  protocols: [] as ProtocolMeta[],
  interfaces: [] as Iface[],
  iface: '',
  bpf: '',
  captureRunning: false,
  captured: 0,
  enabled: new Set<string>(),
  packets: [] as Packet[],          // 旧→新
  selected: null as Packet | null,
  follow: true,
  sse: 'connecting' as 'connecting' | 'open' | 'closed',
  detailOpen: false,
  sendOpen: false,
})

export const filteredNewestFirst = computed(() => {
  const out: Packet[] = []
  for (let i = store.packets.length - 1; i >= 0; i--) {
    const p = store.packets[i]!
    if (p.layers.some(l => store.enabled.has(l.id))) out.push(p)
  }
  return out
})

export const protoCounts = computed(() => {
  const counts = new Map<string, number>()
  for (const p of store.packets) {
    const seen = new Set<string>()
    for (const l of p.layers) if (!seen.has(l.id)) { seen.add(l.id); counts.set(l.id, (counts.get(l.id) ?? 0) + 1) }
  }
  return counts
})

export function addPacket(p: Packet) {
  store.packets.push(p)
  if (store.packets.length > MAX_PACKETS) store.packets.splice(0, store.packets.length - MAX_PACKETS)
  store.captured = p.seq
}

export function clearPackets() {
  store.packets = []
  store.selected = null
  store.detailOpen = false
}

let es: EventSource | null = null

export function connectStream() {
  es?.close()
  store.sse = 'connecting'
  es = new EventSource('/api/netproto/stream')
  es.onopen = () => { store.sse = 'open' }
  es.addEventListener('packet', ev => { addPacket(JSON.parse((ev as MessageEvent).data as string)) })
  es.onerror = () => {
    // EventSource 自带重连:CONNECTING=重连中, CLOSED=彻底断开(重新 new)
    if (es && es.readyState === EventSource.CLOSED) {
      store.sse = 'closed'
      setTimeout(connectStream, 2000)
    } else {
      store.sse = 'connecting'
    }
  }
}

export async function refreshProtocols() {
  store.protocols = await api.protocols()
  for (const p of store.protocols) store.enabled.add(p.id)
}

export async function refreshInterfaces() {
  try {
    store.interfaces = await api.interfaces()
    if (!store.iface && store.interfaces[0]) store.iface = store.interfaces[0].name
  } catch {
    store.interfaces = []
  }
}

export async function refreshStatus() {
  try {
    const s = await api.status()
    store.captureRunning = s.running === true
    store.captured = Number(s.captured ?? 0)
    const iface = s.iface as string
    if (store.captureRunning && iface) store.iface = iface
  } catch { /* 服务未起 */ }
}
