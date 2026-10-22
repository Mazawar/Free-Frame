import { reactive, computed } from 'vue'
import type { Iface, Packet, PacketSummary, ProtocolMeta } from './types'
import { api } from './api'

/** 前端缓冲上限兜底值;实际以后端 ring-size 为准(/config 拉取,见 bootstrap)。 */
const DEFAULT_MAX_PACKETS = 100_000

export const store = reactive({
  protocols: [] as ProtocolMeta[],
  interfaces: [] as Iface[],
  iface: '',
  bpf: '',
  captureRunning: false,
  captured: 0,
  enabled: new Set<string>(),
  packets: [] as PacketSummary[],   // 旧→新(摘要行,不含协议树/hex)
  selected: null as number | null,  // 选中帧 seq
  detail: null as Packet | null,    // 选中帧完整详情(按需拉取)
  sse: 'connecting' as 'connecting' | 'open' | 'closed',
  sendOpen: false,
  /** 初始恢复(环形缓冲最近帧)完成;之前不挂载虚拟表格,避免布局未稳时测高失败 */
  bootstrapped: false,
  /** 后端运行配置(只读):显示参数以它为准 */
  config: { ringSize: DEFAULT_MAX_PACKETS, ringBytes: 0, snaplen: 0, rootProtocol: '' },
})

function maxPackets(): number {
  return store.config.ringSize > 0 ? store.config.ringSize : DEFAULT_MAX_PACKETS
}

export const filteredNewestFirst = computed(() => {
  // 任一层命中即显示(Wireshark 协议列点击语义):勾选 IPv6 = 显示所有含 IPv6 的帧,
  // 勾选业务组 = 显示该组业务帧;全部取消 = 全隐藏。
  // LIST/TLV 元素实体侧栏不可勾,不参与命中判断。
  const exempt = new Set(store.protocols
    .filter(p => p.category === 'element' || p.category === 'internal').map(p => p.id))
  const out: PacketSummary[] = []
  for (let i = store.packets.length - 1; i >= 0; i--) {
    const p = store.packets[i]!
    if (p.layerIds.some(id => !exempt.has(id) && store.enabled.has(id))) out.push(p)
  }
  return out
})

// 每帧每协议只计一次;随 addPackets/裁剪增量维护,避免每次渲染全文遍历
const counts = reactive(new Map<string, number>())
export const protoCounts = counts

function countPacket(p: PacketSummary, delta: number) {
  for (const id of p.layerIds) {
    counts.set(id, (counts.get(id) ?? 0) + delta)
  }
}

/** 批量入口:拼新数组后整体替换(一次依赖触发),高流量下由 SSE 定时合并调用 */
export function addPackets(batch: PacketSummary[]) {
  if (batch.length === 0) return
  // 在普通副本上裁剪:避免对响应式数组 splice 逐索引触发(虚拟表格逐行订阅,量大时拖垮调度)
  const next = store.packets.concat(batch)
  const overflow = next.length - maxPackets()
  if (overflow > 0) {
    for (const p of next.splice(0, overflow)) countPacket(p, -1)
  }
  for (const p of batch) countPacket(p, +1)
  store.packets = next
  store.captured = batch[batch.length - 1]!.seq
}

export function clearPackets() {
  pending.length = 0   // 在途 SSE 事件一并丢弃:否则 150ms 合并窗口会把旧会话的帧补回刚清空的表格
  store.packets = []
  store.selected = null
  store.detail = null
  counts.clear()
}

export function closeDetail() {
  store.selected = null
  store.detail = null
}

/**
 * 选中一帧:完整详情按需拉取(摘要不常驻协议树,Wireshark 点击时解析)。
 * 旧详情保留到新详情到达(stale-while-revalidate)—— 先置空会令面板卸载重挂,产生闪烁。
 */
export async function selectPacket(seq: number) {
  store.selected = seq
  try {
    const p = await api.packet(seq)
    if (store.selected === seq) store.detail = p   // 竞态守卫:期间换帧则丢弃
  } catch { /* 帧已被环形缓冲淘汰:保留旧详情 */ }
}

let es: EventSource | null = null
let pending: PacketSummary[] = []     // 普通数组:SSE 事件先落地,不触发任何响应式更新
let flushTimer: number | undefined
let watchdogTimer: number | undefined
let lastPing = 0

/**
 * SSE 事件缓冲:逐包 addPackets 在 100+ 帧/秒时会把渲染队列堆死(每包一次全表重渲染,
 * 主线程饱和 → 页签冻结)。这里 150ms 合并一次,每秒最多 ~7 次响应式更新。
 */
function flush() {
  if (pending.length === 0) return
  const batch = pending
  pending = []
  addPackets(batch)
}

/** 连接静默超过两个 ping 周期(服务端每 15s 发具名 ping)视为僵尸:强制重连自愈。 */
function watchdog() {
  if (store.sse !== 'open') return
  if (Date.now() - lastPing > 35000) {
    es?.close()
    connectStream()
  }
}

export function connectStream() {
  es?.close()
  store.sse = 'connecting'
  lastPing = Date.now()
  if (flushTimer === undefined) flushTimer = window.setInterval(flush, 150)
  if (watchdogTimer === undefined) watchdogTimer = window.setInterval(watchdog, 5000)
  es = new EventSource('/api/netproto/stream')
  es.onopen = () => { store.sse = 'open'; lastPing = Date.now() }
  es.addEventListener('ping', () => { lastPing = Date.now() })
  es.addEventListener('packet', ev => { pending.push(JSON.parse((ev as MessageEvent).data as string)) })
  es.onerror = () => {
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
