import { reactive, computed } from 'vue'
import type { Iface, Packet, PacketSummary, ProtocolMeta } from './types'
import { api, withToken } from './api'

/** 前端缓冲上限兜底值;实际以后端 ring-size 为准(/config 拉取,见 bootstrap)。 */
const DEFAULT_MAX_PACKETS = 100_000

/** 本页会话身份的 sessionStorage 键:tab 间天然隔离,刷新不丢。 */
const SESSION_KEY = 'netproto.sessionId'

export const store = reactive({
  protocols: [] as ProtocolMeta[],
  interfaces: [] as Iface[],
  iface: '',
  bpf: '',
  /** 本页会话身份(UUID):加载即生成,刷新/后端重启都不换;首次「采集」时在后端注册物化。 */
  sessionId: '',
  /** 后端是否已存在本会话(未注册/被回收/后端重启 = false,身份仍保留)。 */
  sessionLive: false,
  captureRunning: false,
  captured: 0,
  enabled: new Set<string>(),
  packets: [] as PacketSummary[],   // 旧→新(摘要行,不含协议树/hex)
  selected: null as number | null,  // 选中帧 seq
  detail: null as Packet | null,    // 选中帧完整详情(按需拉取)
  sse: 'connecting' as 'connecting' | 'open' | 'closed',
  sendOpen: false,
  signalOpen: false,
  trafficOpen: false,
  /** 初始恢复(环形缓冲最近帧)完成;之前不挂载虚拟表格,避免布局未稳时测高失败 */
  bootstrapped: false,
  /** 后端运行配置(只读):显示参数以它为准 */
  config: { ringSize: DEFAULT_MAX_PACKETS, ringBytes: 0, snaplen: 0, rootProtocol: '' },
})

/** 页面身份就绪:sessionStorage 有就复用(刷新同身份),没有就生成 UUID。
 *  校验存量值的格式(被污染/旧格式直接换新):它会被拼进 URL,不放宽到任意字符串。 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** UUID v4:crypto.randomUUID 仅安全上下文(https / localhost)可用 —— 内网裸 http
 *  (抓包观测台的典型部署形态)下它是 undefined,直接调用会抛 TypeError 致整页白屏。
 *  降级路径:getRandomValues(非安全上下文仍可用)手拼;再降级 Math.random(古老环境)。 */
function uuid(): string {
  const c = globalThis.crypto
  if (c?.randomUUID) return c.randomUUID()
  const b = new Uint8Array(16)
  if (c?.getRandomValues) {
    c.getRandomValues(b)
  } else {
    for (let i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256)
  }
  b[3] = (b[3]! & 0x0f) | 0x40   // version 4
  b[8] = (b[8]! & 0x3f) | 0x80   // variant 10xx
  const h = Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

function ensureSessionIdentity() {
  let id = sessionStorage.getItem(SESSION_KEY)
  if (!id || !UUID_RE.test(id)) {
    id = uuid()
    sessionStorage.setItem(SESSION_KEY, id)
  }
  store.sessionId = id
}

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

/** 批量入口:拼新数组后整体替换(一次依赖触发),高流量下由 SSE 定时合并调用。
 *  allowReset=false(补拉路径)不触发「批首 seq==1」重置:环真的重启时,实时帧
 *  事件自己会带 seq 1 走重置;补拉迟到落地时误重置会整表清空重挂载(滚动位置丢失)。 */
export function addPackets(batch: PacketSummary[], allowReset = true) {
  if (batch.length === 0) return
  // 后端重建:环形重新从 seq 1 计数(批首 == 1 而本页已有更高 seq)→ 清旧帧防混排。
  // 用「批首为 1」而非「严格回退」判定:重连补拉时批首往往 < captured(环未淘汰),
  // 严格回退会把整个缓冲误清一遍。
  if (allowReset && store.captured > 1 && batch[0]!.seq === 1) {
    store.packets = []
    counts.clear()
    store.captured = 0
  }
  // 幂等:重复拉取/SSE 与补拉交叠时,已见过的 seq(<= captured)直接跳过,不重行不重计
  const fresh = batch.filter(p => p.seq > store.captured)
  if (fresh.length === 0) return
  // 在普通副本上裁剪:避免对响应式数组 splice 逐索引触发(虚拟表格逐行订阅,量大时拖垮调度)
  const next = store.packets.concat(fresh)
  const overflow = next.length - maxPackets()
  if (overflow > 0) {
    for (const p of next.splice(0, overflow)) countPacket(p, -1)
  }
  for (const p of fresh) countPacket(p, +1)
  store.packets = next
  store.captured = fresh[fresh.length - 1]!.seq
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
    const p = await api.sessionPacket(store.sessionId, seq)
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

/** 断线后先确认会话还在再重连:会话没了(后端重启/被回收)就停在断开,下次采集注册时重连。 */
async function reconnectIfAlive() {
  if (!store.sessionLive) return
  try {
    await api.sessionStatus(store.sessionId)
    setTimeout(connectStream, 2000)
  } catch {
    store.sessionLive = false
    store.sse = 'closed'
  }
}

/** 订阅本页会话的实时流;后端尚无本会话(未注册)则不连接。 */
export function connectStream() {
  es?.close()
  if (!store.sessionLive) {
    store.sse = 'closed'
    return
  }
  store.sse = 'connecting'
  lastPing = Date.now()
  if (flushTimer === undefined) flushTimer = window.setInterval(flush, 150)
  if (watchdogTimer === undefined) watchdogTimer = window.setInterval(watchdog, 5000)
  es = new EventSource(withToken(`/api/netproto/sessions/${encodeURIComponent(store.sessionId)}/stream`))
  es.onopen = () => {
    store.sse = 'open'
    lastPing = Date.now()
    void backfillAfterOpen()
  }
  es.addEventListener('ping', () => { lastPing = Date.now() })
  // 帧事件同样是存活信号:高流量下连接队列(2048)可能被帧挤满,15s 的 ping 会被
  // 非阻塞 offer 挤掉 —— 只认 ping 会让 35s 看门狗误判连接死亡、强制重连,
  // 重连补拉又与重置启发式竞态导致整表重挂载(滚动位置丢失)
  es.addEventListener('packet', () => { lastPing = Date.now() })
  es.addEventListener('session-closed', () => {
    // 会话被删除(清扫回收/后端重启):身份保留,下次采集重新注册
    es?.close()
    store.sse = 'closed'
    store.sessionLive = false
  })
  es.addEventListener('packet', ev => { pending.push(JSON.parse((ev as MessageEvent).data as string)) })
  es.onerror = () => {
    if (es && es.readyState === EventSource.CLOSED) {
      store.sse = 'closed'
      void reconnectIfAlive()
    } else {
      store.sse = 'connecting'
    }
  }
}

/**
 * 连接建立后补拉会话环形缓冲:兜住「恢复已完成、SSE 尚未 open」与「断线重连期间」
 * 两个窗口里错过的帧。增量(since=本页已见最大 seq):断线重连只拉缺口,
 * 不再整环重拉(满环 10 万条约 30MB JSON,主线程解析冻结数秒,且每次重连都付一遍)。
 * addPackets 幂等(seq 去重),与 SSE 事件交叠无害。
 */
async function backfillAfterOpen() {
  try {
    const recent = await api.sessionPackets(store.sessionId, store.config.ringSize || 100_000, store.captured)
    addPackets(recent.reverse(), false)   // 补拉永不触发重置(见 addPackets 注释)
  } catch { /* 会话已被回收等:忽略,SSE 仍在线 */ }
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

/** 采纳会话(注册成功后调用)。 */
export function adoptSession(live: boolean) {
  store.sessionLive = live
}

/** 页面加载:身份就绪 + 探测后端(会话在就接回并恢复状态;不在则等首次采集注册)。 */
export async function restoreSession() {
  ensureSessionIdentity()
  try {
    applySessionStatus(await api.sessionStatus(store.sessionId))
    store.sessionLive = true
  } catch {
    store.sessionLive = false
    store.captureRunning = false
  }
}

export async function refreshStatus() {
  if (!store.sessionLive) {
    store.captureRunning = false
    return
  }
  try {
    applySessionStatus(await api.sessionStatus(store.sessionId))
  } catch (e) {
    // 404 = 会话已被回收(后端重启/长时间无订阅被清扫):身份保留,下次采集重新注册
    if ((e as { status?: number }).status === 404) {
      store.sessionLive = false
      store.captureRunning = false
    }
  }
}

function applySessionStatus(s: Record<string, unknown>) {
  store.captureRunning = s.running === true
  store.captured = Number(s.captured ?? 0)
  const iface = s.iface as string
  if (store.captureRunning && iface) store.iface = iface
}
