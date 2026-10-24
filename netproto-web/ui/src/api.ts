import type { Iface, Packet, PacketSummary, ProtocolMeta, SignalSeries, Traffic } from './types'
import type { HintData } from './utils/bpf'

/**
 * 部署期令牌(可选):构建时 VITE_NETPROTO_TOKEN,或宿主页面注入 window.__NETPROTO_TOKEN__。
 * 空 = 后端未启用鉴权(默认);后端设置 netproto.auth-token 后所有请求须匹配。
 * EventSource 与浏览器下载无法带自定义头,这两类场景走 ?token= 查询参数(见 withToken)。
 */
const token: string = (
  (import.meta as unknown as { env?: Record<string, string | undefined> }).env?.VITE_NETPROTO_TOKEN
  ?? (globalThis as { __NETPROTO_TOKEN__?: string }).__NETPROTO_TOKEN__
  ?? ''
).trim()

/** URL 追加令牌查询参数(SSE / 导出下载等无法携带自定义头的场景)。 */
export function withToken(url: string): string {
  if (!token) return url
  return url + (url.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(token)
}

/** 统一请求入口:有令牌时附带 X-Netproto-Token 头。 */
function req(url: string, init?: RequestInit): Promise<Response> {
  const headers: Record<string, string> = { ...init?.headers as Record<string, string> | undefined }
  if (token) headers['X-Netproto-Token'] = token
  return fetch(url, { ...init, headers })
}

/** API 错误:message 取后端 body 的 message/error,并附 status 供调用方区分 404(会话已不存在)等。 */
async function json<T>(resp: Response): Promise<T> {
  const body = await resp.json().catch(() => ({}))
  if (!resp.ok) {
    const msg = (body as { message?: string; error?: string }).message
      ?? (body as { error?: string }).error ?? `HTTP ${resp.status}`
    throw Object.assign(new Error(msg), { status: resp.status })
  }
  return body as T
}

export const api = {
  protocols: () => req('/api/netproto/protocols').then(r => json<ProtocolMeta[]>(r)),
  config: () => req('/api/netproto/config').then(r => json<Record<string, number | string>>(r)),
  interfaces: () => req('/api/netproto/interfaces').then(r => json<Iface[]>(r)),

  // ---- 会话化采集(每页专属会话;旧 /capture、/packets 端点不再由页面使用) ----

  /** 空闲注册(页面加载即占位):后端没有本会话则以该 id 创建(不启动采集),
   *  已存在则幂等返回——后端重启/回收后凭同一 id 注册回来。 */
  sessionRegisterIdle: (id: string) =>
    req('/api/netproto/sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    }).then(r => json<Record<string, unknown>>(r)),
  /** 注册并启动本页会话(页面生成 id):后端不存在则创建、已停止则重启、已运行 409。 */
  sessionRegister: (id: string, iface: string, bpf: string) =>
    req('/api/netproto/sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, iface, bpf }),
    }).then(r => json<Record<string, unknown>>(r)),
  sessionStatus: (id: string) =>
    req(`/api/netproto/sessions/${id}/status`).then(r => json<Record<string, unknown>>(r)),
  sessionStop: (id: string) =>
    req(`/api/netproto/sessions/${id}/stop`, { method: 'POST' }).then(r => json<Record<string, unknown>>(r)),
  sessionDelete: (id: string) =>
    req(`/api/netproto/sessions/${id}`, { method: 'DELETE' }).then(r => json<Record<string, unknown>>(r)),
  /** 会话帧摘要(新→旧)。since>0 时只取 seq>since 的帧:断线重连增量补拉缺口,
   *  不再整环重拉(满环 10 万条约 30MB JSON,主线程解析冻结数秒)。 */
  sessionPackets: (id: string, limit: number, since = 0) =>
    req(`/api/netproto/sessions/${id}/packets?limit=${limit}${since > 0 ? `&since=${since}` : ''}`)
      .then(r => json<PacketSummary[]>(r)),
  sessionPacket: (id: string, seq: number) =>
    req(`/api/netproto/sessions/${id}/packet/${seq}`).then(r => json<Packet>(r)),
  sessionImport: (id: string, file: File) => {
    const form = new FormData()
    form.append('file', file)
    return req(`/api/netproto/sessions/${id}/import`, { method: 'POST', body: form })
      .then(r => json<{ imported: number }>(r))
  },
  /** 导出走浏览器下载(Content-Disposition),返回 URL 供 location.href(令牌经查询参数)。 */
  sessionExportUrl: (id: string) => withToken(`/api/netproto/sessions/${id}/export`),

  send: (iface: string, layers: unknown[]) =>
    req('/api/netproto/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iface, layers }),
    }).then(r => json<{ status: string; bytes: number }>(r)),
  template: (path: string) =>
    req(`/api/netproto/template?path=${encodeURIComponent(path)}`)
      .then(r => json<{ layers: { protocol: string; fields: Record<string, unknown> }[] }>(r)),

  // ---- BPF 智能提示(校验结论 = libpcap 编译,与抓包同源) ----

  bpfValidate: (expr: string) =>
    req(`/api/netproto/bpf/validate?expr=${encodeURIComponent(expr)}`)
      .then(r => json<{ ok: boolean; error?: string }>(r)),
  bpfHints: () => req('/api/netproto/bpf/hints').then(r => json<HintData>(r)),

  /** 信号视图:某协议某字段在会话环形缓冲里的时间序列(旧→新)。 */
  sessionSignals: (id: string, proto: string, field: string, limit = 1000) =>
    req(`/api/netproto/sessions/${id}/signals?proto=${encodeURIComponent(proto)}`
      + `&field=${encodeURIComponent(field)}&limit=${limit}`)
      .then(r => json<SignalSeries>(r)),

  /** 流量分析:会话/协议分布/吞吐时间线(纯摘要聚合)。 */
  sessionTraffic: (id: string, limit = 20000) =>
    req(`/api/netproto/sessions/${id}/traffic?limit=${limit}`).then(r => json<Traffic>(r)),
  /** 流量追踪:某端点对(双向)的全部帧摘要(旧→新)。 */
  sessionTrafficFrames: (id: string, ep: {
    srcHost: string; dstHost: string; srcPort: number | null; dstPort: number | null
  }, limit = 500) => {
    const q = new URLSearchParams({ src: ep.srcHost, dst: ep.dstHost, limit: String(limit) })
    if (ep.srcPort != null) q.set('srcPort', String(ep.srcPort))
    if (ep.dstPort != null) q.set('dstPort', String(ep.dstPort))
    return req(`/api/netproto/sessions/${id}/traffic/frames?${q}`).then(r => json<PacketSummary[]>(r))
  },
}
