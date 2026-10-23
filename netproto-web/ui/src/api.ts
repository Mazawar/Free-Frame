import type { Iface, Packet, PacketSummary, ProtocolMeta, SignalSeries, Traffic } from './types'
import type { HintData } from './utils/bpf'

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
  protocols: () => fetch('/api/netproto/protocols').then(r => json<ProtocolMeta[]>(r)),
  config: () => fetch('/api/netproto/config').then(r => json<Record<string, number | string>>(r)),
  interfaces: () => fetch('/api/netproto/interfaces').then(r => json<Iface[]>(r)),

  // ---- 会话化采集(每页专属会话;旧 /capture、/packets 端点不再由页面使用) ----

  /** 空闲注册(页面加载即占位):后端没有本会话则以该 id 创建(不启动采集),
   *  已存在则幂等返回——后端重启/回收后凭同一 id 注册回来。 */
  sessionRegisterIdle: (id: string) =>
    fetch('/api/netproto/sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    }).then(r => json<Record<string, unknown>>(r)),
  /** 注册并启动本页会话(页面生成 id):后端不存在则创建、已停止则重启、已运行 409。 */
  sessionRegister: (id: string, iface: string, bpf: string) =>
    fetch('/api/netproto/sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, iface, bpf }),
    }).then(r => json<Record<string, unknown>>(r)),
  sessionStatus: (id: string) =>
    fetch(`/api/netproto/sessions/${id}/status`).then(r => json<Record<string, unknown>>(r)),
  sessionStop: (id: string) =>
    fetch(`/api/netproto/sessions/${id}/stop`, { method: 'POST' }).then(r => json<Record<string, unknown>>(r)),
  sessionDelete: (id: string) =>
    fetch(`/api/netproto/sessions/${id}`, { method: 'DELETE' }).then(r => json<Record<string, unknown>>(r)),
  sessionPackets: (id: string, limit: number) =>
    fetch(`/api/netproto/sessions/${id}/packets?limit=${limit}`).then(r => json<PacketSummary[]>(r)),
  sessionPacket: (id: string, seq: number) =>
    fetch(`/api/netproto/sessions/${id}/packet/${seq}`).then(r => json<Packet>(r)),
  sessionImport: (id: string, file: File) => {
    const form = new FormData()
    form.append('file', file)
    return fetch(`/api/netproto/sessions/${id}/import`, { method: 'POST', body: form })
      .then(r => json<{ imported: number }>(r))
  },
  /** 导出走浏览器下载(Content-Disposition),返回 URL 供 location.href。 */
  sessionExportUrl: (id: string) => `/api/netproto/sessions/${id}/export`,

  send: (iface: string, layers: unknown[]) =>
    fetch('/api/netproto/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iface, layers }),
    }).then(r => json<{ status: string; bytes: number }>(r)),
  template: (path: string) =>
    fetch(`/api/netproto/template?path=${encodeURIComponent(path)}`)
      .then(r => json<{ layers: { protocol: string; fields: Record<string, unknown> }[] }>(r)),

  // ---- BPF 智能提示(校验结论 = libpcap 编译,与抓包同源) ----

  bpfValidate: (expr: string) =>
    fetch(`/api/netproto/bpf/validate?expr=${encodeURIComponent(expr)}`)
      .then(r => json<{ ok: boolean; error?: string }>(r)),
  bpfHints: () =>
    fetch('/api/netproto/bpf/hints').then(r => json<HintData>(r)),

  /** 信号视图:某协议某字段在会话环形缓冲里的时间序列(旧→新)。 */
  sessionSignals: (id: string, proto: string, field: string, limit = 1000) =>
    fetch(`/api/netproto/sessions/${id}/signals?proto=${encodeURIComponent(proto)}`
      + `&field=${encodeURIComponent(field)}&limit=${limit}`)
      .then(r => json<SignalSeries>(r)),

  /** 流量分析:会话/协议分布/吞吐时间线(纯摘要聚合)。 */
  sessionTraffic: (id: string, limit = 20000) =>
    fetch(`/api/netproto/sessions/${id}/traffic?limit=${limit}`).then(r => json<Traffic>(r)),
  /** 流量追踪:某端点对(双向)的全部帧摘要(旧→新)。 */
  sessionTrafficFrames: (id: string, ep: {
    srcHost: string; dstHost: string; srcPort: number | null; dstPort: number | null
  }, limit = 500) => {
    const q = new URLSearchParams({ src: ep.srcHost, dst: ep.dstHost, limit: String(limit) })
    if (ep.srcPort != null) q.set('srcPort', String(ep.srcPort))
    if (ep.dstPort != null) q.set('dstPort', String(ep.dstPort))
    return fetch(`/api/netproto/sessions/${id}/traffic/frames?${q}`).then(r => json<PacketSummary[]>(r))
  },
}
