import type { Iface, Packet, PacketSummary, ProtocolMeta } from './types'

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

  /** 创建并启动新会话,返回 {sessionId, running, iface, ...}。 */
  sessionCreate: (iface: string, bpf: string) =>
    fetch('/api/netproto/sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iface, bpf }),
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
}
