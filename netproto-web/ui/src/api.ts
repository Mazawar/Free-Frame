import type { Iface, Packet, PacketSummary, ProtocolMeta } from './types'

async function json<T>(resp: Response): Promise<T> {
  const body = await resp.json().catch(() => ({}))
  if (!resp.ok) {
    throw new Error((body as { message?: string; error?: string }).message
      ?? (body as { error?: string }).error ?? `HTTP ${resp.status}`)
  }
  return body as T
}

export const api = {
  protocols: () => fetch('/api/netproto/protocols').then(r => json<ProtocolMeta[]>(r)),
  config: () => fetch('/api/netproto/config').then(r => json<Record<string, number | string>>(r)),
  interfaces: () => fetch('/api/netproto/interfaces').then(r => json<Iface[]>(r)),
  status: () => fetch('/api/netproto/capture/status').then(r => json<Record<string, unknown>>(r)),
  start: (iface: string, bpf: string) =>
    fetch('/api/netproto/capture/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iface, bpf }),
    }).then(r => json<Record<string, unknown>>(r)),
  stop: () =>
    fetch('/api/netproto/capture/stop', { method: 'POST' }).then(r => json<Record<string, unknown>>(r)),
  packets: (limit: number) =>
    fetch(`/api/netproto/packets?limit=${limit}`).then(r => json<PacketSummary[]>(r)),
  packet: (seq: number) =>
    fetch(`/api/netproto/packet/${seq}`).then(r => json<Packet>(r)),
  send: (iface: string, layers: unknown[]) =>
    fetch('/api/netproto/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iface, layers }),
    }).then(r => json<{ status: string; bytes: number }>(r)),
  template: (path: string) =>
    fetch(`/api/netproto/template?path=${encodeURIComponent(path)}`)
      .then(r => json<{ layers: { protocol: string; fields: Record<string, unknown> }[] }>(r)),
  importPcap: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return fetch('/api/netproto/import', { method: 'POST', body: form })
      .then(r => json<{ imported: number }>(r))
  },
}
