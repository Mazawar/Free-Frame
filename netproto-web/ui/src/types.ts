export interface FieldMeta {
  name: string
  order: number
  size: number
  type: string
}

export interface ProtocolMeta {
  id: string
  name: string
  builtin: boolean
  fields: FieldMeta[]
}

export interface LayerView {
  id: string
  name: string
  offset: number
  headerLen: number
  fields: Record<string, unknown>
}

export interface Packet {
  seq: number
  ts: number
  iface: string
  len: number
  path: string
  layers: LayerView[]
  hex: string
}

export interface Iface {
  name: string
  description: string
}
