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
  /** stack=分派树协议 / island=孤岛(不在链路分派) / element=LIST/TLV 元素实体 */
  category: string
  fields: FieldMeta[]
}

export interface LayerView {
  id: string
  name: string
  offset: number
  headerLen: number
  fields: Record<string, unknown>
  /** 顶层字段的帧绝对字节区间 [start, end),供树 ↔ 字节联动高亮。 */
  ranges: Record<string, [number, number]>
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
