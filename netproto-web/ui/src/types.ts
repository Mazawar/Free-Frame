export interface FlagMeta {
  name: string
  mask: number
}

export interface FieldMeta {
  name: string
  order: number
  size: number
  type: string
  /** 展示分组名(注解声明,同组折叠为带名父节点) */
  group?: string
  /** 展示名(Wireshark 式字段名;空 = 用字段名) */
  label?: string
  /** 条件出现表达式(presentIf;表单按已填值求值显隐) */
  presentIf?: string
  /** 变长驱动:引用本层长度字段名(编码器自动) */
  lengthField?: string
  lengthUnit?: string
  lengthAdjust?: number
  lengthAscii?: boolean
  /** 计数驱动:引用本层元素个数字段名 */
  countField?: string
  countUnit?: string
  /** LIST 元素实体类简单名(表单留 JSON 高级模式) */
  elementClass?: string
  /** 校验和字段(编码期计算) */
  checksum?: boolean
  /** 载荷字段(整层剩余字节) */
  payload?: boolean
  /** 位标志字段:Set<TcpFlag> 这类,值可逐位展开 */
  flagClass?: string
  flags?: FlagMeta[]
}

export interface ProtocolMeta {
  id: string
  name: string
  builtin: boolean
  /** 协议分组名(空=不分组),同组在侧栏折叠到一块 */
  group: string
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
  /** 帧绝对位区间 [startBit, endBit)(bit 0 = 首字节 MSB),亚字节字段位展示用。 */
  bitRanges: Record<string, [number, number]>
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

export interface PacketSummary {
  seq: number
  ts: number
  iface: string
  len: number
  path: string
  layerIds: string[]
  src: string
  dst: string
  srcPort: number | null
  dstPort: number | null
  info: string
}

export interface Iface {
  name: string
  description: string
}
