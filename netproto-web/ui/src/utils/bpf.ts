/**
 * BPF 提示文法引擎(纯函数,供 BpfInput 使用)。
 *
 * 设计边界:这里的词条表按 pcap-filter(7)(libpcap 官方文法文档)枚举,状态机只判断
 * 「下一个该接什么类别的词」——它是引导,不是裁判。语法对错的裁决永远在后端
 * /bpf/validate(libpcap pcap_compile,与抓包同一编译器):提示通过 = 真实可用,
 * 前端不实现第二套 BPF 解析器,避免与 libpcap 行为分歧。
 */

export interface BpfSuggest {
  /** 插入的文本;空串 = 纯说明行(不可选) */
  text: string
  desc: string
  kind: 'kw' | 'op' | 'value' | 'recipe' | 'hint'
}

/** /bpf/hints 的素材:协议配方(注册表推导)+ 本机地址。 */
export interface HintData {
  recipes: { expr: string; label: string; builtin: boolean }[]
  localAddresses: { ip: string; iface: string }[]
}

/** 联想上下文:items 是候选列表;tokenStart/tokenEnd 是当前词的完整范围
 *  (起点=词首,终点=词尾,含光标后的残余字符——选中后整词替换,光标在词中间不劈词)。 */
export interface BpfContext {
  items: BpfSuggest[]
  tokenStart: number
  tokenEnd: number
}

interface Kw {
  t: string
  d: string
}

// ---- 文法词条(pcap-filter(7);desc 给不熟悉语法的用户一句话释义) ----

const HOST: Kw = { t: 'host', d: '按主机过滤:IP、域名(ether 下还接受 MAC)' }
const NET: Kw = { t: 'net', d: '按网段过滤,如 192.168.1.0/24' }
const PORT: Kw = { t: 'port', d: '按端口过滤(TCP/UDP 均命中)' }
const PORTRANGE: Kw = { t: 'portrange', d: '按端口区间过滤,如 9000-9010' }
const SRC: Kw = { t: 'src', d: '限定源地址,后接 host / net / port' }
const DST: Kw = { t: 'dst', d: '限定目的地址,后接 host / net / port' }
const ETHER: Kw = { t: 'ether', d: '进入二层(MAC)限定:src/dst/host/proto/广播组播' }
const PROTO: Kw = { t: 'proto', d: '按协议号过滤:ether proto 0x0800 / ip proto tcp' }
const PROTOCHAIN: Kw = { t: 'protochain', d: '按协议链过滤(展开隧道/扩展头)' }
const AND: Kw = { t: 'and', d: '与(两侧条件都要满足,可写 &&)' }
const OR: Kw = { t: 'or', d: '或(任一满足,可写 ||)' }
const NOT: Kw = { t: 'not', d: '非(取反,可写 !)' }

/** 表达式开头(以及 and/or/not/( 之后)能出现的东西,常用在前。 */
const BEGIN: Kw[] = [
  HOST, PORT, { t: 'tcp', d: '仅 TCP 流量' }, { t: 'udp', d: '仅 UDP 流量' },
  { t: 'ip', d: '仅 IPv4 流量' }, { t: 'ip6', d: '仅 IPv6 流量' },
  { t: 'arp', d: '仅 ARP 流量' }, NOT, SRC, DST, NET, PORTRANGE, ETHER,
  { t: 'vlan', d: '仅 802.1Q VLAN 帧(可带 VLAN ID,如 vlan 100)' },
  { t: 'icmp', d: '仅 ICMP 流量' }, { t: 'icmp6', d: '仅 ICMPv6 流量' },
  { t: 'rarp', d: '仅 RARP 流量' },
  { t: 'gateway', d: '经网关的帧(源/目的 MAC 是网关)' },
  { t: 'broadcast', d: '广播帧' }, { t: 'multicast', d: '组播帧' },
  { t: 'less', d: '帧长 ≤ N 字节(len <= N)' },
  { t: 'greater', d: '帧长 ≥ N 字节(len >= N)' },
  { t: 'len', d: '帧长度变量,可比较,如 len > 100' },
  { t: 'mpls', d: '仅 MPLS 帧' },
  { t: 'pppoed', d: '仅 PPPoE 发现阶段' }, { t: 'pppoes', d: '仅 PPPoE 会话阶段' },
  { t: 'tcp[13] & 2 != 0', d: '示例:仅 SYN 帧(协议头字节访问语法)' },
  { t: 'ether[0] & 1 != 0', d: '示例:组播目的 MAC(首字节最低位为 1)' },
]

const SRC_DST: Kw[] = [HOST, NET, PORT, PORTRANGE]
const ETHER_NEXT: Kw[] = [SRC, DST, HOST, PROTO,
  { t: 'broadcast', d: '以太网广播' }, { t: 'multicast', d: '以太网组播' }]
const TCP_UDP_NEXT: Kw[] = [SRC, DST, PORT, PORTRANGE, AND, OR, NOT]
const IP_NEXT: Kw[] = [PROTO, PROTOCHAIN, AND, OR, NOT]
const IP6_NEXT: Kw[] = [PROTO, PROTOCHAIN, { t: 'multicast', d: 'IPv6 组播' }, AND, OR, NOT]

const ETHER_PROTO: Kw[] = [
  { t: 'ip', d: '0x0800 · IPv4' }, { t: 'ip6', d: '0x86DD · IPv6' },
  { t: 'arp', d: '0x0806 · ARP' }, { t: 'rarp', d: '0x8035 · RARP' },
  { t: '0x8100', d: '802.1Q VLAN' },
  { t: '0x8892', d: 'PROFINET' }, { t: '0x88B8', d: 'GOOSE' }, { t: '0x88BA', d: 'SV' },
]
const IP_PROTO: Kw[] = [
  { t: 'tcp', d: '6 · TCP' }, { t: 'udp', d: '17 · UDP' }, { t: 'icmp', d: '1 · ICMP' },
  { t: 'icmp6', d: '58 · ICMPv6' }, { t: 'igmp', d: '2 · IGMP' }, { t: 'pim', d: '103 · PIM' },
  { t: 'ah', d: '51 · AH' }, { t: 'esp', d: '50 · ESP' }, { t: 'vrrp', d: '112 · VRRP' },
]
const OPS: Kw[] = [AND, OR, NOT]
const CMP: Kw[] = [
  { t: '>', d: '大于' }, { t: '<', d: '小于' }, { t: '>=', d: '大于等于' },
  { t: '<=', d: '小于等于' }, { t: '==', d: '等于' }, { t: '!=', d: '不等于' },
]

const hintRow = (desc: string): BpfSuggest => ({ text: '', desc, kind: 'hint' })
const kws = (list: Kw[], kind: BpfSuggest['kind'] = 'kw'): BpfSuggest[] =>
  list.map(k => ({ text: k.t, desc: k.d, kind }))

/** 配方(注册表推导的完整表达式),begin 阶段置顶展示。 */
function recipeItems(h: HintData): BpfSuggest[] {
  return h.recipes.map(r => ({ text: r.expr, desc: `${r.label}`, kind: 'recipe' as const }))
}

function hostValues(h: HintData, mac: boolean): BpfSuggest[] {
  return [
    ...h.localAddresses.map(a => ({ text: a.ip, desc: `本机 · ${a.iface}`, kind: 'value' as const })),
    hintRow(mac ? '主机名 / IP / MAC(如 aa:bb:cc:dd:ee:ff)' : '主机名或 IP(v4/v6)'),
  ]
}

function portValues(h: HintData): BpfSuggest[] {
  const ports = h.recipes
    .filter(r => /^(\w+) port (\d+)$/.test(r.expr))
    .map(r => {
      const m = r.expr.match(/^(\w+) port (\d+)$/)!
      return { text: m[2], desc: `${r.label} · ${m[1]} ${m[2]}`, kind: 'value' as const }
    })
  return [...ports, hintRow('端口号或服务名,如 502(modbus)、53(domain)')]
}

function ethertypeValues(h: HintData): BpfSuggest[] {
  const custom = h.recipes
    .filter(r => /^ether proto (0x[0-9A-Fa-f]+)$/i.test(r.expr))
    .map(r => ({ text: r.expr.replace(/^ether proto /i, ''), desc: r.label, kind: 'value' as const }))
  return [...custom, ...kws(ETHER_PROTO, 'value'), hintRow('协议名或 0xNNNN 数字')]
}

// ---- 状态机 ----

const OPS_TOKEN = new Set(['and', 'or', 'not', '&&', '||', '!'])
const CMP_TOKEN = new Set(['>', '<', '>=', '<=', '==', '!=', '=', '<<', '>>', '+', '-', '*', '/', '%', '&', '|', '^'])
/** 值字面量(IP/数字/域名/MAC/十六进制)——出现即代表一个原语已完整,后面该接操作符。 */
const VALUE_LIKE =
  /^(0x[0-9a-f]+|\d[\d.:/-]*|[\da-f]{2}(:[\da-f]{2}){5}|[a-z][\w.-]*\.[a-z]{2,})$/i

/**
 * 计算光标处的候选。
 * @param caret 光标位置(0..input.length)
 */
export function bpfSuggest(input: string, caret: number, h: HintData): BpfContext {
  const before = input.slice(0, Math.min(caret, input.length))
  // 当前词边界:回溯到空白或括号
  let start = before.length
  while (start > 0 && !/\s/.test(before[start - 1]) && before[start - 1] !== '(' && before[start - 1] !== ')') {
    start--
  }
  const token = before.slice(start)
  // 词尾:从光标向后扫到下一个词边界——替换时吃掉整个词,光标停在词中间也不劈成两半
  let end = Math.min(caret, input.length)
  while (end < input.length && !/\s/.test(input[end]) && input[end] !== '(' && input[end] !== ')') {
    end++
  }
  // 光标前的前缀词(去掉括号,用于判定上下文)
  const toks = before.slice(0, start).split(/\s+/).map(t => t.replace(/[()]/g, '')).filter(Boolean)
  const prev = (toks[toks.length - 1] ?? '').toLowerCase()
  const prev2 = (toks[toks.length - 2] ?? '').toLowerCase()

  let items: BpfSuggest[]

  if (!prev || OPS_TOKEN.has(prev) || prev === '(') {
    items = [...recipeItems(h), ...kws(BEGIN)]
  } else if (prev === 'src' || prev === 'dst') {
    items = kws(prev2 === 'ether' ? [HOST] : SRC_DST)
  } else if (prev === 'ether') {
    items = kws(ETHER_NEXT)
  } else if (prev === 'ip') {
    items = kws(IP_NEXT)
  } else if (prev === 'ip6') {
    items = kws(IP6_NEXT)
  } else if (prev === 'tcp' || prev === 'udp') {
    items = kws(TCP_UDP_NEXT)
  } else if (prev === 'host' || prev === 'gateway') {
    items = hostValues(h, prev2 === 'ether')
  } else if (prev === 'net') {
    items = [hintRow('网段:192.168.1.0/24、192.168.1.0/255.255.255.0 或 192.168.1')]
  } else if (prev === 'port') {
    items = portValues(h)
  } else if (prev === 'portrange') {
    items = [hintRow('起-止,如 9000-9010')]
  } else if (prev === 'proto' || prev === 'protochain') {
    items = prev2 === 'ether'
      ? [...ethertypeValues(h), hintRow('ether proto:二层协议名或 0xNNNN')]
      : [...kws(IP_PROTO, 'value'), hintRow('IP 协议名或协议号')]
  } else if (prev === 'less' || prev === 'greater') {
    items = [hintRow('帧字节数,如 64 / 512 / 1500')]
  } else if (prev === 'len' || prev2 === 'len') {
    // len 之后接比较符;比较符之后填数字
    items = prev === 'len' ? kws(CMP, 'op') : [hintRow('帧字节数,如 100')]
  } else if (prev === 'vlan' || prev === 'mpls') {
    items = kws(OPS, 'op')
  } else if (VALUE_LIKE.test(prev) || CMP_TOKEN.has(prev)) {
    items = kws(OPS, 'op')
  } else {
    // 未知词(如协议名 standalone:arp/icmp/vlan 已完整,或用户乱敲)——操作符收尾
    items = kws(OPS, 'op')
  }

  // 括号未闭合时,操作符阶段补一个 ')' 候选
  const depth = (before.match(/\(/g)?.length ?? 0) - (before.match(/\)/g)?.length ?? 0)
  if (depth > 0 && items.some(s => s.kind === 'op' && s.text === 'and')) {
    items = [...items, { text: ')', desc: '闭合括号', kind: 'op' }]
  }

  const prefix = token.toLowerCase()
  const filtered = prefix
    ? items.filter(s => !s.text || s.text.toLowerCase().startsWith(prefix))
    : items

  return { items: filtered.slice(0, 12), tokenStart: start, tokenEnd: end }
}
