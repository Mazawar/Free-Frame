import type { FieldMeta, ProtocolMeta } from '../types'

/** 极简 Expr 求值(与后端 presentIf 子集一致):== != < <= > >= && || ! ( ) 和 0x/十进制字面量。
 *  求值失败按 false(字段隐藏)——与引擎「父字段缺席即不解析」语义一致。 */
export function evalExpr(expr: string, env: Record<string, unknown>): boolean {
  const tokens = expr.match(/0x[0-9a-fA-F]+|\d+|[A-Za-z_]\w*|==|!=|<=|>=|&&|\|\||[!<>()]/g)
  if (!tokens) return false
  let pos = 0
  const peek = () => tokens[pos]
  const num = (t: string): number => {
    if (/^0x/i.test(t)) return parseInt(t, 16)
    if (/^\d+$/.test(t)) return parseInt(t, 10)
    const v = env[t]
    return typeof v === 'number' ? v : NaN
  }
  const isNumTok = (t?: string) => !!t && (/^(0x[0-9a-fA-F]+|\d+)$/.test(t) || /^[A-Za-z_]\w*$/.test(t))

  function primary(): number {
    const t = peek()
    if (t === '(') { pos++; const v = or(); if (peek() === ')') pos++; return v }
    if (t === '!') { pos++; return primary() === 0 ? 1 : 0 }
    if (isNumTok(t)) { pos++; return num(t) }
    pos++
    return NaN
  }
  function cmp(): number {
    let l = primary()
    while (['<', '<=', '>', '>='].includes(peek() ?? '')) {
      const op = tokens[pos++]!
      const r = primary()
      l = op === '<' ? (l < r ? 1 : 0) : op === '<=' ? (l <= r ? 1 : 0)
        : op === '>' ? (l > r ? 1 : 0) : (l >= r ? 1 : 0)
    }
    return l
  }
  function eq(): number {
    let l = cmp()
    while (peek() === '==' || peek() === '!=') {
      const op = tokens[pos++]!
      const r = cmp()
      l = op === '==' ? (l === r ? 1 : 0) : (l !== r ? 1 : 0)
    }
    return l
  }
  function and(): number {
    let l = eq()
    while (peek() === '&&') { pos++; l = (l !== 0 && eq() !== 0) ? 1 : 0 }
    return l
  }
  function or(): number {
    let l = and()
    while (peek() === '||') { pos++; l = (l !== 0 || and() !== 0) ? 1 : 0 }
    return l
  }
  const v = or()
  return pos >= tokens.length - 1 && v !== 0 && !Number.isNaN(v)
}

// ---- 模板缓存(localStorage,按「链 + 字段指纹」版本化;协议变更 → 指纹变 → 旧缓存弃用) ----

export interface TemplateCacheEntry {
  /** 缓存指纹:协议链 id + 各层字段名/类型/动态属性序列化后的散列,协议一变即失效 */
  v: string
  /** 每层已填字段值 { [protocolId]: fields } */
  values: Record<string, Record<string, unknown>>
}

const CACHE_KEY = 'netproto.sendTemplates.v1'

function fingerprint(chainIds: string[], protos: ProtocolMeta[]): string {
  const parts = chainIds.map(id => {
    const p = protos.find(x => x.id === id)
    if (!p) return id
    return id + '|' + p.fields.map(f =>
      [f.name, f.type, f.size, f.presentIf ?? '', f.lengthField ?? '',
       f.countField ?? '', f.checksum ? 'c' : '', f.payload ? 'p' : ''].join(',')).join(';')
  })
  return hashStr(parts.join('||'))
}

function hashStr(s: string): string {
  let h = 5381
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0
  return (h >>> 0).toString(36)
}

function loadAll(): Record<string, TemplateCacheEntry> {
  try { return JSON.parse(localStorage.getItem(CACHE_KEY) ?? '{}') } catch { return {} }
}

export function loadTemplate(chainIds: string[], protos: ProtocolMeta[]):
    Record<string, Record<string, unknown>> | null {
  const e = loadAll()[chainIds.join('>')]
  return e && e.v === fingerprint(chainIds, protos) ? e.values : null
}

export function saveTemplate(chainIds: string[], protos: ProtocolMeta[],
                             values: Record<string, Record<string, unknown>>): void {
  const all = loadAll()
  all[chainIds.join('>')] = { v: fingerprint(chainIds, protos), values }
  try { localStorage.setItem(CACHE_KEY, JSON.stringify(all)) } catch { /* 配额满:静默放弃 */ }
}

// ---- 表单值 <-> 发送 JSON ----

/** 表单字符串值转发送值:hex 串留给后端(byte[] 便捷格式),数字转 number,flags 拆数组。 */
export function fieldValue(meta: FieldMeta, raw: string): unknown {
  if (raw === '') return undefined
  if (meta.flagClass) {
    // Set<枚举> 目标:后端 Jackson 从 JSON 数组绑定,"SYN,ACK" → ["SYN","ACK"]
    return raw.split(/[,\s]+/).map(s => s.trim()).filter(Boolean)
  }
  if (meta.type === 'int' || meta.type === 'long' || meta.type === 'short' || meta.type === 'byte') {
    const n = /^0x/i.test(raw) ? parseInt(raw, 16) : Number(raw)
    return Number.isFinite(n) ? n : raw
  }
  return raw
}

// ---- 字段填写格式提示(标签徽标 + 输入占位) ----

export interface FmtHint {
  /** 徽标文案:格式 + 定宽,如 dec·2B / 4bit / hex / MAC / IP / str / flags */
  tag: string
  placeholder?: string
}

export function fmtHint(f: FieldMeta): FmtHint {
  const sizeTag = (): string => {
    const b = f.size
    return b > 0 && b % 8 === 0 ? `${b / 8}B` : b > 0 ? `${b}bit` : ''
  }
  if (f.flagClass) return { tag: 'flags' }
  if (f.type === 'byte[]') return { tag: sizeTag() ? `hex·${sizeTag()}` : 'hex', placeholder: '如 01a2ff' }
  if (/Mac$/.test(f.name)) return { tag: sizeTag() ? `MAC·${sizeTag()}` : 'MAC', placeholder: 'aa:bb:cc:dd:ee:ff' }
  if (/Ip$/.test(f.name)) return { tag: sizeTag() ? `IP·${sizeTag()}` : 'IP', placeholder: '192.168.1.1' }
  if (['int', 'long', 'short', 'byte', 'float', 'double'].includes(f.type)) {
    return { tag: `dec·${sizeTag()}`, placeholder: '如 80 / 0x50' }
  }
  return { tag: sizeTag() ? `str·${sizeTag()}` : 'str', placeholder: '文本' }
}
