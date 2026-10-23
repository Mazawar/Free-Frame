<script setup lang="ts">
import { computed, ref } from 'vue'
import type { FieldMeta, LayerView, Packet, ProtocolMeta } from '../types'
import { copyText, fmtValue, layerColor } from '../utils/format'

/**
 * 字段图(参考"信令解析"式分段图):每个字段一个分段(段间留缝即字段隔断,
 * 换层加大缝距)——段内为字节瓦片行(hex + 偏移,层色),亚字节字段在瓦片下方
 * 按归属字段分组铺位框,组名行内联「字段名 + 解码值」(位字段不再单独堆名值块);
 * 字节对齐字段在段底出名值行。字节范围重叠的位字段合并为一段(位框分组共享);
 * 被更深层字段覆盖的 payload 不进图。全部行可换行,无横向滚动。
 * 悬停位框组/名值 ↔ 瓦片互亮;点击复制完整值;点击瓦片钉住所属字段。
 * 只依赖 Packet JSON(可选 protocols 元数据改善标签),可在观测台内使用,
 * 也可打成 Web Component 供任意页面直接渲染。
 */
const props = defineProps<{ packet: Packet | string; protocols?: ProtocolMeta[] }>()

/** 宽容入参:Web Component 场景允许 attribute 直接喂 JSON 串。 */
const p = computed<Packet | null>(() => {
  const v = props.packet as unknown
  if (!v) return null
  if (typeof v === 'string') {
    try { return JSON.parse(v) as Packet } catch { return null }
  }
  return v
})

/** 单段字节瓦片上限:超长载荷由名值行的预览承载。 */
const SEG_TILES = 12

const cap = (s: string) => (s ? s[0]!.toUpperCase() + s.slice(1) : s)

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** 纯 hex 字符串按 hex 语义显示为大写(与详情树一致)。 */
function maybeUpperHex(s: string): string {
  return s.length >= 8 && /^[0-9a-f]+$/.test(s) ? s.toUpperCase() : s
}

/** 名值行短值 + 复制/tooltip 用完整值。 */
function valueTexts(v: unknown, fm?: FieldMeta): { short: string; full: string } {
  const full = maybeUpperHex(fmtValue(v))
  if (Array.isArray(v)) {
    if (fm?.flagClass && fm.flags) {
      const t = v.length ? v.join(', ') : '无置位'
      return { short: t, full: t }
    }
    return { short: `${v.length} 项`, full }
  }
  if (isPlainObject(v)) return { short: `${Object.keys(v).length} 项`, full }
  if (full.length > 44) return { short: `${Math.floor(full.length / 2)} B · ${full.slice(0, 30)}…`, full }
  return { short: full, full }
}

interface Anno {
  key: string
  layer: number
  name: string
  label: string
  start: number
  end: number
  /** 位区间(帧绝对 bit);亚字节字段才有,参与位框分组。 */
  bs?: number
  be?: number
  /** 载荷类字段(payload/body):被更深层字段覆盖时不进图,避免字节重复。 */
  pl: boolean
  color: string
  short: string
  full: string
}

/** 全帧字段标注(顶层字段;元素级留给详情树展开)。 */
const annos = computed<Anno[]>(() => {
  const packet = p.value
  if (!packet) return []
  const out: Anno[] = []
  packet.layers.forEach((l: LayerView, li: number) => {
    const meta = props.protocols?.find(x => x.id === l.id)
    const color = layerColor(li)
    for (const [name, r] of Object.entries(l.ranges ?? {})) {
      if (!r || r[1] <= r[0]) continue
      if (name.includes('[')) continue   // LIST 元素级区间:父字段已覆盖整段字节,不重复进图
      const fm = meta?.fields.find(f => f.name === name)
      const { short, full } = valueTexts(l.fields[name], fm)
      const br = l.bitRanges?.[name]
      out.push({
        key: `L${li}:${name}`,
        layer: li,
        name,
        label: fm?.label ?? cap(name),
        start: r[0],
        end: r[1],
        bs: br?.[0],
        be: br?.[1],
        pl: !!fm?.payload || name === 'payload' || name === 'body',
        color,
        short,
        full,
      })
    }
  })
  // 载荷去重:被更深层字段覆盖的 payload/body 不进图(字节归最深字段),
  // 只留真正无人解码的尾巴
  return out
    .filter(a => !a.pl || !out.some(b => b.layer > a.layer && b.start < a.end && a.start < b.end))
    .sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start))
})

function isSub(a: Anno): boolean {
  return a.bs !== undefined && a.be !== undefined && !(a.be - a.bs >= 8 && a.bs % 8 === 0)
}

function annoAt(idx: number): Anno | null {
  let best: Anno | null = null
  for (const a of annos.value) {
    if (idx >= a.start && idx < a.end && (!best || a.end - a.start < best.end - best.start)) best = a
  }
  return best
}

interface Tile { idx: number; hex: string; color: string | null; title: string }

/** 位框组:同一字段的连续位一组,组下直接标字段名;无归属位为保留组(无标注)。 */
interface BitGroup { key: string; a: Anno | null; boxes: string[] }

interface Seg {
  key: string
  /** 与前一段不同协议层 → 加大左缝距(层隔断)。 */
  layerBreak: boolean
  /** 合入本段的字段(字节范围重叠者合并;通常 1 个)。 */
  fields: Anno[]
  /** 字节对齐字段:段底出名值行(亚字节字段的值内联在位框组名里)。 */
  metaFields: Anno[]
  tiles: Tile[]
  /** 被上限截掉的字节瓦片数。 */
  tileCap: number
  /** 位框组行:连续有亚字节位的字节合成一行,组间留缝、可换行。 */
  brows: BitGroup[][]
  /** LIST 字段:可展开列出元素(字节位置 + 内部字段名值)。 */
  list?: { a: Anno; elems: Elem[] }
}

interface Elem {
  off: number | null
  len: number | null
  /** 标量元素的直接值;对象元素走 fields。 */
  prim: string | null
  fields: [string, string][] | null
}

const segments = computed<Seg[]>(() => {
  const packet = p.value
  if (!packet) return []
  const n = packet.hex.length / 2
  const last = packet.layers.length - 1
  const spans = packet.layers.map((l, i) => ({
    start: l.offset,
    end: i === last ? n : l.offset + Math.max(1, l.headerLen),
    color: layerColor(i),
  }))
  const fields = annos.value
  const sub = fields.filter(isSub)
  const out: Seg[] = []
  let prevLayer = -1
  let i = 0
  while (i < fields.length) {
    const first = fields[i]!
    const members = [first]
    let end = first.end
    let j = i + 1
    // 只合并同层且字节范围重叠的字段(如共享同一字节的多个位字段);
    // 相邻不重叠的字段各自成段(段间留缝即字段隔断)
    while (j < fields.length && fields[j]!.layer === first.layer && fields[j]!.start < end) {
      end = Math.max(end, fields[j]!.end)
      members.push(fields[j]!)
      j++
    }
    const start = first.start
    const tileCount = Math.min(end, n) - start
    const shown = Math.min(tileCount, SEG_TILES)
    const tiles: Tile[] = []
    for (let k = 0; k < shown; k++) {
      const idx = start + k
      const span = spans.find(s => idx >= s.start && idx < s.end)
      const fa = annoAt(idx)
      tiles.push({
        idx,
        hex: packet.hex.substr(idx * 2, 2).toUpperCase(),
        color: span?.color ?? null,
        title: fa ? `0x${idx.toString(16).padStart(4, '0')} · ${fa.label} = ${fa.full}` : `0x${idx.toString(16).padStart(4, '0')}`,
      })
    }
    // 位框组行:位按归属字段分组(组下标字段名),无归属位为保留组;
    // 连续有亚字节位的字节合成一行,组间留缝、可换行;跨字节字段归同一组
    const brows: BitGroup[][] = []
    let run: BitGroup[] = []
    let byKey = new Map<string, BitGroup>()
    for (let b = start; b < start + shown; b++) {
      const hits = sub.filter(a => a.bs! < b * 8 + 8 && b * 8 < a.be!)
      if (!hits.length) {
        if (run.length) { brows.push(run); run = []; byKey = new Map() }
        continue
      }
      const val = parseInt(packet.hex.substr(b * 2, 2), 16)
      let reserved: BitGroup | null = null
      for (let k = 0; k < 8; k++) {
        const g = b * 8 + k
        const owner = hits.find(a => a.bs! <= g && g < a.be!)
        const ch = String((val >> (7 - k)) & 1)
        if (owner) {
          reserved = null
          let grp = byKey.get(owner.key)
          if (!grp) {
            grp = { key: owner.key, a: owner, boxes: [] }
            byKey.set(owner.key, grp)
            run.push(grp)
          }
          grp.boxes.push(ch)
        } else {
          if (!reserved) {
            reserved = { key: `r${b}:${k}`, a: null, boxes: [] }
            run.push(reserved)
          }
          reserved.boxes.push(ch)
        }
      }
    }
    if (run.length) brows.push(run)
    // LIST 字段:收集元素(字节区间取元素级 ranges,内部字段取元素对象属性)
    let list: Seg['list'] | undefined
    for (const a of members) {
      const l = packet.layers[a.layer]
      const v = l?.fields[a.name]
      if (!Array.isArray(v) || v.length === 0) continue
      const fm = props.protocols?.find(x => x.id === l!.id)?.fields.find(f => f.name === a.name)
      if (fm?.flagClass) continue   // 位置标志集不是列表
      list = {
        a,
        elems: v.map((el, idx): Elem => {
          const r = l?.ranges?.[`${a.name}[${idx}]`]
          const trunc = (s: string) => (s.length > 40 ? s.slice(0, 40) + '…' : s)
          if (isPlainObject(el)) {
            return {
              off: r ? r[0] : null,
              len: r ? r[1] - r[0] : null,
              prim: null,
              fields: Object.entries(el).map(([k, ev]) => [k, trunc(maybeUpperHex(fmtValue(ev)))] as [string, string]),
            }
          }
          return { off: r ? r[0] : null, len: r ? r[1] - r[0] : null, prim: trunc(maybeUpperHex(fmtValue(el))), fields: null }
        }),
      }
      break
    }
    out.push({
      key: `seg:${start}:${members.map(m => m.key).join('+')}`,
      layerBreak: prevLayer !== -1 && first.layer !== prevLayer,
      fields: members,
      metaFields: members.filter(m => !isSub(m)),
      tiles,
      tileCap: tileCount - shown,
      brows,
      list,
    })
    prevLayer = members[members.length - 1]!.layer
    i = j
  }
  return out
})

// ---- 联动:悬停名值/位框组/元素 → 字节瓦片亮;悬停/点选瓦片 → 名值亮 ----

const hoverAnno = ref<Anno | null>(null)
const hoverByte = ref<number | null>(null)
const hoverElem = ref<[number, number] | null>(null)
const pinnedKey = ref<string | null>(null)

function tileLit(idx: number): boolean {
  const a = hoverAnno.value
  if (a) return idx >= a.start && idx < a.end
  const e = hoverElem.value
  if (e) return idx >= e[0] && idx < e[1]
  return pinnedKey.value != null && annoAt(idx)?.key === pinnedKey.value
}

function fieldLit(a: Anno): boolean {
  if (hoverAnno.value === a) return true
  if (hoverByte.value != null && hoverByte.value >= a.start && hoverByte.value < a.end) return true
  return pinnedKey.value != null && pinnedKey.value === a.key
}

function onTileClick(idx: number) {
  const a = annoAt(idx)
  pinnedKey.value = a && pinnedKey.value !== a.key ? a.key : null
}

// ---- LIST 展开 / 点击名值行复制完整值 ----

const expanded = ref<Record<string, boolean>>({})

function toggleList(key: string) {
  expanded.value[key] = !expanded.value[key]
}

function onMetaClick(s: Seg, f: Anno) {
  if (s.list && s.list.a.key === f.key) toggleList(s.key)
  else void copyField(f)
}

const copiedKey = ref('')

async function copyField(a: Anno) {
  if (await copyText(a.full)) {
    copiedKey.value = a.key
    setTimeout(() => { if (copiedKey.value === a.key) copiedKey.value = '' }, 1200)
  }
}
</script>

<template>
  <div v-if="p" class="fm mono">
    <div class="segs">
      <div v-for="s in segments" :key="s.key" class="seg"
           :class="{ lbreak: s.layerBreak }">
        <div class="tiles">
          <div v-for="t in s.tiles" :key="t.idx" class="tile"
               :class="{ dim: !t.color, lit: tileLit(t.idx) }"
               :style="t.color ? { '--sc': t.color } : undefined"
               :title="t.title"
               @mouseenter="hoverByte = t.idx"
               @mouseleave="hoverByte = null"
               @click="onTileClick(t.idx)">
            <span class="tv">{{ t.hex }}</span>
            <span class="toff num">{{ t.idx }}</span>
          </div>
          <span v-if="s.tileCap > 0" class="tmore num" title="剩余字节由下方值预览承载">+{{ s.tileCap }}</span>
        </div>
        <div v-for="(br, bi) in s.brows" :key="bi" class="brow">
          <div v-for="g in br" :key="g.key" class="bgroup"
               :class="{ res: !g.a, lit: g.a && fieldLit(g.a) }"
               :style="g.a ? { '--fc': g.a.color } : undefined"
               :title="g.a ? `${g.a.label} = ${g.a.full}` : '保留位'"
               @mouseenter="g.a && (hoverAnno = g.a)"
               @mouseleave="hoverAnno = null"
               @click="g.a && copyField(g.a)">
            <span class="boxes">
              <i v-for="(ch, k) in g.boxes" :key="k">{{ ch }}</i>
            </span>
            <span v-if="g.a" class="gcap">
              <span class="gname">{{ g.a.label }}</span>
              <span class="gval num">{{ copiedKey === g.a.key ? '✓' : g.a.short }}</span>
            </span>
          </div>
        </div>
        <div v-for="f in s.metaFields" :key="f.key" class="meta"
             :class="{ lit: fieldLit(f) }"
             :style="{ '--sc': f.color }"
             :title="s.list && s.list.a.key === f.key ? '点击展开/收起元素' : `${f.label} = ${f.full}`"
             @mouseenter="hoverAnno = f"
             @mouseleave="hoverAnno = null"
             @click="onMetaClick(s, f)">
          <span class="fname">
            {{ f.label }}:
            <span v-if="s.list && s.list.a.key === f.key" class="chev">{{ expanded[s.key] ? '▾' : '▸' }}</span>
          </span>
          <span class="fval num">{{ copiedKey === f.key ? '✓ 已复制' : f.short }}</span>
        </div>
        <div v-if="s.list && expanded[s.key]" class="elems">
          <div v-for="(el, ei) in s.list.elems" :key="s.key + ':' + ei" class="elem"
               :style="{ '--sc': s.list.a.color }"
               @mouseenter="el.off != null ? (hoverElem = [el.off, (el.off ?? 0) + (el.len ?? 0)]) : null"
               @mouseleave="hoverElem = null">
            <span class="ehead">
              <span class="ename num">{{ s.list.a.name }}[{{ ei }}]</span>
              <em v-if="el.off != null" class="eoff num">@{{ el.off }} · {{ el.len }} B</em>
            </span>
            <template v-if="el.fields">
              <span v-for="[k, v] in el.fields" :key="k" class="ef">
                <span class="efk">{{ k }}:</span>
                <span class="efv num" :title="v">{{ v }}</span>
              </span>
            </template>
            <span v-else class="ef num">{{ el.prim }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
  <div v-else class="fm-empty">无帧数据</div>
</template>

<style scoped>
.fm {
  overflow-x: hidden;
  overflow-y: auto;
  font-family: ui-monospace, Consolas, monospace;
}
.fm-empty { padding: 24px; text-align: center; color: #6e7681; font-size: 12px; }

/* 分段流:段间留缝即字段隔断;换层加大缝距;一切可换行,无横向滚动 */
.segs {
  display: flex; flex-wrap: wrap; align-items: flex-start;
  gap: 10px 8px;
}
.seg {
  display: flex; flex-direction: column; align-items: flex-start; gap: 3px;
  width: max-content;
  max-width: 100%;
  min-width: 0;
}
.seg.lbreak { margin-left: 26px; }

/* 字节瓦片行:层色为底,hex 居中 + 右下偏移;窄容器自动换行 */
.tiles { display: flex; flex-wrap: wrap; gap: 2px; max-width: 100%; }
.tile {
  --sc: #3d444d;
  position: relative;
  width: 38px; height: 38px;
  display: flex; align-items: center; justify-content: center;
  border: 1px solid color-mix(in srgb, var(--sc) 45%, transparent);
  border-radius: 4px;
  background: color-mix(in srgb, var(--sc) 16%, transparent);
  cursor: pointer;
  user-select: none;
  transition: filter .1s;
}
.tile.dim { background: rgba(177, 186, 196, .05); }
.tile.dim .tv { color: #6e7681; font-weight: 400; }
.tv { font-size: 13px; font-weight: 700; letter-spacing: .5px; color: var(--sc); }
.toff {
  position: absolute; right: 3px; bottom: 1px;
  font-style: normal; font-size: 8px; line-height: 1; color: #6e7681;
}
.tile.lit,
.tile:hover { filter: brightness(1.55); border-color: color-mix(in srgb, var(--sc) 85%, #fff 15%); }
.tmore {
  align-self: center;
  font-size: 10px; color: #6e7681;
  padding: 0 4px;
  flex: 0 0 auto;
}

/* 位框组行:同一字段的位一组,组名行内联「字段名 + 解码值」(释义);
   位框统一固定宽度,组释义前带竖线(与名值行一致),说明长可撑开;
   组释义之间的间隔 = 一个位框宽 */
.brow { display: flex; flex-wrap: wrap; gap: 4px 14px; max-width: 100%; }
.bgroup {
  display: flex; flex-direction: column; gap: 2px;
  width: max-content; min-width: 0;
}
.bgroup:not(.res) { cursor: pointer; }
.bgroup .boxes { display: flex; gap: 2px; }
.boxes i {
  flex: 0 0 auto;
  width: 14px;
  font-style: normal; font-size: 9px; line-height: 15px; text-align: center;
  color: #6e7681;
  background: rgba(177, 186, 196, .05);
  border: 1px solid #21262d;
  border-radius: 2px;
}
.bgroup:not(.res) .boxes i {
  --fc: #8b949e;
  color: var(--fc); font-weight: 700;
  background: color-mix(in srgb, var(--fc) 20%, transparent);
  border-color: color-mix(in srgb, var(--fc) 85%, transparent);
}
.bgroup.lit .boxes i,
.bgroup:hover .boxes i {
  background: color-mix(in srgb, var(--fc) 32%, transparent);
  border-color: var(--fc);
}
.gcap {
  display: flex; align-items: baseline; gap: 5px;
  padding-left: 6px;
  border-left: 2px solid color-mix(in srgb, var(--fc, #8b949e) 55%, transparent);
  white-space: nowrap;
}
.gname {
  font-size: 8.5px; color: var(--fc); letter-spacing: .2px;
}
.gval {
  font-size: 10.5px; font-weight: 700; flex-shrink: 0;
  color: #e6edf3;
}
.bgroup.lit .gname,
.bgroup:hover .gname { color: #c9d1d9; }

/* 名值行:字段名层色,值亮白;超长省略不撑破 */
.meta {
  display: flex; flex-direction: column; gap: 0;
  padding: 2px 6px 3px;
  border-left: 2px solid var(--sc);
  border-radius: 2px;
  min-width: 0;
  max-width: 100%;
  cursor: pointer;
}
.meta:hover,
.meta.lit { background: color-mix(in srgb, var(--sc) 10%, transparent); }
.fname { font-size: 10px; color: var(--sc); letter-spacing: .3px; }
.fval {
  font-size: 12px; font-weight: 600; color: #e6edf3;
  max-width: 100%;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.meta:hover .fval,
.meta.lit .fval { color: #fff; }
.chev { color: #6e7681; font-style: normal; margin-left: 2px; }

/* LIST 展开的元素卡:横向流动、自动换行(元素再多也往横向铺,不竖撑高度) */
.elems { display: flex; flex-wrap: wrap; gap: 6px; align-items: stretch; width: 100%; }
.elem {
  flex: 1 1 150px;
  max-width: 250px;
  display: flex; flex-direction: column; gap: 1px;
  padding: 3px 8px 4px;
  border-left: 2px solid color-mix(in srgb, var(--sc) 55%, transparent);
  border-radius: 2px;
  min-width: 0;
}
.elem:hover { background: color-mix(in srgb, var(--sc) 9%, transparent); }
.ehead { display: flex; align-items: baseline; gap: 6px; }
.ename { font-size: 10px; font-weight: 700; color: var(--sc); }
.eoff { font-style: normal; font-size: 9px; color: #484f58; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ef { display: flex; align-items: baseline; gap: 4px; min-width: 0; max-width: 100%; }
.efk { font-size: 10px; color: #8b949e; flex-shrink: 0; }
.efv {
  font-size: 11px; color: #c9d1d9;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ef { font-size: 11px; color: #c9d1d9; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
