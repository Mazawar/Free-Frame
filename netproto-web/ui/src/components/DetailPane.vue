<script setup lang="ts">
import { computed, h, nextTick, ref, watch } from 'vue'
import { NButton, NTag, NTree, useMessage } from 'naive-ui'
import { Check, Copy, X } from 'lucide-vue-next'
import { closeDetail, store } from '../store'
import { copyText, fmtValue, layerColor, layerSummary } from '../utils/format'
import HexView from './HexView.vue'

const message = useMessage()
const packet = computed(() => store.selected)
const paneRef = ref<HTMLElement | null>(null)

const selectedKeys = ref<string[]>([])

/** 当前选中字段所属层(Wireshark 双层高亮的「层」:hex 中该层字节浅色铺底)。 */
const selectedLayerIdx = computed(() => {
  const m = /^L(\d+)/.exec(selectedKeys.value[0] ?? '')
  return m ? Number(m[1]) : -1
})

const layerHighlight = computed<[number, number] | null>(() => {
  const l = packet.value?.layers[selectedLayerIdx.value]
  if (!l) return null
  // 层字节 = 头部 + 该层 payload(与 Wireshark 选中协议行的高亮范围一致)
  const end = Math.max(l.offset + l.headerLen, (l.ranges?.payload?.[1] ?? 0))
  return [l.offset, end]
})
const expandedKeys = ref<string[]>([])
const highlight = ref<[number, number] | null>(null)
const copiedKey = ref('')

// ---- Wireshark 式层列表:每层一个顶层节点,子节点为字段 ----

interface Meta {
  kind: 'layer' | 'field' | 'listGroup' | 'element' | 'elementField'
  layerIndex: number
  fieldName?: string
  value?: unknown
  elemIndex?: number
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** 元素行摘要:对象元素取字段拼接(键首字母大写),原始值直接格式化。 */
function elementSummary(v: unknown): string {
  if (isPlainObject(v)) {
    const parts = Object.entries(v).map(([k, e]) => `${cap(k)}=${shortRaw(e)}`)
    const s = parts.join(', ')
    return s.length > 52 ? s.slice(0, 52) + '…' : s
  }
  return shortRaw(v)
}

function shortRaw(v: unknown): string {
  const s = maybeUpperHex(fmtValue(v))
  return s.length > 24 ? s.slice(0, 24) + '…' : s
}

function shortValue(v: unknown): string {
  const s = maybeUpperHex(fmtValue(v))
  if (s.length > 64) return `${Math.floor(s.length / 2)} B · ${s.slice(0, 28)}…`
  return s
}

/** 纯 hex 字符串(偶数长、仅 0-9a-f)按 hex 语义显示为大写。 */
function maybeUpperHex(s: string): string {
  return s.length >= 8 && /^[0-9a-f]+$/.test(s) ? s.toUpperCase() : s
}

/** 属性名首字母大写(Wireshark 风格),复制仍用原名。 */
function cap(s: string): string {
  return s ? s[0]!.toUpperCase() + s.slice(1) : s
}

/**
 * 亚字节字段的位展示(Wireshark 式):字段所在字节的 8 位,
 * 字段位显 0/1、其余位为「.」,如 version(4bit) → "0100 ...."。
 * 仅顶层字段有位区间;字节对齐或跨字节字段返回 null(走普通展示)。
 */
function bitPattern(layerIndex: number, fieldName: string): string | null {
  const l = packet.value?.layers[layerIndex]
  const br = l?.bitRanges?.[fieldName]
  if (!br) return null
  const len = br[1] - br[0]
  const startByte = br[0] >> 3
  const endByte = (br[1] - 1) >> 3
  if (len >= 8 && br[0] % 8 === 0) return null          // 字节对齐:普通展示
  if (startByte !== endByte) return null                 // 跨字节:暂不做跨字节位图
  const byteVal = parseInt(packet.value!.hex.substr(startByte * 2, 2), 16)
  let bits = ''
  for (let j = 0; j < 8; j++) {
    const g = startByte * 8 + j
    bits += g >= br[0] && g < br[1] ? String((byteVal >> (7 - j)) & 1) : '.'
  }
  return `${bits.slice(0, 4)} ${bits.slice(4)}`
}

const treeData = computed(() => {
  const p = packet.value
  if (!p) return []
  return p.layers.map((l, i) => ({
    key: `L${i}`,
    meta: { kind: 'layer', layerIndex: i } satisfies Meta,
    children: Object.entries(l.fields).flatMap(([k, v]) => {
      // LIST/数组字段:分组父节点 + 每元素子节点(元素 key 与引擎元素级 ranges 对齐,可联动高亮)
      if (Array.isArray(v)) {
        return [{
          key: `L${i}:${k}`,
          meta: { kind: 'listGroup', layerIndex: i, fieldName: k, value: v } satisfies Meta,
          children: v.map((el, idx) => ({
            key: `L${i}:${k}[${idx}]`,
            meta: { kind: 'element', layerIndex: i, fieldName: k, elemIndex: idx, value: el } satisfies Meta,
            children: isPlainObject(el)
              ? Object.entries(el).map(([ek, ev]) => ({
                  key: `L${i}:${k}[${idx}].${ek}`,
                  meta: { kind: 'elementField', layerIndex: i, fieldName: ek, value: ev } satisfies Meta,
                }))
              : undefined,
            isLeaf: !isPlainObject(el),
          })),
        }]
      }
      return [{
        key: `L${i}:${k}`,
        meta: { kind: 'field', layerIndex: i, fieldName: k, value: v } satisfies Meta,
      }]
    }),
    isLeaf: false,
  }))
})

function renderLabel({ option }: { option: any }) {
  const meta = option.meta as Meta
  if (meta.kind === 'layer') {
    const l = packet.value!.layers[meta.layerIndex]!
    // 选中该层任一字段时,层行同步点亮(Wireshark 的双层选中:层行 + 字段行)
    const active = meta.layerIndex === selectedLayerIdx.value
    return h('span', { class: `layer-row${active ? ' layer-active' : ''}` }, [
      h('span', { class: 'swatch', style: { background: layerColor(meta.layerIndex) } }),
      h('span', { class: 'lsummary' }, layerSummary(l)),
      h('span', { class: 'loff mono' }, `@${l.offset} · ${l.headerLen} B`),
    ])
  }
  if (meta.kind === 'listGroup') {
    return h('span', { class: 'field-row group-row' }, [
      h('span', { class: 'fname' }, cap(meta.fieldName ?? '')),
      h('span', { class: 'count-badge' }, `${(meta.value as unknown[]).length} 项`),
    ])
  }
  if (meta.kind === 'element') {
    return h('span', { class: 'field-row elem-row' }, [
      h('span', { class: 'eidx mono' }, `[${meta.elemIndex}]`),
      h('span', { class: 'fvalue num', title: maybeUpperHex(fmtValue(meta.value)) }, elementSummary(meta.value)),
      h('button', {
        class: 'copy-btn',
        title: '复制值',
        onClick: (e: MouseEvent) => copyField(e, option.key as string, `${meta.fieldName}[${meta.elemIndex}]`, meta.value),
      }, [h(copiedKey.value === option.key ? Check : Copy, { size: 11 })]),
    ])
  }
  const name = meta.fieldName ?? ''
  const isElemField = meta.kind === 'elementField'
  const bits = isElemField ? null : bitPattern(meta.layerIndex, name)
  return h('span', { class: `field-row${isElemField ? ' elem-field' : ''}` }, [
    bits ? h('span', { class: 'bits mono', title: '字段在字节内的位分布' }, `${bits} =`) : null,
    h('span', { class: 'fname' }, cap(name)),
    h('span', { class: 'fvalue num', title: maybeUpperHex(fmtValue(meta.value)) }, shortValue(meta.value)),
    h('button', {
      class: 'copy-btn',
      title: '复制值',
      onClick: (e: MouseEvent) => copyField(e, option.key as string, name, meta.value),
    }, [h(copiedKey.value === option.key ? Check : Copy, { size: 11 })]),
  ])
}

// ---- 复制 ----

async function copyField(e: MouseEvent, key: string, name: string, v: unknown) {
  e.stopPropagation()
  if (await copyText(maybeUpperHex(fmtValue(v)))) {
    copiedKey.value = key
    message.success(`已复制 ${name}`)
    setTimeout(() => (copiedKey.value = ''), 1500)
  } else {
    message.error('复制失败')
  }
}

async function copyHex(all: boolean) {
  const p = packet.value!
  let text: string
  if (all || !highlight.value) {
    text = p.hex.toUpperCase()
  } else {
    const [s, e] = highlight.value
    text = p.hex.slice(s * 2, e * 2).toUpperCase()
  }
  if (await copyText(text)) {
    message.success(all ? `已复制整帧 Hex(${p.len} B)` : `已复制选中字段 Hex`)
  } else {
    message.error('复制失败')
  }
}

// ---- 字段 ↔ 字节 双向联动 ----

interface RangeEntry { key: string; start: number; end: number }

const rangesIndex = computed<RangeEntry[]>(() => {
  const p = packet.value
  if (!p) return []
  const out: RangeEntry[] = []
  p.layers.forEach((l, i) => {
    out.push({ key: `L${i}`, start: l.offset, end: l.offset + Math.max(1, l.headerLen) })
    for (const [name, r] of Object.entries(l.ranges ?? {})) {
      out.push({ key: `L${i}:${name}`, start: r[0], end: r[1] })
    }
  })
  return out
})

/** 把字节区间滚动到 hex 容器可视范围(居中;只滚 .hex 自身,不动外层)。 */
function scrollToRange(start: number, end: number) {
  nextTick(() => {
    const hexEl = paneRef.value?.querySelector('.hex') as HTMLElement | null
    const first = paneRef.value?.querySelector(`[data-byte="${start}"]`)
    const last = paneRef.value?.querySelector(`[data-byte="${Math.max(start, end - 1)}"]`)
    if (!hexEl || !first) return
    const hr = hexEl.getBoundingClientRect()
    const fr = first.getBoundingClientRect()
    const lr = (last ?? first).getBoundingClientRect()
    const margin = 6
    if (fr.top < hr.top + margin || lr.bottom > hr.bottom - margin) {
      const delta = (fr.top + lr.bottom) / 2 - (hr.top + hr.height / 2)
      hexEl.scrollTop += delta
    }
  })
}

/** 把选中节点滚动到树容器可视范围(点字节反查字段时用)。 */
function scrollTreeToSelection() {
  nextTick(() => {
    const cont = paneRef.value?.querySelector('.tree-side') as HTMLElement | null
    const sel = cont?.querySelector('.n-tree-node--selected')
    if (!cont || !sel) return
    const sr = cont.getBoundingClientRect()
    const nr = sel.getBoundingClientRect()
    if (nr.top < sr.top || nr.bottom > sr.bottom) {
      cont.scrollTop += nr.top - sr.top - (sr.height - nr.height) / 2
    }
  })
}

function applySelection(key: string) {
  selectedKeys.value = [key]
  const r = rangesIndex.value.find(x => x.key === key)
  if (r) {
    highlight.value = [r.start, r.end]
    scrollToRange(r.start, r.end)
  } else {
    highlight.value = null
  }
}

function onSelect(keys: (string | number)[]) {
  const k = keys[0] as string | undefined
  if (k) applySelection(k)
}

function onByteClick(idx: number) {
  const hits = rangesIndex.value.filter(r => idx >= r.start && idx < r.end)
  if (!hits.length) {
    selectedKeys.value = []
    highlight.value = null
    return
  }
  const best = hits.reduce((a, b) => (b.end - b.start < a.end - a.start ? b : a))
  const layerKey = best.key.split(':')[0]!
  if (!expandedKeys.value.includes(layerKey)) {
    expandedKeys.value = [...expandedKeys.value, layerKey]
  }
  applySelection(best.key)
  scrollTreeToSelection()
}

watch(packet, p => {
  selectedKeys.value = []
  highlight.value = null
  expandedKeys.value = p ? p.layers.map((_, i) => `L${i}`) : []
}, { immediate: true })
</script>

<template>
  <section v-if="packet" ref="paneRef" class="pane">
    <header class="pane-head">
      <span class="no num">#{{ packet.seq }}</span>
      <n-tag v-for="(l, i) in packet.layers" :key="l.id" size="small" :bordered="false"
             class="chip"
             :style="{ color: layerColor(i), background: layerColor(i) + '14' }">
        {{ l.id.toUpperCase() }}
      </n-tag>
      <span class="meta num">{{ packet.len }} B · {{ new Date(packet.ts).toLocaleTimeString() }}</span>
      <button class="close" title="关闭" @click="closeDetail"><X :size="14" /></button>
    </header>

    <div class="pane-body">
      <div class="tree-side">
        <n-tree
          :data="treeData"
          :cancelable="false"
          :selected-keys="selectedKeys"
          :expanded-keys="expandedKeys"
          :render-label="renderLabel"
          @update:selected-keys="onSelect"
          @update:expanded-keys="(k: string[]) => (expandedKeys = k)"
        />
      </div>
      <div class="hex-side">
        <div class="hex-actions">
          <n-button size="tiny" quaternary :disabled="!highlight" @click="copyHex(false)">复制选中</n-button>
          <n-button size="tiny" quaternary @click="copyHex(true)">复制整帧</n-button>
        </div>
        <HexView :packet="packet" :highlight="highlight" :layer-hl="layerHighlight" @byte-click="onByteClick" />
      </div>
    </div>
  </section>
</template>

<style scoped>
.pane {
  height: 336px; flex-shrink: 0;
  display: flex; flex-direction: column;
  border-top: 1px solid #21262d;
  background: #0f141a;
}
.pane-head {
  display: flex; align-items: center; gap: 6px;
  padding: 7px 12px 0;
}
.no { font-size: 12px; color: #8b949e; margin-right: 2px; }
.chip { font-family: ui-monospace, Consolas, monospace; font-size: 11px; }
.meta { margin-left: auto; font-size: 11px; color: #8b949e; padding-right: 8px; }
.close {
  background: none; border: none; cursor: pointer;
  color: #6e7681; padding: 3px; border-radius: 4px; display: flex;
}
.close:hover { color: #c9d1d9; background: rgba(177, 186, 196, .1); }
.pane-body { flex: 1; min-height: 0; display: flex; padding: 0 12px 10px; }
.tree-side {
  flex: 1; min-width: 0; overflow: auto;
  border-right: 1px solid #21262d;
  padding-right: 10px; margin-right: 10px;
}
.hex-side { flex: 1.25; min-width: 0; display: flex; flex-direction: column; }
.hex-actions { display: flex; justify-content: flex-end; gap: 4px; margin-bottom: 2px; }

/* 树节点内容 */
:deep(.layer-row) { display: inline-flex; align-items: center; gap: 7px; min-width: 0; }
:deep(.swatch) { width: 8px; height: 8px; border-radius: 2px; display: inline-block; flex-shrink: 0; }
:deep(.lsummary) {
  font-size: 12px; color: #e6edf3; font-weight: 500;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
:deep(.loff) { color: #6e7681; font-size: 11px; flex-shrink: 0; }
:deep(.bits) { color: #8b949e; font-size: 11px; flex-shrink: 0; }
:deep(.layer-active .lsummary) { color: #79b8ff; }
:deep(.field-row) { display: inline-flex; align-items: center; gap: 10px; min-width: 0; }
:deep(.fname) { color: #8b949e; font-size: 12px; }
:deep(.fvalue) {
  color: #c9d1d9; font-size: 12px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  max-width: 260px;
}
:deep(.copy-btn) {
  opacity: 0; display: inline-flex; align-items: center;
  background: none; border: none; cursor: pointer;
  color: #6e7681; padding: 2px; border-radius: 3px; flex-shrink: 0;
  transition: opacity .12s;
}
:deep(.n-tree-node:hover .copy-btn),
:deep(.copy-btn:hover) { opacity: 1; }
:deep(.copy-btn:hover) { color: #c9d1d9; background: rgba(177, 186, 196, .14); }
:deep(.copy-btn.ok) { color: #57ab5a; }

/* 选中效果:内容宽度内的圆角轻底 + 左侧细强调条(不做通栏色块) */
:deep(.n-tree-node-content) { border-radius: 3px; padding-right: 8px; }
:deep(.n-tree-node-content:hover) { background: rgba(177, 186, 196, .07); }
:deep(.n-tree-node--selected > .n-tree-node-content) {
  background: rgba(83, 155, 245, .18) !important;
  box-shadow: inset 2px 0 0 #539bf5;
}
:deep(.n-tree-node--selected .fname),
:deep(.n-tree-node--selected .fvalue),
:deep(.n-tree-node--selected .lsummary) { color: #fff; }
:deep(.n-tree-node--selected .copy-btn) { opacity: 1; }
:deep(.n-tree-node-indent) { width: 12px !important; }

/* LIST 分组/元素行 */
:deep(.group-row .fname) { color: #c9d1d9; font-weight: 500; }
:deep(.count-badge) {
  font-size: 10px; color: #8b949e; flex-shrink: 0;
  background: rgba(139, 148, 158, .12);
  padding: 0 6px; border-radius: 8px; line-height: 16px;
}
:deep(.eidx) { color: #6e7681; font-size: 11px; flex-shrink: 0; }
:deep(.elem-row .fvalue) { max-width: 340px; }
:deep(.elem-field .fname) { font-size: 11px; }
:deep(.elem-field .fvalue) { font-size: 11px; max-width: 220px; }
</style>
