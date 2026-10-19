<script setup lang="ts">
import { computed, h, nextTick, ref, watch } from 'vue'
import { NTag, NTree } from 'naive-ui'
import { X } from 'lucide-vue-next'
import { closeDetail, store } from '../store'
import { fmtValue, layerColor } from '../utils/format'
import HexView from './HexView.vue'
import type { Packet } from '../types'

const packet = computed(() => store.selected)
const paneRef = ref<HTMLElement | null>(null)

const selectedKeys = ref<string[]>([])
const expandedKeys = ref<string[]>([])
const highlight = ref<[number, number] | null>(null)

// ---- 嵌套树:层 i 是层 i-1 的最后一个子节点(Wireshark 式父子结构) ----

interface Meta {
  kind: 'layer' | 'field'
  layerIndex: number
  fieldName?: string
  value?: unknown
}

function shortValue(v: unknown): string {
  const s = fmtValue(v)
  if (s.length > 64) return `${Math.floor(s.length / 2)} B · ${s.slice(0, 28)}…`
  return s
}

const treeData = computed(() => {
  const p = packet.value
  if (!p) return []
  const roots: any[] = []
  let prev: any = null
  p.layers.forEach((l, i) => {
    const children: any[] = Object.entries(l.fields).map(([k, v]) => ({
      key: `L${i}:${k}`,
      meta: { kind: 'field', layerIndex: i, fieldName: k, value: v } satisfies Meta,
    }))
    // payload 类长值占位文本
    const node: any = {
      key: `L${i}`,
      meta: { kind: 'layer', layerIndex: i } satisfies Meta,
      children,
      isLeaf: false,
    }
    if (prev) prev.children.push(node)
    else roots.push(node)
    prev = node
  })
  return roots
})

function renderLabel({ option }: { option: any }) {
  const meta = option.meta as Meta
  if (meta.kind === 'layer') {
    const l = packet.value!.layers[meta.layerIndex]!
    return h('span', { class: 'layer-row' }, [
      h('span', { class: 'swatch', style: { background: layerColor(meta.layerIndex) } }),
      h('span', { class: 'lname' }, l.name),
      h('span', { class: 'loff mono' }, `@${l.offset} · ${l.headerLen} B`),
    ])
  }
  return h('span', { class: 'field-row' }, [
    h('span', { class: 'fname' }, meta.fieldName ?? ''),
    h('span', { class: 'fvalue num', title: fmtValue(meta.value) }, shortValue(meta.value)),
  ])
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

function scrollToByte(start: number) {
  nextTick(() => {
    paneRef.value?.querySelector(`[data-byte="${start}"]`)?.scrollIntoView({ block: 'nearest' })
  })
}

function applySelection(key: string) {
  selectedKeys.value = [key]
  const r = rangesIndex.value.find(x => x.key === key)
  if (r) {
    highlight.value = [r.start, r.end]
    scrollToByte(r.start)
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
        {{ l.id }}
      </n-tag>
      <span class="meta num">{{ packet.len }} B · {{ new Date(packet.ts).toLocaleTimeString() }}</span>
      <button class="close" title="关闭" @click="closeDetail"><X :size="14" /></button>
    </header>

    <div class="pane-body">
      <div class="tree-side">
        <n-tree
          :data="treeData"
          block-line
          :cancelable="false"
          :selected-keys="selectedKeys"
          :expanded-keys="expandedKeys"
          :render-label="renderLabel"
          @update:selected-keys="onSelect"
          @update:expanded-keys="(k: string[]) => (expandedKeys = k)"
        />
      </div>
      <div class="hex-side">
        <div class="legend">
          <span v-for="(l, i) in packet.layers" :key="l.id" class="lg">
            <span class="swatch" :style="{ background: layerColor(i) }"></span>
            {{ l.id }} @{{ l.offset }}-{{ l.offset + l.headerLen }}
          </span>
          <span class="lg tip">点字段或点字节互相定位</span>
        </div>
        <HexView :packet="packet" :highlight="highlight" @byte-click="onByteClick" />
      </div>
    </div>
  </section>
</template>

<style scoped>
.pane {
  height: 320px; flex-shrink: 0;
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
.legend { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 6px; align-items: center; }
.lg { display: inline-flex; align-items: center; gap: 5px; font-size: 11px; color: #8b949e; }
.lg.tip { color: #484f58; margin-left: auto; }
.swatch { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }

/* 树节点内容 */
:deep(.layer-row) { display: inline-flex; align-items: center; gap: 7px; }
:deep(.lname) { font-weight: 600; color: #e6edf3; font-size: 12px; }
:deep(.loff) { color: #6e7681; font-size: 11px; }
:deep(.field-row) { display: inline-flex; align-items: baseline; gap: 10px; min-width: 0; }
:deep(.fname) { color: #8b949e; font-size: 12px; }
:deep(.fvalue) {
  color: #c9d1d9; font-size: 12px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  max-width: 260px;
}
:deep(.n-tree-node--selected .fname),
:deep(.n-tree-node--selected .fvalue) { color: #fff; }
:deep(.n-tree-node-indent) { width: 12px !important; }
</style>
