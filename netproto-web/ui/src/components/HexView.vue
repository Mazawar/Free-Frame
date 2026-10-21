<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import type { Packet } from '../types'
import { hexRows } from '../utils/format'

const props = defineProps<{ packet: Packet; highlight?: [number, number] | null; layerHl?: [number, number] | null }>()
const emit = defineEmits<{ (e: 'byte-click', idx: number): void }>()

const rows = computed(() => hexRows(props.packet))
const rootEl = ref<HTMLElement | null>(null)
/** 选中区外框:跨行时拆成 首段/中段/尾段 三个精确对接的矩形,边框只画外圈,视觉上是一个大框 */
const boxes = ref<{ x: number; y: number; w: number; h: number; cls: string }[]>([])

const BYTE_COLS = 16

function inHighlight(idx: number): boolean {
  const h = props.highlight
  return h != null && idx >= h[0] && idx < h[1]
}

function inLayer(idx: number): boolean {
  const h = props.layerHl
  return h != null && idx >= h[0] && idx < h[1]
}

/**
 * 选中区外框测量:对 选中首字节、选中尾字节、各完整中间行的首尾字节 取 DOM 盒。
 * 矩形以 .hex(overflow 容器)为定位父级,随滚动一起移动;
 * 中段矩形按字节区全宽 —— 8 字节分组间隔等「隔断」都被包进框内。
 */
async function measureBoxes() {
  await nextTick()
  const el = rootEl.value
  const h = props.highlight
  if (!el || h == null || h[1] <= h[0]) {
    boxes.value = []
    return
  }
  const sRow = Math.floor(h[0] / BYTE_COLS)
  const eRow = Math.floor((h[1] - 1) / BYTE_COLS)
  const segs: [number, number][] = []
  if (sRow === eRow) {
    segs.push([h[0], h[1]])
  } else {
    segs.push([h[0], (sRow + 1) * BYTE_COLS])
    for (let r = sRow + 1; r < eRow; r++) segs.push([r * BYTE_COLS, (r + 1) * BYTE_COLS])
    segs.push([eRow * BYTE_COLS, h[1]])
  }
  const out: { x: number; y: number; w: number; h: number; cls: string }[] = []
  // 行距(行首到下行行首):跨行矩形的垂直延伸量,保证相邻段无缝对接
  const rowTop = (idx: number) => {
    const c = el.querySelector(`[data-byte="${idx}"]`)
    return c instanceof HTMLElement ? c.offsetTop : null
  }
  segs.forEach(([s, e], i) => {
    const a = el.querySelector(`[data-byte="${s}"]`)
    const b = el.querySelector(`[data-byte="${e - 1}"]`)
    if (!(a instanceof HTMLElement) || !(b instanceof HTMLElement)) return
    const row = Math.floor(s / BYTE_COLS)
    let top = a.offsetTop - 1
    let bottom = b.offsetTop + b.offsetHeight + 1
    if (i < segs.length - 1) {
      // 非最后段:向下延伸到下一行行首,填掉行间空隙(隔断/换行都包进框内)
      const nextTop = rowTop((row + 1) * BYTE_COLS)
      if (nextTop != null) bottom = nextTop
    }
    if (i > 0) top = a.offsetTop - 1
    const first = i === 0
    out.push({
      x: a.offsetLeft,
      y: top,
      w: b.offsetLeft + b.offsetWidth - a.offsetLeft,
      h: bottom - top,
      cls: segs.length === 1 ? 'hl-single' : first ? 'hl-first' : i === segs.length - 1 ? 'hl-last' : 'hl-mid',
    })
  })
  boxes.value = out
}

watch(() => [props.highlight, rows.value] as const, () => { void measureBoxes() })
onMounted(() => { void measureBoxes() })
</script>

<template>
  <div ref="rootEl" class="hex mono">
    <div v-for="row in rows" :key="row.offset" class="hrow">
      <span class="off num">{{ row.offset.toString(16).padStart(4, '0') }}</span>
      <span class="cells">
        <span v-for="(c, i) in row.cells" :key="i"
              class="cell"
              :class="{ lhl: !inHighlight(row.offset + i) && inLayer(row.offset + i), g8: i === 8 }"
              :style="c.color ? `color:${c.color}` : 'color:#6e7681'"
              :data-byte="row.offset + i"
              :title="`0x${(row.offset + i).toString(16).padStart(4, '0')}`"
              @click="emit('byte-click', row.offset + i)">{{ c.hex }}</span>
      </span>
      <span class="ascii">
        <span v-for="(c, i) in row.cells" :key="'a' + i"
              class="cell"
              :style="c.color ? `color:${c.color}` : 'color:#484f58'"
              @click="emit('byte-click', row.offset + i)">{{ c.ascii }}</span>
      </span>
    </div>
    <!-- 选中区外框:整段一个大轮廓,隔断/换行都包在框内 -->
    <div v-for="(o, i) in boxes" :key="'b' + i" class="hl-box" :class="o.cls"
         :style="{ left: o.x + 'px', top: o.y + 'px', width: o.w + 'px', height: o.h + 'px' }" />
  </div>
</template>

<style scoped>
.hex {
  flex: 1; overflow: auto;
  position: relative;
  font-size: 12px; line-height: 1.65;
  background: #0b0f14;
  border: 1px solid #1b222b;
  border-radius: 4px;
  padding: 6px 10px;
}
.hrow { display: flex; white-space: pre; }
.off { color: #484f58; width: 44px; flex-shrink: 0; user-select: none; }
.cells { width: 350px; flex-shrink: 0; }
.cell {
  display: inline-block; width: 21px;
  text-align: center;
  cursor: pointer;
  border-radius: 2px;
}
/* 第 9 字节起为第二组:左移出 8 字节分组间隔 */
.cell.g8 { margin-left: 14px; }
.cell:hover { background: rgba(177, 186, 196, .14); }
/* 所属协议层=浅蓝铺底;选中区不再逐字节着色,由外框层统一勾边 */
.cell.lhl { background: rgba(31, 111, 235, .16); }
.hl-box {
  position: absolute; z-index: 1; pointer-events: none;
  box-sizing: border-box;
  border-style: solid; border-color: rgba(88, 166, 255, .95);
  background: rgba(88, 166, 255, .07);
}
.hl-box.hl-single { border-width: 1px; border-radius: 4px; }
.hl-box.hl-first { border-width: 1px 1px 0 1px; border-radius: 4px 4px 0 0; }
.hl-box.hl-mid { border-width: 0 1px; }
.hl-box.hl-last { border-width: 0 1px 1px 1px; border-radius: 0 0 4px 4px; }
.ascii { color: #484f58; padding-left: 18px; border-left: 1px solid #1b222b; }
.ascii .cell { width: auto; padding: 0 1px; }
</style>
