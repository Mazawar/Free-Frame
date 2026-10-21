<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import type { Packet } from '../types'
import { hexRows } from '../utils/format'

const props = defineProps<{ packet: Packet; highlight?: [number, number] | null; layerHl?: [number, number] | null }>()
const emit = defineEmits<{ (e: 'byte-click', idx: number): void }>()

const rows = computed(() => hexRows(props.packet))
const rootEl = ref<HTMLElement | null>(null)

/** 选中区外框(SVG 多边形顶点):hex 区与 ASCII 区各一条闭合路径,沿各行选区
 *  首尾字节取点画出阶梯形大轮廓 —— 跨行、行间空隙全部包在框内,无拼接缝。 */
const hexPoly = ref<[number, number][]>([])
const asciiPoly = ref<[number, number][]>([])
const svgW = ref(0)
const svgH = ref(0)

const BYTE_COLS = 16

function inLayer(idx: number): boolean {
  const h = props.layerHl
  return h != null && idx >= h[0] && idx < h[1]
}

/** 按 attr(data-byte / data-abyte)测量一列的选中阶梯轮廓。 */
function buildPts(el: HTMLElement, h: [number, number], attr: string): [number, number][] {
  const sRow = Math.floor(h[0] / BYTE_COLS)
  const eRow = Math.floor((h[1] - 1) / BYTE_COLS)
  const segs: { xl: number; xr: number; top: number; bot: number }[] = []
  for (let r = sRow; r <= eRow; r++) {
    const s = Math.max(h[0], r * BYTE_COLS)
    const e = Math.min(h[1], (r + 1) * BYTE_COLS)
    const a = el.querySelector(`[data-${attr}="${s}"]`)
    const b = el.querySelector(`[data-${attr}="${e - 1}"]`)
    if (!(a instanceof HTMLElement) || !(b instanceof HTMLElement)) continue
    segs.push({
      xl: a.offsetLeft,
      xr: b.offsetLeft + b.offsetWidth,
      top: a.offsetTop - 1,
      bot: a.offsetTop + a.offsetHeight + 1,
    })
  }
  if (!segs.length) return []
  // 相邻行精确对接:中间行底边 = 下一行顶边
  for (let i = 0; i < segs.length - 1; i++) segs[i]!.bot = segs[i + 1]!.top

  const pts: [number, number][] = []
  const first = segs[0]!
  const last = segs[segs.length - 1]!
  pts.push([first.xl, first.top])                                   // 左上角
  segs.forEach((s, i) => {
    if (i > 0) pts.push([segs[i - 1]!.xr, s.top])                   // 右缘下行肘点
    pts.push([s.xr, s.top])                                         // 本行右上角
  })
  pts.push([last.xr, last.bot])                                     // 右下角
  for (let i = segs.length - 1; i >= 0; i--) {
    if (i < segs.length - 1) pts.push([segs[i + 1]!.xl, segs[i]!.bot])  // 左缘上行肘点
    pts.push([segs[i]!.xl, segs[i]!.bot])                           // 本行左下角
  }
  return pts
}

async function measurePolygon() {
  await nextTick()
  const el = rootEl.value
  const h = props.highlight
  if (!el || h == null || h[1] <= h[0]) {
    hexPoly.value = []
    asciiPoly.value = []
    return
  }
  hexPoly.value = buildPts(el, h, 'byte')
  asciiPoly.value = buildPts(el, h, 'abyte')
  svgW.value = el.scrollWidth
  svgH.value = el.scrollHeight
}

const hexPolyStr = computed(() => hexPoly.value.map(p => p.join(',')).join(' '))
const asciiPolyStr = computed(() => asciiPoly.value.map(p => p.join(',')).join(' '))

watch(() => [props.highlight, rows.value] as const, () => { void measurePolygon() })
onMounted(() => { void measurePolygon() })
</script>

<template>
  <div ref="rootEl" class="hex mono">
    <div v-for="row in rows" :key="row.offset" class="hrow">
      <span class="off num">{{ row.offset.toString(16).padStart(4, '0') }}</span>
      <span class="cells">
        <span v-for="(c, i) in row.cells" :key="i"
              class="cell"
              :class="{ lhl: inLayer(row.offset + i) }"
              :style="c.color ? `color:${c.color}` : 'color:#6e7681'"
              :data-byte="row.offset + i"
              :title="`0x${(row.offset + i).toString(16).padStart(4, '0')}`"
              @click="emit('byte-click', row.offset + i)">{{ c.hex }}</span>
      </span>
      <span class="ascii">
        <span v-for="(c, i) in row.cells" :key="'a' + i"
              class="cell"
              :class="{ lhl: inLayer(row.offset + i) }"
              :style="c.color ? `color:${c.color}` : 'color:#484f58'"
              :data-abyte="row.offset + i"
              @click="emit('byte-click', row.offset + i)">{{ c.ascii }}</span>
      </span>
    </div>
    <!-- 选中区外框:hex 与 ASCII 各一条闭合多边形(阶梯轮廓),字节色完整保留 -->
    <svg v-if="hexPoly.length" class="hl-svg" :width="svgW" :height="svgH" aria-hidden="true">
      <polygon :points="hexPolyStr" />
      <polygon v-if="asciiPoly.length" :points="asciiPolyStr" />
    </svg>
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
.cells { width: 336px; flex-shrink: 0; }   /* 16 × 21px,均匀无隔断 */
.cell {
  display: inline-block; width: 21px;
  text-align: center;
  cursor: pointer;
  border-radius: 2px;
}
.cell:hover { background: rgba(177, 186, 196, .14); }
/* 所属协议层=浅蓝铺底;选中区由 SVG 多边形外框统一勾边 */
.cell.lhl { background: rgba(31, 111, 235, .16); }
.hl-svg {
  position: absolute; top: 0; left: 0; z-index: 1;
  pointer-events: none; overflow: visible;
}
.hl-svg polygon {
  fill: rgba(88, 166, 255, .08);
  stroke: rgba(88, 166, 255, .95);
  stroke-width: 1;
  stroke-linejoin: round;
}
.ascii { color: #484f58; padding-left: 18px; border-left: 1px solid #1b222b; }
.ascii .cell { width: auto; padding: 0 1px; }
</style>
