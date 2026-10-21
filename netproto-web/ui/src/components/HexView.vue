<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import type { Packet } from '../types'
import { hexRows } from '../utils/format'

const props = defineProps<{ packet: Packet; highlight?: [number, number] | null; layerHl?: [number, number] | null }>()
const emit = defineEmits<{ (e: 'byte-click', idx: number): void }>()

const rows = computed(() => hexRows(props.packet))
const rootEl = ref<HTMLElement | null>(null)

/** 选中区外框(SVG 多边形):hex 区与 ASCII 区各一组闭合路径。相邻行段水平区间
 *  有交(含端点相接)→连成阶梯轮廓;不相交(如 2+2 切分)→拆成独立框,
 *  避免强行连桥在未选区域画出多余横线。 */
const hexPolys = ref<[number, number][][]>([])
const asciiPolys = ref<[number, number][][]>([])
const svgW = ref(0)
const svgH = ref(0)

const BYTE_COLS = 16

function inLayer(idx: number): boolean {
  const h = props.layerHl
  return h != null && idx >= h[0] && idx < h[1]
}

interface Seg { xl: number; xr: number; top: number; bot: number }

/** 一条链(水平区间相连的行段)→ 阶梯轮廓。 */
function walkChain(chain: Seg[]): [number, number][] {
  const first = chain[0]!
  const last = chain[chain.length - 1]!
  const pts: [number, number][] = []
  pts.push([first.xl, first.top])                                   // 左上角
  chain.forEach((s, i) => {
    if (i > 0) pts.push([chain[i - 1]!.xr, s.top])                  // 右缘下行肘点
    pts.push([s.xr, s.top])                                         // 本行右上角
  })
  pts.push([last.xr, last.bot])                                     // 右下角
  for (let i = chain.length - 1; i >= 0; i--) {
    if (i < chain.length - 1) pts.push([chain[i + 1]!.xl, chain[i]!.bot])  // 左缘上行肘点
    pts.push([chain[i]!.xl, chain[i]!.bot])                         // 本行左下角
  }
  return pts
}

/** 按 attr(data-byte / data-abyte)测量一列的选中轮廓组;null 表示行未渲染齐(须重试)。 */
function buildPolys(el: HTMLElement, h: [number, number], attr: string): [number, number][][] | null {
  const sRow = Math.floor(h[0] / BYTE_COLS)
  const eRow = Math.floor((h[1] - 1) / BYTE_COLS)
  const expected = eRow - sRow + 1
  const segs: Seg[] = []
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
  // 自校验:选区跨 N 行就得测到 N 行;不足说明 DOM 尚未渲染完(残缺多边形会画出错误封口线)
  if (segs.length < expected) return null
  if (!segs.length) return []
  // 相邻行精确对接:中间行底边 = 下一行顶边
  for (let i = 0; i < segs.length - 1; i++) segs[i]!.bot = segs[i + 1]!.top
  // 按水平交叠分链
  const chains: Seg[][] = []
  let cur: Seg[] = []
  for (const s of segs) {
    if (cur.length) {
      const prev = cur[cur.length - 1]!
      if (Math.min(prev.xr, s.xr) < Math.max(prev.xl, s.xl)) {
        chains.push(cur)   // 水平不相交:断链,各自成框
        cur = []
      }
    }
    cur.push(s)
  }
  if (cur.length) chains.push(cur)
  return chains.map(walkChain)
}

const raf2 = () => new Promise<void>(r => requestAnimationFrame(() => requestAnimationFrame(() => r())))

async function measurePolygon(retries = 5) {
  await nextTick()
  for (let attempt = 0; ; attempt++) {
    const el = rootEl.value
    const h = props.highlight
    if (!el || h == null || h[1] <= h[0]) {
      hexPolys.value = []
      asciiPolys.value = []
      return
    }
    const hx = buildPolys(el, h, 'byte')
    const asc = hx == null ? null : buildPolys(el, h, 'abyte')
    if (hx != null && asc != null) {
      hexPolys.value = hx
      asciiPolys.value = asc
      svgW.value = el.clientWidth      // 可视区尺寸:SVG 不撑大内容宽度,避免出现横向滚动条
      svgH.value = el.clientHeight
      return
    }
    // 行未渲染齐:双 rAF 后重试(跨帧渲染/晚到的行);放弃时保留旧框,避免画残缺封口线
    if (attempt >= retries) return
    await raf2()
  }
}

const hexPolyStrs = computed(() => hexPolys.value.map(p => p.map(pt => pt.join(',')).join(' ')))
const asciiPolyStrs = computed(() => asciiPolys.value.map(p => p.map(pt => pt.join(',')).join(' ')))

watch(() => [props.highlight, rows.value] as const, () => { void measurePolygon() })
onMounted(() => {
  void measurePolygon()
  // 兜底:行晚到/字体加载等导致内容尺寸变化时重测(自愈残缺多边形)
  ro = new ResizeObserver(() => { void measurePolygon() })
  if (rootEl.value) ro.observe(rootEl.value)
})
onBeforeUnmount(() => ro?.disconnect())
let ro: ResizeObserver | null = null
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
    <!-- 选中区外框:hex 与 ASCII 各一组闭合多边形(相连=阶梯,断开=独立框) -->
    <svg v-if="hexPolyStrs.length" class="hl-svg" :width="svgW" :height="svgH" aria-hidden="true">
      <polygon v-for="(pts, i) in hexPolyStrs" :key="'h' + i" :points="pts" />
      <polygon v-for="(pts, i) in asciiPolyStrs" :key="'a' + i" :points="pts" />
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
