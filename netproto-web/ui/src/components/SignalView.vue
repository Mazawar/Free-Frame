<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { NButton, NModal, NSelect } from 'naive-ui'
import { RefreshCw } from 'lucide-vue-next'
import { api } from '../api'
import { store } from '../store'
import type { ProtocolMeta, SignalPoint } from '../types'

/**
 * 信号视图:把会话环形缓冲里的帧,按「协议 · 字段」抽成时间序列可视化 ——
 * 模拟量(遥测:电压/电流/温度…)画共享值域曲线,数字量(遥信:状态/标志位)画
 * 逻辑分析仪式方波泳道;1bit 字段自动判数字量,其余可点徽标切换 A/D。
 * 数据由后端 /sessions/{id}/signals 重解码给出(旧→新),开窗期间 2s 自动刷新。
 */

interface Signal {
  proto: string
  field: string
  label: string
  kind: 'analog' | 'digital'
  points: SignalPoint[]
  err?: string
}

const PALETTE = ['#539bf5', '#57ab5a', '#c69026', '#d2a8ff', '#f85149', '#7ee787', '#39c5cf']
const W = 820
const H = 380
const M = { l: 52, r: 14, t: 12, b: 26 }
const LANE_H = 26

const signals = ref<Signal[]>([])
const proto = ref<string | null>(null)
const field = ref<string | null>(null)
let timer: number | undefined

// ---- 源选择(只列有可画数值字段的协议) ----

const NUMERIC = new Set(['int', 'long', 'short', 'byte', 'float', 'double', 'boolean'])
const plottable = (f: { type: string; payload?: boolean; checksum?: boolean; elementClass?: string; lengthField?: string }) =>
  NUMERIC.has(f.type) && !f.payload && !f.checksum && !f.elementClass && !f.lengthField

/** 协议下拉按分组展示(与发包面板同款):组路径做组头,过滤输入仍可跨组搜索。 */
const protoOptions = computed(() => {
  const protos = store.protocols.filter(
    p => (p.category === 'stack' || p.category === 'island') && p.fields.some(plottable))
  const groups = new Map<string, ProtocolMeta[]>()
  for (const p of protos) {
    const g = p.groupPath?.length ? p.groupPath.join(' / ') : (p.builtin ? '内置栈' : '独立协议')
    if (!groups.has(g)) groups.set(g, [])
    groups.get(g)!.push(p)
  }
  return [...groups.entries()].map(([g, ps]) => ({
    type: 'group' as const, label: g, key: g,
    children: ps.map(p => ({ label: p.name, value: p.id })),
  }))
})

const fieldOptions = computed(() => {
  const p = store.protocols.find(x => x.id === proto.value)
  if (!p) return []
  return p.fields.filter(plottable)
    .map(f => ({ label: `${f.label || f.name}${f.size === 1 ? ' 〔数字量〕' : ''}`, value: f.name }))
})

function addSignal() {
  if (!proto.value || !field.value) return
  if (signals.value.some(s => s.proto === proto.value && s.field === field.value)) return
  const p = store.protocols.find(x => x.id === proto.value)!
  const f = p.fields.find(x => x.name === field.value)!
  signals.value.push({
    proto: proto.value,
    field: field.value,
    label: `${p.name} · ${f.label || f.name}`,
    kind: f.size === 1 ? 'digital' : 'analog',
    points: [],
  })
  refreshAll()
}

function removeSignal(i: number) {
  signals.value.splice(i, 1)
}

/** 同一字段两种画法之间切换(如 8bit 运行状态既可曲线也可方波)。 */
function toggleKind(s: Signal) {
  s.kind = s.kind === 'analog' ? 'digital' : 'analog'
}

// ---- 数据拉取:添加即拉一次;开窗期间 2s 轮询(演示节奏,量级毫秒级/千帧) ----

async function refreshAll() {
  if (!store.sessionId || !signals.value.length) return
  await Promise.all(signals.value.map(async s => {
    try {
      const r = await api.sessionSignals(store.sessionId, s.proto, s.field, 1000)
      s.points = r.points
      s.err = undefined
    } catch (e) {
      s.err = (e as Error).message
    }
  }))
}

onMounted(() => {
  // 弹窗 display-directive="show" 关窗不销毁组件:必须守卫 signalOpen,
  // 否则关窗后仍按 2s/信号 轮询(每次还带千帧重解码)
  timer = window.setInterval(() => {
    if (store.signalOpen && signals.value.length) refreshAll()
  }, 2000)
})
onBeforeUnmount(() => clearInterval(timer))
watch(() => store.signalOpen, open => { if (open) refreshAll() })

// ---- 图表几何(纯计算,模板只渲染) ----

const analog = computed(() => signals.value.filter(s => s.kind === 'analog'))
const digital = computed(() => signals.value.filter(s => s.kind === 'digital'))
const colorAt = (s: Signal) => PALETTE[signals.value.indexOf(s) % PALETTE.length]

function extent(xs: number[]): [number, number] {
  let a = Infinity, b = -Infinity
  for (const x of xs) { if (x < a) a = x; if (x > b) b = x }
  return [a, b]
}

const plot = computed(() => {
  const all = signals.value.flatMap(s => s.points)
  if (!all.length) return null
  const [tMin, tMax0] = extent(all.map(p => p.ts))
  const span = Math.max(tMax0 - tMin, 1)
  const digitalH = digital.value.length * LANE_H
  const plotH = Math.max(H - M.t - M.b - (digitalH ? digitalH + 8 : 0), 40)
  const x = (ts: number) => M.l + ((ts - tMin) / span) * (W - M.l - M.r)

  // 模拟区共享值域(所有曲线同尺度,不归一化误导)
  const avs = analog.value.flatMap(s => s.points.map(p => p.v))
  let [vMin0, vMax0] = avs.length ? extent(avs) : [0, 1]
  if (vMin0 === vMax0) { vMin0 -= 1; vMax0 += 1 }
  const pad = (vMax0 - vMin0) * 0.08
  const vMin = vMin0 - pad, vMax = vMax0 + pad
  const y = (v: number) => M.t + plotH - ((v - vMin) / (vMax - vMin)) * plotH

  const lines = analog.value.map(s => {
    const pts = s.points.map(p => ({ cx: x(p.ts), cy: y(p.v) }))
    return {
      color: colorAt(s),
      // 点少时补画数据点圆点,单点/稀疏也能看见
      dots: pts.length <= 60 ? pts : [],
      d: pts.map((p, i) => `${i ? 'L' : 'M'}${p.cx.toFixed(1)},${p.cy.toFixed(1)}`).join(' '),
    }
  })

  // 数字泳道:step-after 方波,末尾保持到图右缘
  const lanes = digital.value.map(s => {
    const li = digital.value.indexOf(s)
    const mid = M.t + plotH + 8 + li * LANE_H + LANE_H / 2
    let d = ''
    s.points.forEach((p, i) => {
      const yy = p.v ? mid - 8 : mid + 8
      const x0 = x(p.ts).toFixed(1)
      if (i === 0) { d += `M${x0},${yy.toFixed(1)}`; return }
      const prev = s.points[i - 1]!
      d += ` L${x0},${(prev.v ? mid - 8 : mid + 8).toFixed(1)} L${x0},${yy.toFixed(1)}`
    })
    const last = s.points[s.points.length - 1]
    if (last) d += ` L${(W - M.r).toFixed(1)},${(last.v ? mid - 8 : mid + 8).toFixed(1)}`
    return { color: colorAt(s), mid, d, points: s.points }
  })

  const ticks = [0, 0.25, 0.5, 0.75, 1].map(f => ({
    x: x(tMin + span * f),
    label: new Date(tMin + span * f).toLocaleTimeString('zh-CN', { hour12: false }),
  }))
  const vTicks = [0, 1 / 3, 2 / 3, 1].map(f =>
    ({ y: M.t + plotH * (1 - f), v: vMin + (vMax - vMin) * f }))
  return { lines, lanes, ticks, vTicks, plotH }
})

function fmtV(v: number): string {
  return Math.abs(v) >= 1000 ? v.toFixed(0) : String(Math.round(v * 10) / 10)
}

function lastV(s: Signal): string {
  const p = s.points[s.points.length - 1]
  return p ? fmtV(p.v) : '—'
}
</script>

<template>
  <n-modal v-model:show="store.signalOpen" preset="card" title="信号视图" :style="{ width: '900px' }"
           display-directive="show">
    <!-- 固定高度:加信号 chips 换行也不会把弹窗顶高 -->
    <div class="body">
      <div class="bar">
        <n-select v-model:value="proto" :options="protoOptions" filterable size="small"
                  placeholder="协议" class="sel" />
        <n-select v-model:value="field" :options="fieldOptions" size="small"
                  placeholder="字段(数值 / 位)" class="sel" :disabled="!proto" />
        <n-button size="small" type="primary" :disabled="!proto || !field" @click="addSignal">添加</n-button>
        <span class="grow" />
        <n-button size="small" secondary @click="refreshAll">
          <template #icon><RefreshCw :size="12" /></template>
          刷新
        </n-button>
      </div>

    <div v-if="signals.length" class="chips">
      <span v-for="(s, i) in signals" :key="s.proto + '.' + s.field" class="chip"
            :title="s.err ?? `${s.points.length} 点 · 当前 ${lastV(s)}`">
        <i class="dot" :style="{ background: PALETTE[i % PALETTE.length] }" />
        {{ s.label }}
        <button class="kind" :title="s.kind === 'analog' ? '切换为数字量(方波)' : '切换为模拟量(曲线)'"
                @click="toggleKind(s)">{{ s.kind === 'analog' ? '模拟' : '数字' }}</button>
        <span class="cur">{{ lastV(s) }}</span>
        <button class="x" title="移除" @click="removeSignal(i)">×</button>
      </span>
    </div>

    <div class="chart">
      <svg v-if="plot" :width="W" :height="H" class="sg">
        <g v-for="(t, i) in plot.vTicks" :key="'v' + i">
          <line class="grid" :x1="M.l" :x2="W - M.r" :y1="t.y" :y2="t.y" />
          <text class="lab" :x="M.l - 6" :y="t.y + 3" text-anchor="end">{{ fmtV(t.v) }}</text>
        </g>
        <g v-for="(t, i) in plot.ticks" :key="'t' + i">
          <line class="grid dim" :x1="t.x" :x2="t.x" :y1="M.t" :y2="H - M.b" />
          <text class="lab" :x="t.x" :y="H - 8" text-anchor="middle">{{ t.label }}</text>
        </g>
        <!-- 模拟量曲线 -->
        <g v-for="(l, i) in plot.lines" :key="'a' + i">
          <path class="curve" :d="l.d" :stroke="l.color" />
          <circle v-for="(p, j) in l.dots" :key="j" class="pt"
                  :cx="p.cx" :cy="p.cy" :fill="l.color" />
        </g>
        <!-- 数字量方波泳道 -->
        <g v-for="(ln, i) in plot.lanes" :key="'d' + i">
          <line class="lane-base" :x1="M.l" :x2="W - M.r" :y1="ln.mid" :y2="ln.mid" />
          <path class="pulse" :d="ln.d" :stroke="ln.color" />
          <text class="lab" :x="M.l - 6" :y="ln.mid + 3" text-anchor="end">D{{ i + 1 }}</text>
        </g>
      </svg>
      <div v-else class="empty">
        {{ signals.length
          ? '暂无选中协议的帧 —— 先「采集」,或注入演示样例(智能配电 · 状态上报:电压/电流/温度/运行状态)'
          : '选择协议与字段,添加信号后展示遥测曲线与遥信方波' }}
      </div>
    </div>
    </div>
  </n-modal>
</template>

<style scoped>
/* 固定高度:chips 换行增多也不顶高弹窗(与 TrafficView 同规矩) */
.body {
  height: clamp(470px, 60vh, 560px);
  display: flex;
  flex-direction: column;
}

.bar { flex-shrink: 0; display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.sel { width: 240px; }
.grow { flex: 1; }

.chips { flex-shrink: 0; display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
.chip {
  display: inline-flex; align-items: center; gap: 6px;
  font-size: 12px; color: #e6edf3;
  background: #1c2129; border: 1px solid #2d333b; border-radius: 999px;
  padding: 2px 8px;
}
.chip .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.chip .cur { color: #8b949e; font-family: ui-monospace, Consolas, monospace; }
.chip .kind, .chip .x {
  border: none; background: none; cursor: pointer; padding: 0 2px;
  color: #8b949e; font-size: 11px; line-height: 1;
}
.chip .kind:hover { color: #539bf5; }
.chip .x:hover { color: #f85149; }

.chart { flex: 1; min-height: 0; background: #0d1117; border: 1px solid #21262d; border-radius: 6px; overflow: auto; }
.sg { display: block; }

.grid { stroke: #21262d; stroke-width: 1; }
.grid.dim { stroke: #1a1f27; }
.lab { fill: #6e7681; font-size: 10px; font-family: ui-monospace, Consolas, monospace; }
.curve { fill: none; stroke-width: 1.5; stroke-linejoin: round; }
.pt { r: 2.2; stroke: #0d1117; stroke-width: 1; }
.pulse { fill: none; stroke-width: 1.5; }
.lane-base { stroke: #21262d; stroke-dasharray: 2 3; }

.empty {
  padding: 48px 0; text-align: center; color: #6e7681; font-size: 12px;
}
</style>
