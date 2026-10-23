<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { NButton, NModal } from 'naive-ui'
import { RefreshCw, X } from 'lucide-vue-next'
import { api } from '../api'
import { selectPacket, store } from '../store'
import type { PacketSummary, Traffic, TrafficConversation } from '../types'

/**
 * 流量分析 / 流量追踪:
 * ① 概览(帧数/字节/时长/平均速率)+ 吞吐时间线(帧/s 与 KB/s 双轴);
 * ② 会话表(方向无关端点对,按字节降序)与协议分布(按字节);
 * ③ 点会话行 = 流量追踪 —— 拉出该端点对双向全部帧,点帧跳回主表选中。
 * 数据来自后端 /traffic 纯摘要聚合(不重解码),开窗期间 2s 自动刷新。
 */

const traffic = ref<Traffic | null>(null)
const trace = ref<{ conv: TrafficConversation; rows: PacketSummary[] } | null>(null)
const loading = ref(false)
let timer: number | undefined

async function refresh() {
  if (!store.sessionId) return
  loading.value = true
  try {
    traffic.value = await api.sessionTraffic(store.sessionId, 20000)
    if (trace.value) await loadTrace(trace.value.conv, true)
  } catch {
    // 拉取失败保持旧图,不打断
  } finally {
    loading.value = false
  }
}

async function loadTrace(c: TrafficConversation, keep = false) {
  try {
    const rows = await api.sessionTrafficFrames(store.sessionId, c, 500)
    trace.value = { conv: c, rows }
  } catch {
    if (!keep) trace.value = null
  }
}

/** 帧行点击:与主表行点击同一条路径(选中 + 拉详情),再关弹窗。 */
function jump(seq: number) {
  selectPacket(seq)
  store.trafficOpen = false
}

onMounted(() => {
  timer = window.setInterval(() => { if (store.trafficOpen) refresh() }, 2000)
})
onBeforeUnmount(() => clearInterval(timer))
watch(() => store.trafficOpen, open => { if (open) refresh() })

// ---- 格式化 ----

const fmtB = (b: number) => {
  const r = Math.round(b * 10) / 10
  return r >= 1048576 ? (r / 1048576).toFixed(1) + ' MB' : r >= 1024 ? (r / 1024).toFixed(1) + ' KB' : r + ' B'
}
const fmtRate = (bps: number) => fmtB(bps) + '/s'
const avgRate = computed(() => {
  const w = traffic.value?.window
  if (!w || w.to <= w.from) return fmtRate(0)
  return fmtRate(w.bytes * 1000 / (w.to - w.from))
})
const fmtDur = (a: number, b: number) => b > a ? ((b - a) / 1000).toFixed(1) + ' s' : '—'
const fmtT = (ts: number) => new Date(ts).toLocaleTimeString('zh-CN', { hour12: false })

// ---- 吞吐时间线几何(帧/s 左轴蓝线,KB/s 右轴绿线) ----

const TL = { W: 880, H: 150, L: 44, R: 52, T: 10, B: 20 }
const tl = computed(() => {
  const t = traffic.value
  if (!t || !t.timeline.buckets.length) return null
  const { from, to } = t.window
  const span = Math.max(to - from, 1)
  const sec = Math.max(t.timeline.bucketMs / 1000, 0.001)
  const fps = t.timeline.buckets.map(b => b.frames / sec)
  const kbs = t.timeline.buckets.map(b => b.bytes / 1024 / sec)
  const fpsMax = Math.max(...fps, 1)
  const kbsMax = Math.max(...kbs, 0.1)
  const x = (t0: number) => TL.L + ((t0 - from) / span) * (TL.W - TL.L - TL.R)
  const h = TL.H - TL.T - TL.B
  const yF = (v: number) => TL.T + (1 - v / fpsMax) * h
  const yK = (v: number) => TL.T + (1 - v / kbsMax) * h
  const line = (arr: number[], ys: (v: number) => number) =>
    t.timeline.buckets.map((b, i) => `${i ? 'L' : 'M'}${x(b.t0).toFixed(1)},${ys(arr[i]!).toFixed(1)}`).join(' ')
  const gy = [0, 0.5, 1].map(f => TL.T + h * (1 - f))
  return {
    dF: line(fps, yF), dK: line(kbs, yK), gy,
    fpsTop: Math.ceil(fpsMax), kbsTop: Math.ceil(kbsMax * 10) / 10,
    ticks: [0, 0.5, 1].map(f => ({ x: x(from + span * f), label: fmtT(from + span * f) })),
  }
})

const protoMaxBytes = computed(() =>
  Math.max(...(traffic.value?.protocols.map(p => p.bytes) ?? []), 1))
</script>

<template>
  <!-- 固定高度布局:弹窗永不因追踪区展开/收起而变高(垂直居中的弹窗长高会把顶部顶出屏幕),
       追踪区出现时会话表区收缩,各区内部滚动。 -->
  <n-modal v-model:show="store.trafficOpen" preset="card" title="流量分析" :style="{ width: '960px' }"
           display-directive="show">
    <div class="body">
      <div class="bar">
        <div v-if="traffic" class="stats">
          <span>帧 <b>{{ traffic.window.frames.toLocaleString() }}</b></span>
          <span>字节 <b>{{ fmtB(traffic.window.bytes) }}</b></span>
          <span>时长 <b>{{ fmtDur(traffic.window.from, traffic.window.to) }}</b></span>
          <span>平均 <b>{{ avgRate }}</b></span>
        </div>
        <span class="grow" />
        <n-button size="small" secondary :loading="loading" @click="refresh">
          <template #icon><RefreshCw :size="12" /></template>
          刷新
        </n-button>
      </div>

      <div v-if="tl" class="chart">
        <svg :width="TL.W" :height="TL.H" class="tl">
          <g v-for="(y, i) in tl.gy" :key="i">
            <line class="grid" :x1="TL.L" :x2="TL.W - TL.R" :y1="y" :y2="y" />
            <text class="lab lf" :x="TL.L - 6" :y="y + 3" text-anchor="end">
              {{ i === 0 ? tl.fpsTop : i === 1 ? Math.round(tl.fpsTop / 2) : 0 }}
            </text>
            <text class="lab lk" :x="TL.W - TL.R + 6" :y="y + 3">
              {{ i === 0 ? tl.kbsTop : i === 1 ? Math.round(tl.kbsTop * 10) / 10 : 0 }}
            </text>
          </g>
          <g v-for="(t, i) in tl.ticks" :key="'t' + i">
            <line class="grid dim" :x1="t.x" :x2="t.x" :y1="TL.T" :y2="TL.H - TL.B" />
            <text class="lab" :x="t.x" :y="TL.H - 6" text-anchor="middle">{{ t.label }}</text>
          </g>
          <path class="kline" :d="tl.dK" />
          <path class="fline" :d="tl.dF" />
          <text class="lab lf" :x="TL.L" :y="TL.T - 0" text-anchor="start">帧/s</text>
          <text class="lab lk" :x="TL.W - TL.R" :y="TL.T - 0" text-anchor="end">KB/s</text>
        </svg>
      </div>
      <div v-else class="empty flex-fill">暂无帧 —— 先「采集」,或注入演示样例</div>

      <div v-if="traffic" class="main">
        <div class="convs">
          <div class="hd">会话(按字节)</div>
          <div class="thead tr">
            <span>协议</span><span>端点</span>
            <span class="num">帧</span><span class="num">字节</span><span class="num">速率</span>
          </div>
          <div class="tbody">
            <div v-for="c in traffic.conversations" :key="c.key" class="tr"
                 :class="{ on: trace?.conv.key === c.key }" @click="loadTrace(c)">
              <span class="proto">{{ c.protoName }}</span>
              <span class="ep" :title="c.key">{{ c.srcHost }}{{ c.withPorts ? ':' + c.srcPort : '' }} ⇄ {{ c.dstHost }}{{ c.withPorts ? ':' + c.dstPort : '' }}</span>
              <span class="num">{{ c.frames }}</span>
              <span class="num">{{ fmtB(c.bytes) }}</span>
              <span class="num">{{ fmtRate(c.rateBps) }}</span>
            </div>
            <div v-if="!traffic.conversations.length" class="none">无会话</div>
          </div>
        </div>
        <div class="protos">
          <div class="hd">协议分布(按字节)</div>
          <div class="prows">
            <div v-for="p in traffic.protocols" :key="p.id" class="prow">
              <span class="pn" :title="p.id">{{ p.name }}</span>
              <span class="pb"><i :style="{ width: (p.bytes / protoMaxBytes * 100).toFixed(1) + '%' }" /></span>
              <span class="pv">{{ fmtB(p.bytes) }} · {{ p.frames }} 帧</span>
            </div>
          </div>
        </div>
      </div>

      <div v-if="trace" class="trace">
        <div class="hd">
          追踪:{{ trace.conv.key }}({{ trace.rows.length }} 帧)
          <button class="x" title="关闭追踪" @click="trace = null"><X :size="12" /></button>
        </div>
        <div class="trows">
          <div v-for="r in trace.rows" :key="r.seq" class="trow" @click="jump(r.seq)"
               title="点击在主表选中该帧">
            <span class="tseq">#{{ r.seq }}</span>
            <span class="tts">{{ fmtT(r.ts) }}</span>
            <span class="tlen">{{ r.len }}B</span>
            <span class="tinfo">{{ r.info }}</span>
          </div>
        </div>
      </div>
    </div>
  </n-modal>
</template>

<style scoped>
/* 弹窗总高固定(clamp 自适应视口),内部各区弹性分配 —— 追踪区出现/消失只改变
   会话表区的高度,弹窗自身永不长高(垂直居中的弹窗长高会把顶部顶出屏幕)。 */
.body {
  height: clamp(480px, 74vh, 660px);
  display: flex;
  flex-direction: column;
}

.bar { flex-shrink: 0; display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.grow { flex: 1; }
.stats { display: flex; gap: 14px; font-size: 12px; color: #8b949e; }
.stats b { color: #e6edf3; font-family: ui-monospace, Consolas, monospace; margin-left: 3px; }

.chart { flex-shrink: 0; background: #0d1117; border: 1px solid #21262d; border-radius: 6px; margin-bottom: 12px; overflow-x: auto; }
.tl { display: block; }
.grid { stroke: #21262d; }
.grid.dim { stroke: #1a1f27; }
.lab { fill: #6e7681; font-size: 10px; font-family: ui-monospace, Consolas, monospace; }
.lab.lf { fill: #539bf5; }
.lab.lk { fill: #57ab5a; }
.fline { fill: none; stroke: #539bf5; stroke-width: 1.5; }
.kline { fill: none; stroke: #57ab5a; stroke-width: 1.5; }

.main { flex: 1; min-height: 0; display: flex; gap: 12px; align-items: stretch; }
.convs { flex: 1.5; min-width: 0; min-height: 0; display: flex; flex-direction: column; }
.protos { flex: 1; min-width: 0; min-height: 0; display: flex; flex-direction: column; }
.hd { flex-shrink: 0; font-size: 12px; color: #8b949e; margin-bottom: 6px; display: flex; align-items: center; gap: 6px; }

.thead, .tr {
  display: grid; grid-template-columns: 110px 1fr 46px 76px 84px;
  gap: 8px; padding: 4px 8px; font-size: 12px; align-items: center;
}
.thead { flex-shrink: 0; color: #6e7681; border-bottom: 1px solid #21262d; }
.tbody { flex: 1; min-height: 0; overflow-y: auto; }
.tr { color: #e6edf3; cursor: pointer; border-radius: 4px; }
.tr:hover { background: #1c2129; }
.tr.on { background: #21262d; }
.tr .proto { color: #79c0ff; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tr .ep { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: ui-monospace, Consolas, monospace; font-size: 11px; }
.tr .num { text-align: right; font-family: ui-monospace, Consolas, monospace; color: #c9d1d9; }
.none { padding: 16px; text-align: center; color: #6e7681; font-size: 12px; }

.prows { flex: 1; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; gap: 6px; }
.prow { display: grid; grid-template-columns: 110px 1fr auto; gap: 8px; align-items: center; font-size: 12px; }
.pn { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #e6edf3; }
.pb { height: 8px; background: #161b22; border-radius: 4px; overflow: hidden; }
.pb i { display: block; height: 100%; background: #539bf5; border-radius: 4px; }
.pv { color: #8b949e; font-family: ui-monospace, Consolas, monospace; font-size: 11px; white-space: nowrap; }

.trace { flex-shrink: 0; height: 200px; display: flex; flex-direction: column; margin-top: 12px; border-top: 1px dashed #2d333b; padding-top: 10px; }
.trace .hd { color: #79c0ff; }
.trace .x { border: none; background: none; color: #8b949e; cursor: pointer; padding: 0; }
.trace .x:hover { color: #f85149; }
.trows { flex: 1; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; gap: 2px; }
.trow {
  display: flex; gap: 10px; font-size: 12px; padding: 3px 8px; border-radius: 4px;
  cursor: pointer; color: #c9d1d9;
}
.trow:hover { background: #1c2129; }
.tseq { color: #6e7681; font-family: ui-monospace, Consolas, monospace; }
.tts { color: #8b949e; font-family: ui-monospace, Consolas, monospace; }
.tlen { font-family: ui-monospace, Consolas, monospace; }
.tinfo { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.empty { padding: 40px 0; text-align: center; color: #6e7681; font-size: 12px; }
.empty.flex-fill { flex: 1; display: flex; align-items: center; justify-content: center; }
</style>
