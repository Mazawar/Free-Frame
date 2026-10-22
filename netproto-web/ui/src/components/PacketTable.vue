<script setup lang="ts">
import { computed, h, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { NDataTable, type DataTableColumns } from 'naive-ui'
import type { PacketSummary } from '../types'
import { filteredNewestFirst, selectPacket, store } from '../store'
import { fmtTime, layerColor, protocolOf } from '../utils/format'

const tableRef = ref<InstanceType<typeof NDataTable> | null>(null)
// 虚拟列表对「容器 0 高 / 页面隐藏时灌入的数据」不会自愈:重建表格强制重测。
// heal 覆盖四个入口:首填充、挂载时已有数据(恢复/SSE 先于 bootstrap)、布局晚稳定、页面重新可见/resize。
const tableKey = ref(0)
let healTimer: number | undefined

function heal() {
  if (rows.value.length === 0) return
  tableKey.value++
}

function scheduleHeal() {
  clearTimeout(healTimer)
  healTimer = window.setTimeout(heal, 350)
}

function onVisibility() {
  if (!document.hidden) scheduleHeal()
}

const rows = computed(() => filteredNewestFirst.value)

function protoChip(p: PacketSummary) {
  const { id, index } = protocolOf(p)
  const c = layerColor(index)
  const meta = store.protocols.find(x => x.id === id)
  const base = {
    color: c,
    background: c + '14',
    padding: '1px 7px',
    borderRadius: '3px',
    fontSize: '11px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    whiteSpace: 'nowrap' as const,
  }
  // 有分组的协议只显示一枚顶层组标签(如 [智能配电]);信令名在信息列,完整链路在详情面板
  const segs = meta?.groupPath ?? []
  return h('span', { style: base }, (segs[0] ?? id).toUpperCase())
}

// ---- 列宽:可拖拽 + localStorage 持久化 ----
const WIDTH_KEY = 'netproto.colWidths.v1'
const COL_MIN: Record<string, number> = { seq: 52, ts: 70, src: 90, dst: 90, proto: 60, len: 44 }
const DEFAULT_WIDTHS: Record<string, number> = { seq: 72, ts: 100, src: 170, dst: 170, proto: 120, len: 60 }
const widths = ref<Record<string, number>>({ ...DEFAULT_WIDTHS, ...loadWidths() })

function loadWidths(): Record<string, number> {
  try { return JSON.parse(localStorage.getItem(WIDTH_KEY) ?? '{}') } catch { return {} }
}

/** 拖拽回调(limitedWidth 已按 min/max 钳制):更新列宽并持久化。 */
function onColResize(_w: number, limited: number, column: { key?: string | number }) {
  if (column.key == null) return
  widths.value[column.key] = limited
  try { localStorage.setItem(WIDTH_KEY, JSON.stringify(widths.value)) } catch { /* 配额满:忽略 */ }
}

const columns = computed<DataTableColumns<PacketSummary>>(() => [
  { title: 'No.', key: 'seq', width: widths.value.seq, minWidth: COL_MIN.seq, resizable: true,
    render: r => h('span', { class: 'num' }, String(r.seq)) },
  { title: '时间', key: 'ts', width: widths.value.ts, minWidth: COL_MIN.ts, resizable: true,
    render: r => h('span', { class: 'num dim' }, fmtTime(r.ts)) },
  { title: '源地址', key: 'src', width: widths.value.src, minWidth: COL_MIN.src, resizable: true,
    render: r => h('span', { class: 'mono' }, r.src) },
  { title: '目标地址', key: 'dst', width: widths.value.dst, minWidth: COL_MIN.dst, resizable: true,
    render: r => h('span', { class: 'mono' }, r.dst) },
  { title: '协议', key: 'proto', width: widths.value.proto, minWidth: COL_MIN.proto, resizable: true,
    render: protoChip },
  { title: '长度', key: 'len', width: widths.value.len, minWidth: COL_MIN.len, resizable: true,
    render: r => h('span', { class: 'num dim' }, String(r.len)) },
  {
    title: '信息', key: 'info', ellipsis: { tooltip: true },
    render: r => h('span', { class: 'info' }, r.info),
  },
])

const rowProps = (r: PacketSummary) => ({
  style: 'cursor:pointer',
  onClick: () => selectPacket(r.seq),
})

watch(() => rows.value.length, (n, old) => {
  if (old === 0 && n > 0) {
    tableKey.value++
    scheduleHeal()   // 布局/字体晚稳定时再兜一次
    return
  }
  nextTick(() => t0().scrollTo?.({ top: 0 }))
})

onMounted(() => {
  if (rows.value.length > 0) {
    nextTick(heal)   // 恢复/SSE 先于 bootstrap 到达:mount 中测量不可靠,次帧重建
  }
  document.addEventListener('visibilitychange', onVisibility)
  window.addEventListener('resize', scheduleHeal)
})

onBeforeUnmount(() => {
  document.removeEventListener('visibilitychange', onVisibility)
  window.removeEventListener('resize', scheduleHeal)
  clearTimeout(healTimer)
})

function t0() {
  return tableRef.value as unknown as { scrollTo?: (o: { top: number }) => void } | null
}
</script>

<template>
  <n-data-table
    v-if="store.bootstrapped"
    :key="tableKey"
    ref="tableRef"
    :columns="columns"
    :data="rows"
    :item-height="26"
    :row-key="(r: PacketSummary) => r.seq"
    :row-props="rowProps"
    :row-class-name="(r: PacketSummary) => store.selected === r.seq ? 'sel' : ''"
    virtual-scroll
    flex-height style="height: 100%"
    size="small" :single-line="false"
    @unstable-column-resize="onColResize"
  >
    <template #empty>
      <div class="empty">
        <template v-if="store.packets.length === 0">
          <div class="empty-title">暂无数据</div>
          <div class="empty-sub">选择网卡开始采集后,命中所选协议的帧将实时显示</div>
        </template>
        <template v-else>
          <div class="empty-title">当前过滤无匹配帧</div>
          <div class="empty-sub">在左侧协议列表中勾选要显示的协议</div>
        </template>
      </div>
    </template>
  </n-data-table>
</template>

<style scoped>
/* 整数行高(26px = line-height 20 + padding 3×2 + border 1):虚拟滚动按整数行预算可见区,
   小数行高会把最后一行切在滚动底部折叠线下(显示"少一行") */
:deep(.n-data-table-tr) { height: 26px; }
:deep(.n-data-table-td) { line-height: 20px; padding-top: 3px; padding-bottom: 3px; }
/* 单行不换行:放不下的单元格省略号截断(完整内容在详情面板) */
:deep(.n-data-table-td) {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
:deep(.n-data-table-tr.sel .n-data-table-td) {
  background: #1e3a5f !important;
}
:deep(.n-data-table-tr.sel .n-data-table-td:first-child) {
  box-shadow: inset 2px 0 0 #539bf5;
}
:deep(td .dim) { color: #8b949e; }
:deep(td .info) { color: #c9d1d9; }
:deep(.mono) { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.empty { padding: 48px 0; color: #484f58; }
.empty-title { font-size: 13px; color: #6e7681; margin-bottom: 4px; }
.empty-sub { font-size: 12px; }
</style>
