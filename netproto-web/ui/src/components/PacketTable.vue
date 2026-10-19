<script setup lang="ts">
import { computed, h, ref, watch } from 'vue'
import { NDataTable, NTag, type DataTableColumns } from 'naive-ui'
import type { Packet } from '../types'
import { filteredNewestFirst, store } from '../store'
import { fmtTime, layerColor, summary } from '../utils/format'

const tableRef = ref<InstanceType<typeof NDataTable> | null>(null)

const rows = computed(() => filteredNewestFirst.value.slice(0, 1000))

const columns: DataTableColumns<Packet> = [
  { title: '#', key: 'seq', width: 70, sorter: (a, b) => a.seq - b.seq },
  { title: '时间', key: 'ts', width: 110, render: r => fmtTime(r.ts) },
  {
    title: '协议路径', key: 'path', width: 300,
    render: r => r.layers.map((l, i) => h(
      NTag,
      { size: 'small', bordered: false, style: `color:${layerColor(i)};border:1px solid ${layerColor(i)}55;background:transparent;margin-right:4px` },
      { default: () => l.id },
    )),
  },
  { title: '长度', key: 'len', width: 70, render: r => `${r.len} B` },
  { title: '概要', key: 'summary', ellipsis: { tooltip: true }, render: r => summary(r) },
]

const rowProps = (r: Packet) => ({
  style: 'cursor: pointer;' + (store.selected?.seq === r.seq ? 'background:#1d3461' : ''),
  onClick: () => { store.selected = r; store.detailOpen = true },
})

// 跟随最新:新帧到达时滚回顶部(表为新→旧)
watch(() => rows.value.length, () => {
  if (store.follow) {
    const t = tableRef.value as unknown as { scrollTo?: (o: { top: number }) => void } | null
    t?.scrollTo?.({ top: 0 })
  }
})
</script>

<template>
  <n-data-table
    ref="tableRef"
    :columns="columns"
    :data="rows"
    :row-key="(r: Packet) => r.seq"
    :row-props="rowProps"
    :row-class-name="(r: Packet) => store.selected?.seq === r.seq ? 'sel' : ''"
    virtual-scroll flex-height style="height: 100%"
    size="small" :single-line="false"
  >
    <template #empty>
      <div class="empty-hint">
        <template v-if="store.packets.length === 0">
          等待数据 —— 选择网卡后点「开始采集」;业务协议挂在 UDP 9999 / 9998 可直接观测
        </template>
        <template v-else>当前过滤条件下没有帧(调整左侧协议过滤)</template>
      </div>
    </template>
  </n-data-table>
</template>

<style scoped>
:deep(.n-data-table-tr.sel) { background: #1d3461 !important; }
</style>
