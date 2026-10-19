<script setup lang="ts">
import { computed, h, ref, watch } from 'vue'
import { NDataTable, type DataTableColumns } from 'naive-ui'
import type { Packet } from '../types'
import { filteredNewestFirst, store } from '../store'
import { endpoints, fmtTime, info, layerColor, protocolOf } from '../utils/format'

const tableRef = ref<InstanceType<typeof NDataTable> | null>(null)

const rows = computed(() => filteredNewestFirst.value.slice(0, 1000))

function protoChip(p: Packet) {
  const { id, index } = protocolOf(p)
  const c = layerColor(index)
  return h('span', {
    style: {
      color: c,
      background: c + '14',
      padding: '1px 7px',
      borderRadius: '3px',
      fontSize: '11px',
      fontFamily: 'ui-monospace, Consolas, monospace',
    },
  }, id)
}

const columns: DataTableColumns<Packet> = [
  { title: 'No.', key: 'seq', width: 64, render: r => h('span', { class: 'num' }, String(r.seq)) },
  { title: '时间', key: 'ts', width: 100, render: r => h('span', { class: 'num dim' }, fmtTime(r.ts)) },
  {
    title: '源地址', key: 'src', width: 150,
    render: r => h('span', { class: 'mono' }, endpoints(r).src),
  },
  {
    title: '目标地址', key: 'dst', width: 150,
    render: r => h('span', { class: 'mono' }, endpoints(r).dst),
  },
  { title: '协议', key: 'proto', width: 96, render: protoChip },
  { title: '长度', key: 'len', width: 60, render: r => h('span', { class: 'num dim' }, String(r.len)) },
  {
    title: '信息', key: 'info', ellipsis: { tooltip: true },
    render: r => h('span', { class: 'info' }, info(r)),
  },
]

const rowProps = (r: Packet) => ({
  style: store.selected?.seq === r.seq ? 'cursor:pointer' : 'cursor:pointer',
  onClick: () => { store.selected = r },
})

watch(() => rows.value.length, () => {
  const t = tableRef.value as unknown as { scrollTo?: (o: { top: number }) => void } | null
  t?.scrollTo?.({ top: 0 })
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
:deep(.n-data-table-tr) { height: 26px; }
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
