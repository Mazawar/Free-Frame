<script setup lang="ts">
import { computed, ref } from 'vue'
import { NCollapse, NCollapseItem, NTabs, NTabPane, NTag } from 'naive-ui'
import { X } from 'lucide-vue-next'
import { closeDetail, store } from '../store'
import { fmtTime, fmtValue, layerColor } from '../utils/format'
import HexView from './HexView.vue'

const packet = computed(() => store.selected)
const tab = ref<'tree' | 'bytes'>('tree')
const expanded = computed({
  get: () => [packet.value?.layers[packet.value.layers.length - 1]?.id ?? ''],
  set: () => { /* 受控展示,不需要展开状态持久化 */ },
})
</script>

<template>
  <section v-if="packet" class="pane">
    <header class="pane-head">
      <span class="no num">#{{ packet.seq }}</span>
      <n-tag v-for="(l, i) in packet.layers" :key="l.id" size="small" :bordered="false"
             class="chip"
             :style="{ color: layerColor(i), background: layerColor(i) + '14' }">
        {{ l.id }}
      </n-tag>
      <span class="meta num">{{ packet.len }} B · {{ fmtTime(packet.ts) }}</span>
      <button class="close" title="关闭" @click="closeDetail"><X :size="14" /></button>
    </header>

    <n-tabs v-model:value="tab" type="line" size="small" class="tabs" :show-tabs-bar="false">
      <n-tab-pane name="tree" tab="协议树" display-directive="show">
        <div class="tree">
          <n-collapse :default-expanded-names="expanded" arrow-placement="left">
            <n-collapse-item v-for="(l, i) in packet.layers" :key="l.id" :name="l.id">
              <template #header>
                <span class="layer-head">
                  <span class="swatch" :style="{ background: layerColor(i) }"></span>
                  {{ l.name }}
                  <span class="off">@{{ l.offset }} · {{ l.headerLen }} B</span>
                </span>
              </template>
              <table class="kv-table">
                <tbody>
                  <tr v-for="(v, k) in l.fields" :key="k">
                    <td class="k">{{ k }}</td>
                    <td class="v">{{ fmtValue(v) }}</td>
                  </tr>
                </tbody>
              </table>
            </n-collapse-item>
          </n-collapse>
        </div>
      </n-tab-pane>
      <n-tab-pane name="bytes" tab="字节" display-directive="show">
        <div class="bytes-wrap">
          <div class="legend">
            <span v-for="(l, i) in packet.layers" :key="l.id" class="lg">
              <span class="swatch" :style="{ background: layerColor(i) }"></span>
              {{ l.id }} @{{ l.offset }}-{{ l.offset + l.headerLen }}
            </span>
          </div>
          <HexView :packet="packet" />
        </div>
      </n-tab-pane>
    </n-tabs>
  </section>
</template>

<style scoped>
.pane {
  height: 296px; flex-shrink: 0;
  display: flex; flex-direction: column;
  border-top: 1px solid #21262d;
  background: #0f141a;
}
.pane-head {
  display: flex; align-items: center; gap: 6px;
  padding: 7px 12px 0;
  border-bottom: 1px solid #21262d;
}
.no { font-size: 12px; color: #8b949e; margin-right: 2px; }
.chip { font-family: ui-monospace, Consolas, monospace; font-size: 11px; }
.meta { margin-left: auto; font-size: 11px; color: #8b949e; padding-right: 8px; }
.close {
  background: none; border: none; cursor: pointer;
  color: #6e7681; padding: 3px; border-radius: 4px; display: flex;
}
.close:hover { color: #c9d1d9; background: rgba(177, 186, 196, .1); }
.tabs { flex: 1; min-height: 0; display: flex; flex-direction: column; padding: 0 12px; }
.tabs :deep(.n-tabs-nav) { padding-top: 2px; }
.tabs :deep(.n-tabs-tab) { font-size: 12px; }
.tabs :deep(.n-tab-pane) { padding-top: 8px !important; }
.tree { overflow-y: auto; height: 200px; padding-right: 4px; }
.tree :deep(.n-collapse-item__header) { font-size: 12px; }
.tree :deep(.n-collapse-item__content-inner) { padding-top: 2px !important; }
.layer-head { display: inline-flex; align-items: center; gap: 7px; }
.swatch { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }
.off { color: #6e7681; font-size: 11px; font-family: ui-monospace, Consolas, monospace; }
.bytes-wrap { height: 200px; display: flex; flex-direction: column; }
.legend { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 6px; }
.lg { display: inline-flex; align-items: center; gap: 5px; font-size: 11px; color: #8b949e; }
</style>
