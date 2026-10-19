<script setup lang="ts">
import { computed } from 'vue'
import { NCollapse, NCollapseItem, NDrawer, NDrawerContent, NSpace, NTag } from 'naive-ui'
import { store } from '../store'
import { fmtValue, layerColor } from '../utils/format'
import HexView from './HexView.vue'

const packet = computed(() => store.selected)
</script>

<template>
  <n-drawer v-model:show="store.detailOpen" :width="560" placement="right">
    <n-drawer-content v-if="packet" :title="`#${packet.seq} · ${packet.len} B · ${packet.path}`" closable>
      <n-space vertical :size="12" style="height: 100%">
        <n-collapse :default-expanded-names="[packet.layers[packet.layers.length - 1]?.id]">
          <n-collapse-item
            v-for="(l, i) in packet.layers"
            :key="l.id"
            :name="l.id"
          >
            <template #header>
              <span :style="{ color: layerColor(i), fontWeight: 600 }">■</span>
              <span style="margin: 0 6px">{{ l.name }}</span>
              <span class="off">@{{ l.offset }} +{{ l.headerLen }}B</span>
            </template>
            <table class="kv-table">
              <tbody>
                <tr v-for="(v, k) in l.fields" :key="k">
                  <td class="k">{{ k }}</td>
                  <td>{{ fmtValue(v) }}</td>
                </tr>
              </tbody>
            </table>
          </n-collapse-item>
        </n-collapse>

        <div style="flex-shrink: 0">
          <div class="hex-legend">
            <n-tag v-for="(l, i) in packet.layers" :key="l.id" size="small" :bordered="false"
                   :style="`color:${layerColor(i)};border:1px solid ${layerColor(i)}55;background:transparent`">
              {{ l.id }} @{{ l.offset }}-{{ l.offset + l.headerLen }}
            </n-tag>
          </div>
          <HexView :packet="packet" style="max-height: 40vh" />
        </div>
      </n-space>
    </n-drawer-content>
  </n-drawer>
</template>

<style scoped>
.off { color: #64748b; font-size: 11px; }
.hex-legend { margin-bottom: 6px; display: flex; flex-wrap: wrap; gap: 4px; }
</style>
