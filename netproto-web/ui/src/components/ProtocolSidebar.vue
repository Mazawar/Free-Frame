<script setup lang="ts">
import { computed } from 'vue'
import { NButton, NCheckbox, NSpace, NTag } from 'naive-ui'
import { protoCounts, store } from '../store'

const entries = computed(() =>
  store.protocols.map(p => ({ meta: p, count: protoCounts.value.get(p.id) ?? 0 })))

function toggleAll(on: boolean) {
  if (on) store.protocols.forEach(p => store.enabled.add(p.id))
  else store.enabled.clear()
}

const allOn = computed(() =>
  store.protocols.length > 0 && store.protocols.every(p => store.enabled.has(p.id)))
</script>

<template>
  <div>
    <div class="side-head">
      <span>协议过滤</span>
      <n-space :size="4">
        <n-button size="tiny" quaternary @click="toggleAll(true)">全选</n-button>
        <n-button size="tiny" quaternary @click="toggleAll(false)">全不选</n-button>
      </n-space>
    </div>
    <ul class="proto-list">
      <li v-for="e in entries" :key="e.meta.id">
        <n-checkbox size="small" :checked="store.enabled.has(e.meta.id)"
                    :on-update:checked="(v: boolean) => v ? store.enabled.add(e.meta.id) : store.enabled.delete(e.meta.id)">
          <span class="proto-name" :title="e.meta.id">{{ e.meta.name }}</span>
        </n-checkbox>
        <span class="proto-count" v-if="e.count">{{ e.count }}</span>
        <n-tag v-if="e.meta.builtin" size="tiny" :bordered="false" class="builtin">内置</n-tag>
      </li>
    </ul>
    <p class="hint">只显示勾选协议命中的帧;未注册协议不会被引擎解析。</p>
  </div>
</template>

<style scoped>
.side-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; color: #cbd5e1; font-size: 13px; }
.proto-list { list-style: none; margin: 0; padding: 0; }
.proto-list li { display: flex; align-items: center; gap: 6px; padding: 3px 2px; }
.proto-name { font-size: 12px; max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.proto-count { margin-left: auto; font-size: 11px; color: #94a3b8; }
.builtin { font-size: 10px; }
.hint { color: #64748b; font-size: 11px; margin-top: 12px; line-height: 1.6; }
</style>
