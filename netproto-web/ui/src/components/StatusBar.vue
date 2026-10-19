<script setup lang="ts">
import { computed } from 'vue'
import { filteredNewestFirst, store } from '../store'

const ifaceLabel = computed(() => {
  const hit = store.interfaces.find(i => i.name === store.iface)
  return hit ? (hit.description || hit.name).slice(0, 46) : (store.iface || '-')
})

const rate = computed(() => {
  if (store.packets.length < 2) return null
  const first = store.packets[0]!
  const last = store.packets[store.packets.length - 1]!
  const secs = Math.max(0.001, (last.ts - first.ts) / 1000)
  return (store.packets.length / secs).toFixed(1)
})
</script>

<template>
  <div class="status">
    <span>缓冲 {{ store.packets.length }} 帧(上限 2000)</span>
    <span>过滤后 {{ filteredNewestFirst.length }} 帧</span>
    <span v-if="rate">速率 ~{{ rate }} fps</span>
    <span class="spacer"></span>
    <span>{{ ifaceLabel }}</span>
  </div>
</template>

<style scoped>
.status { display: flex; gap: 16px; color: #64748b; font-size: 11px; align-items: center; }
.spacer { flex: 1; }
</style>
