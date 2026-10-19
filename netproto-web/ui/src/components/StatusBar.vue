<script setup lang="ts">
import { computed } from 'vue'
import { filteredNewestFirst, store } from '../store'

const ifaceLabel = computed(() => {
  const hit = store.interfaces.find(i => i.name === store.iface)
  return hit ? (hit.description || hit.name).slice(0, 48) : store.iface || ''
})

const rate = computed(() => {
  if (store.packets.length < 2) return null
  const first = store.packets[0]!
  const last = store.packets[store.packets.length - 1]!
  const secs = Math.max(0.001, (last.ts - first.ts) / 1000)
  return (store.packets.length / secs).toFixed(1)
})

const sseText = computed(() =>
  store.sse === 'open' ? '实时' : store.sse === 'connecting' ? '重连中' : '已断开')
</script>

<template>
  <footer class="bar">
    <span class="num">缓冲 {{ store.packets.length }}</span>
    <span class="num">显示 {{ filteredNewestFirst.length }}</span>
    <span v-if="rate" class="num">{{ rate }} 帧/秒</span>
    <span class="flex1"></span>
    <span v-if="ifaceLabel" class="dim">{{ ifaceLabel }}</span>
    <span class="sse" :class="store.sse">
      <span class="dot"></span>{{ sseText }}
    </span>
  </footer>
</template>

<style scoped>
.bar {
  height: 26px; flex-shrink: 0;
  display: flex; align-items: center; gap: 16px;
  padding: 0 12px;
  font-size: 11px; color: #8b949e;
  background: #12171e;
  border-top: 1px solid #21262d;
  user-select: none;
}
.dim { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 380px; }
.flex1 { flex: 1; }
.sse { display: inline-flex; align-items: center; gap: 5px; }
.sse .dot { width: 6px; height: 6px; border-radius: 50%; }
.sse.open { color: #57ab5a; } .sse.open .dot { background: #57ab5a; }
.sse.connecting { color: #c69026; } .sse.connecting .dot { background: #c69026; }
.sse.closed { color: #e5534b; } .sse.closed .dot { background: #e5534b; }
</style>
