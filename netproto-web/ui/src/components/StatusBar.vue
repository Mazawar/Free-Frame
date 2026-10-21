<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { filteredNewestFirst, store } from '../store'

const ifaceLabel = computed(() => {
  const hit = store.interfaces.find(i => i.name === store.iface)
  return hit ? (hit.description || hit.name).slice(0, 48) : store.iface || ''
})

// 最近 5s 滑动窗口平均帧率(空闲归 0,突发不虚高);tick 驱动空闲时的衰减刷新
const tick = ref(0)
let timer: number | undefined
onMounted(() => { timer = window.setInterval(() => { tick.value++ }, 1000) })
onUnmounted(() => window.clearInterval(timer))

const rate = computed(() => {
  void tick.value
  const now = Date.now()
  const recent = store.packets.filter(p => now - p.ts < 5000).length
  return recent === 0 ? null : (recent / 5).toFixed(1)
})

const sseText = computed(() =>
  store.sse === 'open' ? '实时' : store.sse === 'connecting' ? '重连中' : '已断开')
</script>

<template>
  <footer class="bar">
    <span class="num" title="缓冲容量:后端 ring-size 配置(实际驻留还受 ring-bytes 字节预算约束)">缓冲 {{ store.config.ringSize }}</span>
    <span class="num" title="当前列表行数(过滤后)">显示 {{ filteredNewestFirst.length }}</span>
    <span v-if="rate" class="num">{{ rate }} 帧/秒</span>
    <span class="flex1"></span>
    <span v-if="store.captureRunning && ifaceLabel" class="dim">{{ ifaceLabel }}</span>
    <span v-else class="dim">未采集</span>
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
