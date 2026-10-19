<script setup lang="ts">
import { computed, ref } from 'vue'
import { NButton, NInput, NSelect, NTooltip, useMessage } from 'naive-ui'
import { Play, Square, SendHorizontal, Trash2 } from 'lucide-vue-next'
import { api } from '../api'
import { clearPackets, refreshStatus, store } from '../store'

const message = useMessage()
const switching = ref(false)

const ifaceOptions = computed(() =>
  store.interfaces.map(i => ({ label: (i.description || i.name).slice(0, 64), value: i.name })))

async function start() {
  if (!store.iface) return
  switching.value = true
  try {
    await api.start(store.iface, store.bpf)
    await refreshStatus()
  } catch (e) {
    message.error(`启动失败:${(e as Error).message}`, { keepAliveOnHover: true, duration: 5000 })
  } finally {
    switching.value = false
  }
}

async function stop() {
  switching.value = true
  try {
    await api.stop()
    await refreshStatus()
  } catch (e) {
    message.error((e as Error).message)
  } finally {
    switching.value = false
  }
}
</script>

<template>
  <header class="bar">
    <div class="brand">
      <span class="mark"></span>
      <span class="name">netproto</span>
    </div>

    <n-select v-model:value="store.iface" :options="ifaceOptions" filterable
              placeholder="选择网卡" size="small" class="iface" />
    <n-input v-model:value="store.bpf" size="small" class="bpf"
             placeholder="BPF 过滤" spellcheck="false" />

    <n-button size="small" type="primary" :disabled="store.captureRunning || !store.iface"
              :loading="switching" @click="start">
      <template #icon><Play :size="13" /></template>
      采集
    </n-button>
    <n-button size="small" :disabled="!store.captureRunning" @click="stop">
      <template #icon><Square :size="11" /></template>
    </n-button>

    <span class="capture-state" :class="{ on: store.captureRunning }">
      <span class="dot"></span>{{ store.captureRunning ? '采集中' : '空闲' }}
    </span>

    <span class="flex1"></span>

    <n-button size="small" secondary @click="store.sendOpen = true">
      <template #icon><SendHorizontal :size="13" /></template>
      发包
    </n-button>
    <n-tooltip trigger="hover">
      <template #trigger>
        <n-button size="small" quaternary @click="clearPackets">
          <template #icon><Trash2 :size="13" /></template>
        </n-button>
      </template>
      清空列表
    </n-tooltip>
  </header>
</template>

<style scoped>
.bar {
  height: 44px; flex-shrink: 0;
  display: flex; align-items: center; gap: 8px;
  padding: 0 12px;
  background: #12171e;
  border-bottom: 1px solid #21262d;
}
.brand { display: flex; align-items: center; gap: 7px; margin-right: 8px; user-select: none; }
.mark { width: 8px; height: 8px; border-radius: 2px; background: #539bf5; }
.name { font-weight: 600; font-size: 13px; letter-spacing: .2px; color: #e6edf3; }
.iface { width: 250px; }
.bpf { width: 170px; }
.capture-state {
  display: inline-flex; align-items: center; gap: 5px;
  margin-left: 4px; font-size: 12px; color: #8b949e; white-space: nowrap;
}
.capture-state .dot { width: 6px; height: 6px; border-radius: 50%; background: #6e7681; }
.capture-state.on { color: #57ab5a; }
.capture-state.on .dot { background: #57ab5a; }
.flex1 { flex: 1; }
</style>
