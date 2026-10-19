<script setup lang="ts">
import { computed, ref } from 'vue'
import { NButton, NInput, NSelect, NSpace, NTag, useMessage } from 'naive-ui'
import { api } from '../api'
import { clearPackets, refreshStatus, store } from '../store'

const message = useMessage()
const switching = ref(false)

const ifaceOptions = computed(() =>
  store.interfaces.map(i => ({ label: (i.description || i.name).slice(0, 60), value: i.name })))

const sseTag = computed(() => {
  if (store.sse === 'open') return { type: 'success' as const, text: '推送已连接' }
  if (store.sse === 'connecting') return { type: 'warning' as const, text: '推送重连中' }
  return { type: 'error' as const, text: '推送已断开' }
})

async function start() {
  if (!store.iface) return
  switching.value = true
  try {
    await api.start(store.iface, store.bpf)
    await refreshStatus()
    message.success(`已开始采集:${store.iface}`)
  } catch (e) {
    message.error(`启动失败:${(e as Error).message}(混杂模式通常需要管理员权限)`)
  } finally {
    switching.value = false
  }
}

async function stop() {
  switching.value = true
  try {
    await api.stop()
    await refreshStatus()
    message.success('已停止采集')
  } catch (e) {
    message.error((e as Error).message)
  } finally {
    switching.value = false
  }
}
</script>

<template>
  <div class="toolbar">
    <span class="brand">netproto<small>annotation protocol stack</small></span>
    <n-space :size="8" align="center" :wrap="false" style="flex: 1; min-width: 0">
      <n-select v-model:value="store.iface" :options="ifaceOptions" filterable
                placeholder="网卡" size="small" style="width: 260px" />
      <n-input v-model:value="store.bpf" size="small" placeholder="BPF 过滤器(可空)"
               style="width: 200px" spellcheck="false" />
      <n-button size="small" type="primary" :disabled="store.captureRunning || !store.iface"
                :loading="switching" @click="start">开始采集</n-button>
      <n-button size="small" :disabled="!store.captureRunning" @click="stop">停止</n-button>
      <n-tag size="small" :type="store.captureRunning ? 'success' : 'default'"
             :bordered="false">{{ store.captureRunning ? '采集中' : '空闲' }}</n-tag>
      <n-tag size="small" :type="sseTag.type" :bordered="false">{{ sseTag.text }}</n-tag>
      <span style="flex: 1"></span>
      <n-button size="small" quaternary @click="store.sendOpen = true">发包</n-button>
      <n-button size="small" quaternary @click="clearPackets">清空</n-button>
    </n-space>
  </div>
</template>

<style scoped>
.toolbar { display: flex; align-items: center; width: 100%; min-width: 0; }
</style>
