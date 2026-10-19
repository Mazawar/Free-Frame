<script setup lang="ts">
import { computed, ref } from 'vue'
import { NButton, NInput, NModal, NSelect, NSpace, useMessage } from 'naive-ui'
import { api } from '../api'
import { store } from '../store'

const message = useMessage()
const sending = ref(false)

const ifaceOptions = computed(() =>
  store.interfaces.map(i => ({ label: (i.description || i.name).slice(0, 60), value: i.name })))

const TEMPLATE = {
  layers: [
    { protocol: 'ethernet', fields: { dstMac: 'ff:ff:ff:ff:ff:ff', srcMac: '02:00:00:00:00:01' } },
    { protocol: 'ipv4', fields: { sourceIp: '192.168.1.100', destinationIp: '255.255.255.255', ttl: 64 } },
    { protocol: 'udp', fields: { srcPort: 44444, dstPort: 9999 } },
    { protocol: 'my-app', fields: { version: 1, type: 2, sequenceId: 1, payloadData: '68656c6c6f' } },
  ],
}

const json = ref(JSON.stringify(TEMPLATE, null, 2))

async function send() {
  let parsed: { layers?: unknown[] }
  try {
    parsed = JSON.parse(json.value)
  } catch (e) {
    message.error(`JSON 无效:${(e as Error).message}`)
    return
  }
  if (!Array.isArray(parsed.layers) || parsed.layers.length === 0) {
    message.error('layers 必须是非空数组(外层→内层)')
    return
  }
  if (!store.iface) {
    message.error('请先选择网卡')
    return
  }
  sending.value = true
  try {
    const r = await api.send(store.iface, parsed.layers)
    message.success(`已注入 ${r.bytes} 字节(选择子/长度已自动补齐)`)
    store.sendOpen = false
  } catch (e) {
    message.error(`注入失败:${(e as Error).message}(需要管理员权限)`)
  } finally {
    sending.value = false
  }
}
</script>

<template>
  <n-modal v-model:show="store.sendOpen" preset="card" title="发包 · 原始以太网注入"
           style="width: 640px">
    <n-space vertical :size="10">
      <n-space align="center" :size="8">
        <n-select v-model:value="store.iface" :options="ifaceOptions" filterable
                  placeholder="网卡" size="small" style="width: 280px" />
        <n-button size="small" @click="json = JSON.stringify(TEMPLATE, null, 2)">填充模板</n-button>
        <n-button size="small" type="primary" :loading="sending" @click="send">注入</n-button>
      </n-space>
      <n-input v-model:value="json" type="textarea" :rows="14" spellcheck="false"
               style="font-family: ui-monospace, Consolas, monospace" />
      <p class="hint">
        layers 外层→内层;etherType/protocol/端口等选择子与长度字段自动补齐(显式值优先)。
        byte[] 字段给 hex;Mac 给 "aa:bb:cc:dd:ee:ff";Ip 给点分十进制。
        需管理员权限;TCP 为无握手 raw 注入,仅演示用。
      </p>
    </n-space>
  </n-modal>
</template>

<style scoped>
.hint { color: #64748b; font-size: 11px; margin: 0; line-height: 1.7; }
</style>
