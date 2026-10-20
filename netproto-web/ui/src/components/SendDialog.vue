<script setup lang="ts">
import { computed, ref } from 'vue'
import { NButton, NInput, NModal, NSelect, NSpace, useMessage } from 'naive-ui'
import { SendHorizontal } from 'lucide-vue-next'
import { api } from '../api'
import { store } from '../store'

const message = useMessage()
const sending = ref(false)

const ifaceOptions = computed(() =>
  store.interfaces.map(i => ({ label: (i.description || i.name).slice(0, 64), value: i.name })))

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
    message.error('layers 必须是非空数组(外层 → 内层)')
    return
  }
  if (!store.iface) {
    message.error('请先选择网卡')
    return
  }
  sending.value = true
  try {
    const r = await api.send(store.iface, parsed.layers)
    message.success(`已注入 ${r.bytes} 字节`)
    store.sendOpen = false
  } catch (e) {
    message.error(`注入失败:${(e as Error).message}`, { duration: 5000 })
  } finally {
    sending.value = false
  }
}
</script>

<template>
  <n-modal v-model:show="store.sendOpen" preset="card" title="构造并发送"
           style="width: 620px">
    <n-space vertical :size="10">
      <n-space align="center" :size="8">
        <n-select v-model:value="store.iface" :options="ifaceOptions" filterable
                  placeholder="网卡" size="small" style="width: 270px" />
        <n-button size="small" quaternary @click="json = JSON.stringify(TEMPLATE, null, 2)">模板</n-button>
        <span class="flex1"></span>
        <n-button size="small" type="primary" :loading="sending" @click="send">
          <template #icon><SendHorizontal :size="13" /></template>
          注入
        </n-button>
      </n-space>
      <n-input v-model:value="json" type="textarea" :rows="14" spellcheck="false"
               class="code" />
      <p class="hint">
        层顺序外层 → 内层。etherType / protocol / 端口等选择子与长度字段自动补齐(显式值优先);
        byte[] 字段填 hex,Mac 填 aa:bb:cc:dd:ee:ff,Ip 填点分十进制。需管理员权限。
      </p>
    </n-space>
  </n-modal>
</template>

<style scoped>
.flex1 { flex: 1; }
.code { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.hint { color: #6e7681; font-size: 11px; margin: 0; line-height: 1.7; }
</style>
