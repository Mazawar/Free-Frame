<script setup lang="ts">
import { computed, ref } from 'vue'
import { NButton, NInput, NSelect, NTooltip, useMessage } from 'naive-ui'
import { Download, Play, SendHorizontal, Square, Trash2, Upload } from 'lucide-vue-next'
import { api } from '../api'
import { adoptSession, clearPackets, connectStream, disconnectStream, refreshStatus, store } from '../store'

const message = useMessage()
const switching = ref(false)
const importing = ref(false)
const fileInput = ref<HTMLInputElement | null>(null)

const ifaceOptions = computed(() =>
  store.interfaces.map(i => ({ label: (i.description || i.name).slice(0, 64), value: i.name })))

/** 采集 = 本页新会话:释放旧会话(腾名额)→ 创建并启动 → 订阅它的流。序号从 1 重新计数。 */
async function start() {
  if (!store.iface) return
  switching.value = true
  try {
    if (store.sessionId) {
      // 先断流再删:正常路径不吃 session-closed 兜底;删失败(已不在)不阻塞新会话
      disconnectStream()
      try { await api.sessionDelete(store.sessionId) } catch { /* 会话已不存在 */ }
      adoptSession('')
    }
    const s = await api.sessionCreate(store.iface, store.bpf)
    adoptSession(String(s.sessionId))
    clearPackets()
    await refreshStatus()
    connectStream()
  } catch (e) {
    message.error(`启动失败:${(e as Error).message}`, { keepAliveOnHover: true, duration: 5000 })
    await refreshStatus()
  } finally {
    switching.value = false
  }
}

/** 停止 = 本页会话停止采集;会话与缓冲保留(数据继续可看,刷新页面可恢复)。 */
async function stop() {
  if (!store.sessionId) return
  switching.value = true
  try {
    await api.sessionStop(store.sessionId)
    await refreshStatus()
  } catch (e) {
    message.error((e as Error).message)
  } finally {
    switching.value = false
  }
}

/** 导出本页会话的环形缓冲:Content-Disposition 触发浏览器下载 .pcap(Wireshark 可直接打开)。 */
function exportPcap() {
  if (!store.sessionId) return
  window.location.href = api.sessionExportUrl(store.sessionId)
}

/** 导入 pcap:替换本页会话列表(要求会话已停止;无会话时按钮禁用)。SSE 会把全部帧送回。 */
async function onImportFile(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''   // 允许再次选择同一文件
  if (!file || !store.sessionId) return
  importing.value = true
  try {
    const r = await api.sessionImport(store.sessionId, file)
    clearPackets()
    message.success(`已导入 ${r.imported} 帧(替换当前列表)`)
  } catch (err) {
    message.error(`导入失败:${(err as Error).message}`, { keepAliveOnHover: true, duration: 5000 })
  } finally {
    importing.value = false
  }
}
</script>

<template>
  <!-- 三区布局:品牌 | 采集组(来源→过滤→启停→状态)| 工具组(动作图标)。
       新功能按区插入,组间竖分隔线隔开。 -->
  <header class="bar">
    <div class="zone left">
      <div class="brand" title="Netproto — 注解驱动的协议栈观测台">
        <!-- 与 favicon.svg 同一设计(浏览器标签页图标),保证页内/标签页一致 -->
        <svg class="mark" viewBox="0 0 16 16" aria-hidden="true">
          <rect x="0" y="0" width="16" height="16" rx="3.5" fill="#0d1117"/>
          <rect x="3" y="2.6" width="10" height="3" rx="1.5" fill="#539bf5"/>
          <rect x="3" y="6.5" width="10" height="3" rx="1.5" fill="#57ab5a"/>
          <rect x="3" y="10.4" width="6.5" height="3" rx="1.5" fill="#c69026"/>
          <circle cx="11.6" cy="11.9" r="1.4" fill="#e6edf3"/>
        </svg>
        <span class="name">Netproto</span>
      </div>
    </div>

    <div class="zone grow">
      <!-- 采集组 -->
      <div class="group">
        <n-select v-model:value="store.iface" :options="ifaceOptions" filterable
                  :disabled="store.captureRunning"
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
        <span class="capture-state" :class="{ on: store.captureRunning }"
              :title="store.captureRunning ? '采集中' : '空闲'">
          <span class="dot"></span>{{ store.captureRunning ? '采集中' : '空闲' }}
        </span>
      </div>
    </div>

    <div class="zone right">
      <!-- 工具组:后续新功能(设置/显示选项等)在此区追加 -->
      <div class="group">
        <n-button size="small" secondary @click="store.sendOpen = true">
          <template #icon><SendHorizontal :size="13" /></template>
          发包
        </n-button>

        <span class="vdiv"></span>

        <n-tooltip trigger="hover">
          <template #trigger>
            <n-button size="small" quaternary :disabled="store.captured === 0" @click="exportPcap">
              <template #icon><Download :size="13" /></template>
            </n-button>
          </template>
          导出 .pcap(Wireshark 可打开)
        </n-tooltip>
        <n-tooltip trigger="hover">
          <template #trigger>
            <n-button size="small" quaternary :loading="importing"
                      :disabled="!store.sessionId || store.captureRunning" @click="fileInput?.click()">
              <template #icon><Upload :size="13" /></template>
            </n-button>
          </template>
          导入 .pcap(替换当前列表;需本页已有会话且已停止)
        </n-tooltip>
        <input ref="fileInput" type="file" accept=".pcap" hidden @change="onImportFile" />
        <n-tooltip trigger="hover">
          <template #trigger>
            <n-button size="small" quaternary @click="clearPackets">
              <template #icon><Trash2 :size="13" /></template>
            </n-button>
          </template>
          清空列表
        </n-tooltip>
      </div>
    </div>
  </header>
</template>

<style scoped>
.bar {
  height: 44px; flex-shrink: 0;
  display: flex; align-items: center; gap: 10px;
  padding: 0 12px;
  background: #12171e;
  border-bottom: 1px solid #21262d;
  user-select: none;
}
.zone { display: flex; align-items: center; min-width: 0; }
.zone.left { flex-shrink: 0; }
.zone.grow { flex: 1; }
.zone.right { flex-shrink: 0; }

/* 功能分组:轻描淡写的容器,新组按 .group 插入即可获得一致观感 */
.group { display: flex; align-items: center; gap: 8px; }
.vdiv { width: 1px; height: 18px; background: #2d333b; margin: 0 4px; flex-shrink: 0; }

.brand { display: flex; align-items: center; gap: 7px; margin-right: 2px; }
.mark { width: 16px; height: 16px; display: block; }
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
</style>
