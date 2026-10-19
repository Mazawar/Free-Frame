<script setup lang="ts">
import { onMounted } from 'vue'
import { NConfigProvider, NMessageProvider, darkTheme } from 'naive-ui'
import Toolbar from './components/Toolbar.vue'
import ProtocolSidebar from './components/ProtocolSidebar.vue'
import PacketTable from './components/PacketTable.vue'
import PacketDetail from './components/PacketDetail.vue'
import SendDialog from './components/SendDialog.vue'
import StatusBar from './components/StatusBar.vue'
import { api } from './api'
import { addPacket, connectStream, refreshInterfaces, refreshProtocols, refreshStatus, store } from './store'

onMounted(async () => {
  connectStream()
  await Promise.all([refreshProtocols(), refreshInterfaces(), refreshStatus()])
  if (store.captureRunning) {
    const recent = await api.packets(200)
    recent.reverse().forEach(addPacket)   // 旧→新补齐环形缓冲
  }
})
</script>

<template>
  <n-config-provider :theme="darkTheme">
    <n-message-provider>
      <div class="app-shell">
        <header class="toolbar-bar">
          <Toolbar />
        </header>
        <div class="mid">
          <aside class="side">
            <ProtocolSidebar />
          </aside>
          <main class="main">
            <PacketTable />
          </main>
        </div>
        <footer class="status-bar">
          <StatusBar />
        </footer>
      </div>
      <PacketDetail />
      <SendDialog />
    </n-message-provider>
  </n-config-provider>
</template>

<style scoped>
.app-shell { height: 100%; display: flex; flex-direction: column; }
.mid { flex: 1; display: flex; min-height: 0; }
.side { width: 232px; flex-shrink: 0; border-right: 1px solid rgba(51, 65, 85, .5); overflow-y: auto; padding: 10px; }
.main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
.toolbar-bar { border-bottom: 1px solid rgba(51, 65, 85, .5); padding: 8px 12px; display: flex; }
.status-bar { border-top: 1px solid rgba(51, 65, 85, .5); padding: 4px 12px; }
</style>
