<script setup lang="ts">
import { onMounted } from 'vue'
import { NConfigProvider, NMessageProvider, NGlobalStyle, darkTheme, type GlobalThemeOverrides } from 'naive-ui'
import Toolbar from './components/Toolbar.vue'
import ProtocolSidebar from './components/ProtocolSidebar.vue'
import PacketTable from './components/PacketTable.vue'
import DetailPane from './components/DetailPane.vue'
import SendDialog from './components/SendDialog.vue'
import StatusBar from './components/StatusBar.vue'
import { api } from './api'
import { addPackets, connectStream, refreshInterfaces, refreshProtocols, restoreSession, store } from './store'

// 克制的开发者工具配色:中性深底 + 单一强调色
const themeOverrides: GlobalThemeOverrides = {
  common: {
    primaryColor: '#539bf5',
    primaryColorHover: '#6cb2ff',
    primaryColorPressed: '#4284d4',
    primaryColorSuppl: '#539bf5',
    infoColor: '#539bf5',
    successColor: '#57ab5a',
    warningColor: '#c69026',
    errorColor: '#e5534b',
    bodyColor: '#0d1117',
    popoverColor: '#1c2128',
    cardColor: '#161b22',
    modalColor: '#161b22',
    tableColor: '#0d1117',
    tableHeaderColor: '#12171e',
    inputColor: '#0d1117',
    actionColor: '#12171e',
    hoverColor: 'rgba(177, 186, 196, 0.07)',
    borderColor: '#2d333b',
    dividerColor: '#21262d',
    textColorBase: '#e6edf3',
    textColor1: '#e6edf3',
    textColor2: '#c9d1d9',
    textColor3: '#8b949e',
    placeholderColor: '#6e7681',
    colorScrollbar: '#2d333b',
    colorScrollbarHover: '#444c56',
    borderRadius: '4px',
    borderRadiusSmall: '3px',
    fontSize: '13px',
    fontSizeMedium: '13px',
    fontSizeSmall: '12px',
    fontSizeTiny: '11px',
    heightMedium: '30px',
    heightSmall: '26px',
  },
  Card: { paddingMedium: '12px 16px' },
  DataTable: {
    thPaddingSmall: '5px 10px',
    tdPaddingSmall: '3px 10px',
    thColor: '#12171e',
    tdColor: '#0d1117',
    tdColorHover: 'rgba(177, 186, 196, 0.06)',
    borderColor: '#1b222b',
    fontSizeSmall: '12px',
    thTextColor: '#8b949e',
    thFontWeight: '500',
  },
  Select: { peers: { InternalSelection: { color: '#0d1117' } } },
  Input: { color: '#0d1117' },
}

onMounted(async () => {
  // 本页专属会话恢复(sessionStorage 隔离):上次未删的会话接回,数据与流都只属于本页
  await restoreSession()
  connectStream()   // 无会话时内部直接置 closed(状态栏显示"无会话")
  // 配置先行:缓冲上限等显示参数以它为准,恢复裁剪依赖 maxPackets
  try {
    const c = await api.config()
    store.config = {
      ringSize: Number(c.ringSize) || 100_000,
      ringBytes: Number(c.ringBytes) || 0,
      snaplen: Number(c.snaplen) || 0,
      rootProtocol: String(c.rootProtocol ?? ''),
    }
  } catch { /* 服务未起:用兜底默认 */ }
  await Promise.all([refreshProtocols(), refreshInterfaces()])
  // 恢复本页会话环形缓冲里的最近帧(服务端按环容量截断,这里给足上限;单批一次进 store)
  try {
    if (store.sessionLive) {
      const recent = await api.sessionPackets(store.sessionId, store.config.ringSize || 100_000)
      addPackets(recent.reverse())
    }
  } catch { /* 会话刚被回收:列表为空 */ } finally {
    store.bootstrapped = true
  }
})

// 右键菜单只在输入框内可用(便于粘贴),其余区域禁用
function onContextMenu(e: MouseEvent) {
  const t = e.target as HTMLElement | null
  if (t?.closest('input, textarea')) return
  e.preventDefault()
}
</script>

<template>
  <n-config-provider :theme="darkTheme" :theme-overrides="themeOverrides">
    <n-global-style />
    <n-message-provider>
      <div class="app" @contextmenu="onContextMenu">
        <Toolbar />
        <div class="body">
          <ProtocolSidebar />
          <div class="center">
            <PacketTable />
            <DetailPane v-if="store.selected" />
          </div>
        </div>
        <StatusBar />
      </div>
      <SendDialog />
    </n-message-provider>
  </n-config-provider>
</template>

<style scoped>
.app { height: 100dvh; display: flex; flex-direction: column; }
.body { flex: 1; display: flex; min-height: 0; }
.center { flex: 1; min-width: 0; display: flex; flex-direction: column; }
</style>
