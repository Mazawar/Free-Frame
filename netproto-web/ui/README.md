# netproto-ui — 观测页面前端

Vue 3 + Vite + Naive UI(TypeScript)。构建产物直接输出到 starter 的
`../src/main/resources/static`(已提交进仓库,Java 侧构建不需要 Node)。

## 开发

```bash
npm install
npm run dev      # http://localhost:5173,/api 代理到 localhost:8848 的后端
```

## 构建与发布

```bash
npm run build    # 输出到 ../src/main/resources/static(emptyOutDir 覆盖旧文件)
# 重新打包后端即可看到新页面:
cd ../../.. && ./mvnw -q package -DskipTests -pl netproto-demo
```

## 结构

```
src/
├── main.ts / App.vue        布局(工具栏/侧栏/帧表/底部分析面板/状态栏)+ 主题令牌 + 生命周期
├── store.ts                 单一 reactive store + SSE 连接管理
├── api.ts                   REST 封装
├── types.ts                 与后端 JSON 视图对应的类型
├── utils/format.ts          端点提取/信息列(Wireshark 风格)/hex dump(按层着色)/时间格式化
└── components/
    ├── Toolbar.vue          网卡/BPF/采集启停/状态点/发包入口(图标化)
    ├── ProtocolSidebar.vue  协议过滤(内置栈与业务协议分组、命中计数)
    ├── PacketTable.vue      Wireshark 式列(No./时间/源/目的/协议/长度/信息)+ 虚拟滚动
    ├── DetailPane.vue       底部分析面板:协议树(层级字段表)/字节(hex)两个 tab
    ├── HexView.vue          hex dump(层色高亮 + 偏移 + ASCII)
    ├── SendDialog.vue       构造并发送(模板/校验/自动接线说明)
    └── StatusBar.vue        缓冲/显示/速率/网卡/推送状态
```

视觉:GitHub Dark 系配色(中性深底、单一强调色、低饱和层色)、UI 文本用系统字体栈、
数据(时间/地址/长度/hex)用等宽 + tabular-nums,信息密度优先。
