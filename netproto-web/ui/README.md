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
├── main.ts / App.vue        布局(顶栏/侧栏/主表/状态栏)+ 生命周期
├── store.ts                 单一 reactive store + SSE 连接管理
├── api.ts                   REST 封装
├── types.ts                 与后端 JSON 视图对应的类型
├── utils/format.ts          概要行/hex dump(按层着色)/时间格式化
└── components/
    ├── Toolbar.vue          网卡/BPF/启停/推送状态/发包入口
    ├── ProtocolSidebar.vue  协议过滤(勾选 + 命中计数 + 内置徽标)
    ├── PacketTable.vue      虚拟滚动帧表格(新→旧,点击开详情)
    ├── PacketDetail.vue     右侧抽屉:层级手风琴 + 字段表 + hex
    ├── HexView.vue          hex dump(层色图例 + 高亮)
    ├── SendDialog.vue       原始以太网注入(模板 + 校验)
    └── StatusBar.vue        缓冲/过滤/速率/网卡
```
