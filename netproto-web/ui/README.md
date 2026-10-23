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
    ├── DetailPane.vue       底部分析面板:左侧嵌套协议树 + 右侧字节,点字段/点字节双向联动高亮
    ├── FieldMapView.vue     字段图:字段分段 + 位框分组释义(纯数据驱动,可独立嵌入/Web Component)
    ├── HexView.vue          hex dump(层色 + 选中字段高亮 + 点击回调)
    ├── SendDialog.vue       构造并发送(模板/校验/自动接线说明)
    └── StatusBar.vue        缓冲/显示/速率/网卡/推送状态
```

视觉:GitHub Dark 系配色(中性深底、单一强调色、低饱和层色)、UI 文本用系统字体栈、
数据(时间/地址/长度/hex)用等宽 + tabular-nums,信息密度优先。

## 字段图(字段分段 + 位框分组释义)

详情面板右上角的「字段图」按钮打开整帧视图:每个字段一个分段(段间留缝即
字段隔断,换层加大缝距)——段内为字节瓦片行(hex + 偏移,层色),亚字节字段
在瓦片下方按归属字段分组铺位框,组名行内联「字段名 + 解码值」(位字段不单独
堆名值块;组间留缝、可换行,分组把分段宽度撑开);字节对齐字段在段底出名值行;
LIST 字段名值行带 ▸ 可展开元素卡(元素字节位置 + 内部字段名值,悬停高亮其
瓦片;元素卡横向流动自动换行,不竖撑高度);字节范围重叠的位字段合并为一段(位框分组共享);LIST 元素级区间与被
更深层字段覆盖的 payload 不进图(字节归最深字段)。全部行可换行,无横向滚动。
悬停位框组/名值 ↔ 瓦片互亮,点击复制完整值,点击瓦片钉住所属字段。

`FieldMapView.vue` 只依赖 `Packet` JSON(`props: { packet, protocols? }`),
不依赖 naive-ui / store,两种复用方式:

1. **Vue 组件直接嵌入**:拷贝 `FieldMapView.vue` + `utils/format.ts` + `types.ts`
   (或直接 import),`<FieldMapView :packet="packetJson" :protocols="metas" />`。

2. **Web Component(任意网页/框架)**:`npm run build` 的第二段产出
   `src/main/resources/netproto-ui/netproto-fieldmap.js`(iife 单文件,内联 Vue,
   gzip 约 44 KB),starter 自动挂载在 `/netproto/netproto-fieldmap.js`:

   ```html
   <script src="/netproto/netproto-fieldmap.js"></script>
   <netproto-fieldmap></netproto-fieldmap>
   <script>
     // packet = /api/netproto/sessions/{id}/packet/{seq} 的 JSON
     document.querySelector('netproto-fieldmap').packet = packet   // 属性传对象
     // 或 attribute 传 JSON 串:<netproto-fieldmap packet='{"seq":1,...}'>
   </script>
   ```
