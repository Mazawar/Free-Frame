import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 字段图 Web Component 独立构建:iife 单文件(内联 Vue + 组件样式),
// 产物落进 starter 的 netproto-ui 静态目录,用户程序 <script> 引入即可
// 用 <netproto-fieldmap> 渲染任意 Packet JSON。须在主构建之后跑(emptyOutDir:false)。
export default defineConfig({
  plugins: [vue({ features: { customElement: true } })],
  // lib iife 下 Vite 不注入 NODE_ENV 替换,Vue 运行时的 process.env.NODE_ENV 裸引用会直接炸
  define: { 'process.env.NODE_ENV': JSON.stringify('production') },
  build: {
    outDir: '../src/main/resources/netproto-ui',
    emptyOutDir: false,
    lib: {
      entry: 'src/fieldmap-element.ts',
      formats: ['iife'],
      name: 'NetProtoFieldMap',
      fileName: () => 'netproto-fieldmap.js',
    },
  },
})
