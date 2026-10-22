import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 构建产物直接落进 starter 的 static(打 jar 即带页面,无需 Node 即可构建 Java 侧)
export default defineConfig({
  plugins: [vue()],
  // base './' 使产物资源用相对路径:页面挂在任意前缀(/netproto/ 等)都能加载
  base: './',
  build: {
    outDir: '../src/main/resources/netproto-ui',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8848',
    },
  },
})
