import { defineCustomElement } from 'vue'
import FieldMapView from './components/FieldMapView.vue'

/**
 * 字段图 Web Component 入口:<netproto-fieldmap>。
 * 用法(任意网页/框架,iife 单文件、零运行时依赖):
 *   <script src="netproto-fieldmap.js"></script>
 *   <netproto-fieldmap></netproto-fieldmap>
 *   <script>document.querySelector('netproto-fieldmap').packet = packetJson</script>
 * packet 为 /api/netproto/sessions/{id}/packet/{seq} 的 JSON(属性传对象,
 * 或 attribute 传 JSON 串);protocols 可选(改善字段标签)。
 */
customElements.define('netproto-fieldmap', defineCustomElement(FieldMapView))
