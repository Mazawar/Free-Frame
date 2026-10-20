<script setup lang="ts">
import { computed } from 'vue'
import type { Packet } from '../types'
import { hexRows } from '../utils/format'

const props = defineProps<{ packet: Packet; highlight?: [number, number] | null; layerHl?: [number, number] | null }>()
const emit = defineEmits<{ (e: 'byte-click', idx: number): void }>()

const rows = computed(() => hexRows(props.packet))

function inHighlight(idx: number): boolean {
  const h = props.highlight
  return h != null && idx >= h[0] && idx < h[1]
}

function inLayer(idx: number): boolean {
  const h = props.layerHl
  return h != null && idx >= h[0] && idx < h[1]
}
</script>

<template>
  <div class="hex mono">
    <div v-for="row in rows" :key="row.offset" class="hrow">
      <span class="off num">{{ row.offset.toString(16).padStart(4, '0') }}</span>
      <span class="cells">
        <span v-for="(c, i) in row.cells" :key="i"
              class="cell"
              :class="{ hl: inHighlight(row.offset + i), lhl: !inHighlight(row.offset + i) && inLayer(row.offset + i), g8: i === 8 }"
              :style="inHighlight(row.offset + i) || inLayer(row.offset + i) ? '' : c.color ? `color:${c.color}` : 'color:#6e7681'"
              :data-byte="row.offset + i"
              :title="`0x${(row.offset + i).toString(16).padStart(4, '0')}`"
              @click="emit('byte-click', row.offset + i)">{{ c.hex }}</span>
      </span>
      <span class="ascii">
        <span v-for="(c, i) in row.cells" :key="'a' + i"
              class="cell"
              :class="{ hl: inHighlight(row.offset + i), lhl: !inHighlight(row.offset + i) && inLayer(row.offset + i) }"
              :style="inHighlight(row.offset + i) || inLayer(row.offset + i) ? '' : c.color ? `color:${c.color}` : 'color:#484f58'"
              @click="emit('byte-click', row.offset + i)">{{ c.ascii }}</span>
      </span>
    </div>
  </div>
</template>

<style scoped>
.hex {
  flex: 1; overflow: auto;
  font-size: 12px; line-height: 1.65;
  background: #0b0f14;
  border: 1px solid #1b222b;
  border-radius: 4px;
  padding: 6px 10px;
}
.hrow { display: flex; white-space: pre; }
.off { color: #484f58; width: 44px; flex-shrink: 0; user-select: none; }
.cells { width: 350px; flex-shrink: 0; }
.cell {
  display: inline-block; width: 21px;
  text-align: center;
  cursor: pointer;
  border-radius: 2px;
}
/* 第 9 字节起为第二组:左移出 8 字节分组间隔 */
.cell.g8 { margin-left: 14px; }
.cell:hover { background: rgba(177, 186, 196, .14); }
/* 双层高亮:所属协议层=浅蓝底,选中字段=实心蓝 */
.cell.lhl { background: rgba(31, 111, 235, .22); border-radius: 0; }
.cell.hl {
  background: #1f6feb;
  color: #fff !important;
  font-weight: 700;
  border-radius: 0;
}
.ascii { color: #484f58; padding-left: 18px; border-left: 1px solid #1b222b; }
.ascii .cell { width: auto; padding: 0 1px; }
</style>
