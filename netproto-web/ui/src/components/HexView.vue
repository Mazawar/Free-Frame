<script setup lang="ts">
import { computed } from 'vue'
import type { Packet } from '../types'
import { hexRows } from '../utils/format'

const props = defineProps<{ packet: Packet; highlight?: [number, number] | null }>()
const emit = defineEmits<{ (e: 'byte-click', idx: number): void }>()

const rows = computed(() => hexRows(props.packet))

function inHighlight(idx: number): boolean {
  const h = props.highlight
  return h != null && idx >= h[0] && idx < h[1]
}
</script>

<template>
  <div class="hex mono">
    <div v-for="row in rows" :key="row.offset" class="hrow">
      <span class="off num">{{ row.offset.toString(16).padStart(4, '0') }}</span>
      <span class="cells">
        <span v-for="(c, i) in row.cells" :key="i"
              class="cell" :class="{ hl: inHighlight(row.offset + i) }"
              :style="inHighlight(row.offset + i) ? '' : c.color ? `color:${c.color}` : 'color:#6e7681'"
              :data-byte="row.offset + i"
              :title="`0x${(row.offset + i).toString(16).padStart(4, '0')}`"
              @click="emit('byte-click', row.offset + i)">{{ c.hex }}</span>
      </span>
      <span class="ascii">
        <span v-for="(c, i) in row.cells" :key="'a' + i"
              class="cell" :class="{ hl: inHighlight(row.offset + i) }"
              :style="inHighlight(row.offset + i) ? '' : c.color ? `color:${c.color}` : 'color:#484f58'"
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
.cells { width: 328px; flex-shrink: 0; }
.cell { display: inline-block; width: 20px; cursor: pointer; border-radius: 2px; }
.cell:hover { background: rgba(177, 186, 196, .14); }
.cell.hl { background: #1f6feb; color: #fff !important; }
.ascii { color: #484f58; }
</style>
