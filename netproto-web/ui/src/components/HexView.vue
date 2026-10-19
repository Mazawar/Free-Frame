<script setup lang="ts">
import { computed } from 'vue'
import type { Packet } from '../types'
import { hexRows } from '../utils/format'

const props = defineProps<{ packet: Packet }>()

const rows = computed(() => hexRows(props.packet))
</script>

<template>
  <div class="hex mono">
    <div v-for="row in rows" :key="row.offset" class="row">
      <span class="off num">{{ row.offset.toString(16).padStart(4, '0') }}</span>
      <span class="cells">
        <span v-for="(c, i) in row.cells" :key="i"
              :style="c.color ? `color:${c.color}` : 'color:#6e7681'">{{ c.hex }}</span>
      </span>
      <span class="ascii">
        <span v-for="(c, i) in row.cells" :key="'a' + i"
              :style="c.color ? `color:${c.color}` : 'color:#484f58'">{{ c.ascii }}</span>
      </span>
    </div>
  </div>
</template>

<style scoped>
.hex {
  flex: 1; overflow: auto;
  font-size: 12px; line-height: 1.6;
  background: #0b0f14;
  border: 1px solid #1b222b;
  border-radius: 4px;
  padding: 6px 10px;
}
.row { display: flex; white-space: pre; }
.off { color: #484f58; width: 44px; flex-shrink: 0; }
.cells { width: 340px; flex-shrink: 0; }
.cells span { display: inline-block; width: 22px; }
.ascii { color: #484f58; }
</style>
