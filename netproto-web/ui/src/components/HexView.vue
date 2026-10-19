<script setup lang="ts">
import { computed } from 'vue'
import type { Packet } from '../types'
import { hexRows } from '../utils/format'

const props = defineProps<{ packet: Packet }>()

const rows = computed(() => hexRows(props.packet))
</script>

<template>
  <div class="hex">
    <div v-for="row in rows" :key="row.offset">
      <span class="hex-off">{{ row.offset.toString(16).padStart(4, '0') }}</span>
      <span class="hex-off">  </span>
      <span v-for="(c, i) in row.cells" :key="i" :style="c.color ? `color:${c.color}` : 'color:#94a3b8'">{{ c.hex }}&nbsp;</span>
      <span class="hex-off"> | </span>
      <span v-for="(c, i) in row.cells" :key="'a' + i" :style="c.color ? `color:${c.color}` : 'color:#64748b'">{{ c.ascii }}</span>
    </div>
  </div>
</template>
