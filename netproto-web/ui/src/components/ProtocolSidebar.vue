<script setup lang="ts">
import { computed } from 'vue'
import { NCheckbox } from 'naive-ui'
import { protoCounts, store } from '../store'

interface Row { id: string; name: string; builtin: boolean; count: number }
interface Group { label: string; rows: Row[] }

const groups = computed<Group[]>(() => {
  const builtin: Row[] = []
  const custom: Row[] = []
  const islands: Row[] = []
  for (const p of store.protocols) {
    if (p.category === 'element') continue   // LIST/TLV 元素实体:不可过滤,不展示
    const row = { id: p.id, name: p.name, builtin: p.builtin, count: protoCounts.value.get(p.id) ?? 0 }
    if (p.category === 'island') islands.push(row)
    else (p.builtin ? builtin : custom).push(row)
  }
  const out: Group[] = []
  if (builtin.length) out.push({ label: '内置协议栈', rows: builtin })
  if (custom.length) out.push({ label: '业务协议', rows: custom })
  if (islands.length) out.push({ label: '独立协议 · 不在链路分派', rows: islands })
  return out
})

function selectAll() {
  store.protocols.forEach(p => {
    if (p.category !== 'element') store.enabled.add(p.id)
  })
}

function toggle(id: string, v: boolean) {
  v ? store.enabled.add(id) : store.enabled.delete(id)
}
</script>

<template>
  <aside class="side">
    <div class="head">
      <span>协议</span>
      <button class="mini" @click="selectAll">全选</button>
      <button class="mini" @click="store.enabled.clear()">清空</button>
    </div>
    <div class="scroll">
      <section v-for="g in groups" :key="g.label">
        <div class="group-label">{{ g.label }}</div>
        <label v-for="row in g.rows" :key="row.id" class="row" :title="row.id">
          <n-checkbox size="small"
                      :checked="store.enabled.has(row.id)"
                      :on-update:checked="(v: boolean) => toggle(row.id, v)" />
          <span class="pname">{{ row.name }}</span>
          <span class="pcount num" :class="{ zero: row.count === 0 }">{{ row.count }}</span>
        </label>
      </section>
    </div>
    <div class="foot">只解析已注册的协议</div>
  </aside>
</template>

<style scoped>
.side {
  width: 208px; flex-shrink: 0;
  display: flex; flex-direction: column;
  background: #0f141a;
  border-right: 1px solid #21262d;
}
.head {
  display: flex; align-items: center; gap: 8px;
  padding: 9px 12px 7px;
  font-size: 11px; font-weight: 600; color: #8b949e;
  text-transform: uppercase; letter-spacing: .5px;
}
.mini {
  margin-left: auto; background: none; border: none; cursor: pointer;
  font-size: 11px; color: #6e7681; padding: 0 2px;
}
.mini:hover { color: #c9d1d9; }
.mini + .mini { margin-left: 0; }
.scroll { flex: 1; overflow-y: auto; padding: 0 6px 8px; }
.group-label {
  font-size: 10px; color: #6e7681; letter-spacing: .5px;
  padding: 10px 6px 4px; user-select: none;
}
.row {
  display: flex; align-items: center; gap: 7px;
  padding: 2px 6px; border-radius: 4px; cursor: pointer;
}
.row:hover { background: rgba(177, 186, 196, .06); }
.pname {
  font-size: 12px; color: #c9d1d9;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.pcount { margin-left: auto; font-size: 11px; color: #8b949e; }
.pcount.zero { color: #484f58; }
.foot {
  padding: 7px 12px; font-size: 11px; color: #484f58;
  border-top: 1px solid #21262d;
}
</style>
