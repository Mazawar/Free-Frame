<script setup lang="ts">
import { computed, ref } from 'vue'
import { NCheckbox } from 'naive-ui'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'
import { protoCounts, store } from '../store'
import type { ProtocolMeta } from '../types'

interface Row { id: string; name: string; builtin: boolean; count: number }
interface GroupBlock { name: string; rows: Row[]; count: number; checked: boolean; indeterminate: boolean }
interface Section { label: string; rows: Row[]; groups: GroupBlock[] }

const expandedGroups = ref(new Set<string>())

function toggleGroup(name: string) {
  const s = new Set(expandedGroups.value)
  s.has(name) ? s.delete(name) : s.add(name)
  expandedGroups.value = s
}

function toRow(p: ProtocolMeta): Row {
  return { id: p.id, name: p.name, builtin: p.builtin, count: protoCounts.value.get(p.id) ?? 0 }
}

const sections = computed<Section[]>(() => {
  const buckets: Record<string, ProtocolMeta[]> = { stackBuiltin: [], stackCustom: [], island: [] }
  for (const p of store.protocols) {
    if (p.category === 'element') continue   // LIST/TLV 元素实体:不可过滤,不展示
    if (p.category === 'island') buckets.island.push(p)
    else buckets[p.builtin ? 'stackBuiltin' : 'stackCustom'].push(p)
  }
  const build = (list: ProtocolMeta[]): Pick<Section, 'rows' | 'groups'> => {
    const plain: Row[] = []
    const byGroup = new Map<string, ProtocolMeta[]>()
    for (const p of list) {
      if (p.group) {
        if (!byGroup.has(p.group)) byGroup.set(p.group, [])
        byGroup.get(p.group)!.push(p)
      } else {
        plain.push(toRow(p))
      }
    }
    const groups: GroupBlock[] = [...byGroup.entries()].map(([name, ps]) => {
      const rows = ps.map(toRow)
      const enabledCount = rows.filter(r => store.enabled.has(r.id)).length
      return {
        name, rows,
        count: rows.reduce((a, r) => a + r.count, 0),
        checked: rows.length > 0 && enabledCount === rows.length,
        indeterminate: enabledCount > 0 && enabledCount < rows.length,
      }
    })
    return { rows: plain, groups }
  }
  const out: Section[] = []
  if (buckets.stackBuiltin.length) out.push({ label: '内置协议栈', ...build(buckets.stackBuiltin) })
  if (buckets.stackCustom.length) out.push({ label: '业务协议', ...build(buckets.stackCustom) })
  if (buckets.island.length) out.push({ label: '独立协议 · 不在链路分派', ...build(buckets.island) })
  return out
})

function toggle(id: string, v: boolean) {
  v ? store.enabled.add(id) : store.enabled.delete(id)
}

/** 组级勾选:全选/取消组内全部。 */
function toggleGroupCheck(g: GroupBlock, v: boolean) {
  for (const r of g.rows) {
    v ? store.enabled.add(r.id) : store.enabled.delete(r.id)
  }
}

function selectAll() {
  store.protocols.forEach(p => {
    if (p.category !== 'element') store.enabled.add(p.id)
  })
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
      <section v-for="s in sections" :key="s.label">
        <div class="group-label">{{ s.label }}</div>

        <!-- 无组协议 -->
        <label v-for="row in s.rows" :key="row.id" class="row" :title="row.id">
          <n-checkbox size="small"
                      :checked="store.enabled.has(row.id)"
                      :on-update:checked="(v: boolean) => toggle(row.id, v)" />
          <span class="pname">{{ row.name }}</span>
          <span class="pcount num" :class="{ zero: row.count === 0 }">{{ row.count }}</span>
        </label>

        <!-- 协议分组:折叠归纳 + 组级三态勾选 -->
        <div v-for="g in s.groups" :key="g.name" class="pblock">
          <div class="row grow">
            <n-checkbox size="small"
                        :checked="g.checked"
                        :indeterminate="g.indeterminate"
                        :on-update:checked="(v: boolean) => toggleGroupCheck(g, v)" />
            <span class="gname" @click="toggleGroup(g.name)">
              <component :is="expandedGroups.has(g.name) ? ChevronDown : ChevronRight" :size="12" />
              {{ g.name }}
            </span>
            <span class="pcount num" :class="{ zero: g.count === 0 }">{{ g.count }}</span>
          </div>
          <template v-if="expandedGroups.has(g.name)">
            <label v-for="row in g.rows" :key="row.id" class="row indented" :title="row.id">
              <n-checkbox size="small"
                          :checked="store.enabled.has(row.id)"
                          :on-update:checked="(v: boolean) => toggle(row.id, v)" />
              <span class="pname">{{ row.name }}</span>
              <span class="pcount num" :class="{ zero: row.count === 0 }">{{ row.count }}</span>
            </label>
          </template>
        </div>
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
.row.indented { padding-left: 24px; }
.row.grow { padding-left: 6px; }
.pname {
  font-size: 12px; color: #c9d1d9;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.gname {
  display: inline-flex; align-items: center; gap: 3px;
  font-size: 12px; color: #c9d1d9; font-weight: 500;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.gname:hover { color: #fff; }
.gname :deep(svg) { color: #6e7681; flex-shrink: 0; }
.pblock { margin: 1px 0; }
.pcount { margin-left: auto; font-size: 11px; color: #8b949e; }
.pcount.zero { color: #484f58; }
.foot {
  padding: 7px 12px; font-size: 11px; color: #484f58;
  border-top: 1px solid #21262d;
}
</style>
