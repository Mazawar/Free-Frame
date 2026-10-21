<script setup lang="ts">
import { computed, ref } from 'vue'
import { NCheckbox } from 'naive-ui'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'
import { protoCounts, store } from '../store'
import type { ProtocolMeta } from '../types'

interface Row { id: string; name: string; count: number }
/** 组节点:path 为 '/' 连接的完整组路径(如 智能配电/接入管理),支持任意深度。 */
interface GroupNode {
  name: string
  key: string
  rows: Row[]
  children: GroupNode[]
  count: number
  checked: boolean
  indeterminate: boolean
}
interface Item {
  kind: 'group' | 'row'
  depth: number
  group?: GroupNode
  row?: Row
}
interface Section { label: string; items: Item[] }

const expandedPaths = ref(new Set<string>())

function toggleExpand(key: string) {
  const s = new Set(expandedPaths.value)
  s.has(key) ? s.delete(key) : s.add(key)
  expandedPaths.value = s
}

function toRow(p: ProtocolMeta): Row {
  return { id: p.id, name: p.name, count: protoCounts.get(p.id) ?? 0 }
}

/** 组段数组 → 树:每段一级,协议挂最深层节点。
 *  展开键取 JSON 串:段内含任意字符(包括其它组的名字)都不会碰撞。 */
function insert(root: GroupNode, segs: string[], row: Row) {
  let cur = root
  let key = '[]'
  for (const seg of segs) {
    key = JSON.stringify([...JSON.parse(key), seg])
    let next = cur.children.find(c => c.key === key)
    if (!next) {
      next = { name: seg, key, rows: [], children: [], count: 0, checked: false, indeterminate: false }
      cur.children.push(next)
    }
    cur = next
  }
  cur.rows.push(row)
}

/** 自底向上聚合:计数、全选/半选状态。 */
function aggregate(node: GroupNode): { total: number; enabled: number } {
  let total = node.rows.length
  let enabled = node.rows.filter(r => store.enabled.has(r.id)).length
  for (const c of node.children) {
    const s = aggregate(c)
    total += s.total
    enabled += s.enabled
  }
  node.count = node.rows.reduce((a, r) => a + r.count, 0)
    + node.children.reduce((a, c) => a + c.count, 0)
  node.checked = total > 0 && enabled === total
  node.indeterminate = enabled > 0 && enabled < total
  return { total, enabled }
}

/** 树 → 扁平渲染项;组未展开则不下钻。 */
function flatten(node: GroupNode, depth: number, out: Item[]) {
  out.push({ kind: 'group', depth, group: node })
  if (!expandedPaths.value.has(node.key)) {
    return
  }
  for (const r of node.rows) {
    out.push({ kind: 'row', depth: depth + 1, row: r })
  }
  for (const c of node.children) {
    flatten(c, depth + 1, out)
  }
}

const sections = computed<Section[]>(() => {
  const buckets: Record<string, ProtocolMeta[]> = { stackBuiltin: [], stackCustom: [], island: [] }
  for (const p of store.protocols) {
    // 元素实体/公共头等中间产物:不可过滤,不展示
    if (p.category === 'element' || p.category === 'internal') continue
    if (p.category === 'island') buckets.island.push(p)
    else buckets[p.builtin ? 'stackBuiltin' : 'stackCustom'].push(p)
  }
  const build = (list: ProtocolMeta[]): Pick<Section, 'items'> => {
    const root: GroupNode = { name: '', key: '[]', rows: [], children: [], count: 0, checked: false, indeterminate: false }
    for (const p of list) {
      insert(root, p.groupPath, toRow(p))
    }
    aggregate(root)
    const items: Item[] = []
    for (const r of root.rows) {
      items.push({ kind: 'row', depth: 0, row: r })
    }
    for (const g of root.children) {
      flatten(g, 0, items)
    }
    return { items }
  }
  const out: Section[] = []
  const b = build(buckets.stackBuiltin)
  const c = build(buckets.stackCustom)
  const i = build(buckets.island)
  if (b.items.length) out.push({ label: '内置协议栈', items: b.items })
  if (c.items.length) out.push({ label: '业务协议', items: c.items })
  if (i.items.length) out.push({ label: '独立协议 · 不在链路分派', items: i.items })
  return out
})

function toggle(id: string, v: boolean) {
  v ? store.enabled.add(id) : store.enabled.delete(id)
}

/** 组级勾选:全选/取消该组全部后代协议。 */
function toggleGroupCheck(g: GroupNode, v: boolean) {
  for (const r of g.rows) {
    v ? store.enabled.add(r.id) : store.enabled.delete(r.id)
  }
  for (const c of g.children) {
    toggleGroupCheck(c, v)
  }
}

function selectAll() {
  store.protocols.forEach(p => {
    if (p.category !== 'element' && p.category !== 'internal') store.enabled.add(p.id)
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
        <template v-for="(item, i) in s.items" :key="(item.group?.key ?? item.row?.id) + i">
          <!-- 组节点:任意深度,三态勾选 + 折叠 -->
          <div v-if="item.kind === 'group' && item.group" class="row grow"
               :style="{ paddingLeft: 6 + item.depth * 14 + 'px' }">
            <n-checkbox size="small"
                        :checked="item.group.checked"
                        :indeterminate="item.group.indeterminate"
                        :on-update:checked="(v: boolean) => toggleGroupCheck(item.group!, v)" />
            <span class="gname" @click="toggleExpand(item.group.key)">
              <component :is="expandedPaths.has(item.group.key) ? ChevronDown : ChevronRight" :size="12" />
              {{ item.group.name }}
            </span>
            <span class="pcount num" :class="{ zero: item.group.count === 0 }">{{ item.group.count }}</span>
          </div>
          <!-- 协议行 -->
          <label v-else-if="item.row" class="row" :title="item.row.id"
                 :style="{ paddingLeft: 6 + (item.depth + 1) * 14 + 'px' }">
            <n-checkbox size="small"
                        :checked="store.enabled.has(item.row.id)"
                        :on-update:checked="(v: boolean) => toggle(item.row!.id, v)" />
            <span class="pname">{{ item.row.name }}</span>
            <span class="pcount num" :class="{ zero: item.row.count === 0 }">{{ item.row.count }}</span>
          </label>
        </template>
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
.gname {
  display: inline-flex; align-items: center; gap: 3px;
  font-size: 12px; color: #c9d1d9; font-weight: 500;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.gname:hover { color: #fff; }
.gname :deep(svg) { color: #6e7681; flex-shrink: 0; }
.pcount { margin-left: auto; font-size: 11px; color: #8b949e; }
.pcount.zero { color: #484f58; }
.foot {
  padding: 7px 12px; font-size: 11px; color: #484f58;
  border-top: 1px solid #21262d;
}
</style>
