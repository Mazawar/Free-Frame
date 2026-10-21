<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { NButton, NInput, NModal, NSelect, NSpace, NSwitch, NTag, useMessage } from 'naive-ui'
import { SendHorizontal, SlidersHorizontal, Code2 } from 'lucide-vue-next'
import { api } from '../api'
import { store } from '../store'
import { layerColor } from '../utils/format'
import type { FieldMeta, ProtocolMeta } from '../types'
import { evalExpr, fieldValue, fmtHint, loadTemplate, saveTemplate } from '../utils/sendTemplate'

const message = useMessage()
/** 字段名首字母大写(与详情树一致);label 注解优先 */
const cap = (s: string) => (s ? s[0]!.toUpperCase() + s.slice(1) : s)
const sending = ref(false)
/** 业务目标协议(选它 → /template 推导整条链) */
const target = ref<string | null>(null)
/** 链上各层已填值 { [protocolId]: { [field]: raw } } */
const values = ref<Record<string, Record<string, string>>>({})
const mode = ref<'form' | 'json'>('form')
const jsonText = ref('')
/** /template 原始返回(层顺序),用于渲染与发送 */
const chainLayers = ref<{ protocol: string; fields: Record<string, unknown> }[]>([])

const ifaceOptions = computed(() =>
  store.interfaces.map(i => ({ label: (i.description || i.name).slice(0, 64), value: i.name })))

/** 可选目标:非 element 的协议(业务 + 栈协议都可发);按组分组展示(过滤输入可跨组搜索) */
const targetOptions = computed(() => {
  const protos = store.protocols.filter(p => p.category !== 'element')
  const groups = new Map<string, ProtocolMeta[]>()
  for (const p of protos) {
    const g = p.group || (p.builtin ? '内置栈' : '独立协议')
    if (!groups.has(g)) groups.set(g, [])
    groups.get(g)!.push(p)
  }
  return [...groups.entries()].map(([g, ps]) => ({
    type: 'group' as const, label: g, key: g,
    children: ps.map(p => ({ label: `${p.name} (${p.id})`, value: p.id })),
  }))
})

const chainIds = computed(() => chainLayers.value.map(l => l.protocol))
const chainText = computed(() => chainIds.value.join(' ▸ '))

function protoOf(id: string): ProtocolMeta | undefined {
  return store.protocols.find(p => p.id === id)
}
function fieldsOf(id: string): FieldMeta[] {
  return protoOf(id)?.fields ?? []
}
/** 前端展示用字段:过滤 payload 与列表型(elementClass),这些留给 JSON 高级模式 */
function editableFields(id: string): FieldMeta[] {
  return fieldsOf(id).filter(f => !f.payload && !f.elementClass)
}

/** 条件显隐:presentIf 按当前层已填值求值(数字字符串按数读) */
function visible(id: string, f: FieldMeta): boolean {
  if (!f.presentIf) return true
  const env: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(values.value[id] ?? {})) {
    const n = Number(v)
    env[k] = v !== '' && Number.isFinite(n) ? n : v
  }
  return evalExpr(f.presentIf, env)
}

/** 本层被引用的长度/计数指示字段(编码器自动算,发送时剔除);
 *  注意 lengthField 标在内容字段上,指示字段本身是"被指向"的那个。 */
function indicatorNames(id: string): Set<string> {
  return new Set(fieldsOf(id)
    .flatMap(f => [f.lengthField, f.countField])
    .filter((x): x is string => !!x))
}
const isChecksumField = (f: FieldMeta) => !!f.checksum

/** flags 字段(Set<枚举>):表单存逗号串,选择框拆数组 */
function flagSel(id: string, f: FieldMeta): string[] {
  return (values.value[id]?.[f.name] ?? '').split(/[,\s]+/).map(s => s.trim()).filter(Boolean)
}
function setFlags(id: string, f: FieldMeta, arr: string[]) {
  values.value[id]![f.name] = arr.join(',')
}
/** 徽标悬浮说明:这个字段到底该填什么 */
function fmtTitle(f: FieldMeta): string {
  const h = fmtHint(f)
  const width = h.tag.includes('·') ? `,定宽 ${h.tag.split('·')[1]}` : ''
  const what: Record<string, string> = {
    dec: '十进制数值,也接受 0x 前缀十六进制',
    hex: '十六进制字节串,两位一字节',
    MAC: '冒号分隔 MAC 地址',
    IP: '点分十进制 IPv4 地址',
    str: 'UTF-8 文本',
    flags: '勾选标志位,未勾选按 0 编码',
  }
  const kind = h.tag.split('·')[0]!
  return `${f.name}:${what[kind] ?? kind}${width}`
}

/** 选目标 → 拉模板 → 恢复缓存值 */
async function pickTarget(id: string | null) {
  if (!id) return
  try {
    const t = await api.template(id)
    chainLayers.value = t.layers
    // 默认值打底
    const base: Record<string, Record<string, string>> = {}
    for (const l of t.layers) {
      base[l.protocol] = {}
      for (const [k, v] of Object.entries(l.fields)) {
        base[l.protocol]![k] = String(v ?? '')
      }
    }
    // 缓存值覆盖(指纹校验在内)
    const cached = loadTemplate(chainIds.value, store.protocols)
    if (cached) {
      for (const [pid, fields] of Object.entries(cached)) {
        if (base[pid]) {
          for (const [k, v] of Object.entries(fields)) base[pid]![k] = String(v)
        }
      }
      message.info('已恢复上次填写(按协议版本缓存)', { duration: 2500 })
    }
    values.value = base
    mode.value = 'form'
    syncToJson()
  } catch (e) {
    message.error(`模板生成失败:${(e as Error).message}`)
  }
}

/** 表单 → 发送 JSON(空值与自动指示字段剔除,交编码器补) */
function buildLayers(): { protocol: string; fields: Record<string, unknown> }[] {
  return chainLayers.value.map(l => {
    const indicators = indicatorNames(l.protocol)
    const fields: Record<string, unknown> = {}
    const metas = fieldsOf(l.protocol)
    for (const f of metas) {
      const raw = values.value[l.protocol]?.[f.name]
      if (raw === undefined || raw === '') continue
      if (indicators.has(f.name)) continue         // 长度/计数指示交给编码器
      fields[f.name] = fieldValue(f, raw)
    }
    return { protocol: l.protocol, fields }
  })
}

function syncToJson() {
  jsonText.value = JSON.stringify({ layers: buildLayers() }, null, 2)
}

watch(values, syncToJson, { deep: true })

/** 打开弹窗时默认选第一个协议(避免空表单);已选过则保留 */
watch(() => store.sendOpen, (open) => {
  if (open && !target.value) {
    const first = targetOptions.value[0]?.children[0]?.value
    if (first) {
      target.value = first
      pickTarget(first)
    }
  }
})

function switchToJson() {
  syncToJson()
  mode.value = 'json'
}
function switchToForm() {
  try {
    const parsed = JSON.parse(jsonText.value) as { layers?: { protocol: string; fields: Record<string, unknown> }[] }
    if (Array.isArray(parsed.layers)) {
      chainLayers.value = parsed.layers
      const base: Record<string, Record<string, string>> = {}
      for (const l of parsed.layers) {
        base[l.protocol] = {}
        for (const [k, v] of Object.entries(l.fields ?? {})) {
          base[l.protocol]![k] = typeof v === 'string' ? v : String(v)
        }
      }
      values.value = base
    }
    mode.value = 'form'
  } catch (e) {
    message.error(`JSON 无效:${(e as Error).message}`)
  }
}

async function send() {
  const payload = mode.value === 'json'
    ? (() => { try { return JSON.parse(jsonText.value) } catch (e) { message.error(`JSON 无效:${(e as Error).message}`); return null } })()
    : { layers: buildLayers() }
  if (!payload || !Array.isArray((payload as { layers?: unknown[] }).layers)
      || (payload as { layers: unknown[] }).layers.length === 0) {
    if (payload) message.error('layers 必须是非空数组(外层 → 内层)')
    return
  }
  if (!store.iface) {
    message.error('请先选择网卡')
    return
  }
  sending.value = true
  try {
    const r = await api.send(store.iface, (payload as { layers: unknown[] }).layers)
    // 成功即缓存当前表单值(仅表单模式;指纹随协议定义自动失效旧缓存)
    if (mode.value === 'form') saveTemplate(chainIds.value, store.protocols, values.value)
    message.success(`已注入 ${r.bytes} 字节`)
    store.sendOpen = false
  } catch (e) {
    message.error(`注入失败:${(e as Error).message}`, { duration: 5000 })
  } finally {
    sending.value = false
  }
}
</script>

<template>
  <n-modal v-model:show="store.sendOpen" preset="card" title="构造并发送"
           style="width: 720px">
    <div class="body">
      <n-space align="center" :size="8">
        <n-select v-model:value="store.iface" :options="ifaceOptions" filterable
                  placeholder="网卡" size="small" style="width: 240px" />
        <n-select v-model:value="target" :options="targetOptions" filterable
                  placeholder="选择目标协议(自动生成协议链)" size="small" style="width: 260px"
                  @update:value="pickTarget" />
        <span class="flex1"></span>
        <n-button size="small" quaternary @click="mode === 'form' ? switchToJson() : switchToForm()">
          <template #icon>
            <component :is="mode === 'form' ? Code2 : SlidersHorizontal" :size="13" />
          </template>
          {{ mode === 'form' ? 'JSON' : '表单' }}
        </n-button>
        <n-button size="small" type="primary" :loading="sending" @click="send">
          <template #icon><SendHorizontal :size="13" /></template>
          注入
        </n-button>
      </n-space>

      <div v-if="chainText" class="chain">
        <span v-for="(id, i) in chainIds" :key="id + i" class="chip"
              :style="{ color: layerColor(i), background: layerColor(i) + '14' }">
          {{ (protoOf(id)?.name ?? id).toUpperCase() }}
        </span>
      </div>

      <!-- 表单模式:按层分组的字段编辑 -->
      <div v-if="mode === 'form'" class="layers">
        <section v-for="(l, i) in chainLayers" :key="l.protocol" class="layer">
          <header class="lhead">
            <span class="lname">{{ protoOf(l.protocol)?.name ?? l.protocol }}</span>
            <n-tag size="tiny" :bordered="false"
                   :style="{ color: layerColor(i), background: layerColor(i) + '14' }">
              {{ l.protocol }}
            </n-tag>
          </header>
          <div class="grid">
            <div v-for="f in editableFields(l.protocol)" :key="f.name"
                 v-show="visible(l.protocol, f)"
                 class="field" :title="f.label && f.label !== f.name ? f.label : undefined">
              <label class="flabel">
                {{ f.label || cap(f.name) }}
                <span class="fmt" :title="fmtTitle(f)">{{ fmtHint(f).tag }}</span>
                <span v-if="indicatorNames(l.protocol).has(f.name) || isChecksumField(f)"
                      class="auto" title="编码期自动计算,可留空覆盖">自动</span>
              </label>
              <n-select v-if="f.flagClass && f.flags" :value="flagSel(l.protocol, f)" multiple clearable
                        size="tiny" max-tag-count="responsive"
                        :options="f.flags.map(fl => ({ label: fl.name, value: fl.name }))"
                        @update:value="(arr: string[]) => setFlags(l.protocol, f, arr)" />
              <n-input v-else v-model:value="values[l.protocol]![f.name]" size="tiny"
                       :placeholder="fmtHint(f).placeholder"
                       :disabled="isChecksumField(f) && (values[l.protocol]![f.name] ?? '') === ''"
                       spellcheck="false" class="finput" />
            </div>
          </div>
        </section>
        <p v-if="!chainLayers.length" class="hint">先选择目标协议,自动生成协议链与字段表单;填写值按协议版本本地缓存。</p>
      </div>

      <!-- JSON 高级模式:包成单一元素,避免条件分支直接挂在列表容器下被重复挂载 -->
      <div v-else class="jsonbody">
        <n-input v-model:value="jsonText" type="textarea" :rows="16" spellcheck="false" class="code" />
      </div>

      <p v-if="mode === 'form'" class="hint">
        字段标签旁徽标标注填写格式:dec=十进制(可 0x 十六进制)、hex=十六进制字节、MAC/IP=地址格式;悬浮徽标看说明。
        「自动」字段(长度/计数/校验和)由编码器计算,可留空。发送成功后按协议链缓存本次填写。
      </p>
      <p v-else class="hint">
        层顺序外层 → 内层;选择子/长度/校验和自动补齐(显式值优先)。byte[] 填 hex,MAC 填 aa:bb:cc:dd:ee:ff,IP 填点分十进制。
      </p>
    </div>
  </n-modal>
</template>

<style scoped>
.body { display: flex; flex-direction: column; gap: 10px; }
.flex1 { flex: 1; }
.chain { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.chip {
  font-size: 11px; padding: 1px 7px; border-radius: 3px;
  font-family: ui-monospace, Consolas, monospace;
  letter-spacing: .3px;
}
.layers { max-height: 52vh; overflow-y: auto; display: flex; flex-direction: column; gap: 10px; }
.layer { background: #0d1117; border: 1px solid #21262d; border-radius: 5px; padding: 8px 10px; }
.lhead { display: flex; align-items: center; gap: 7px; margin-bottom: 7px; }
.lname { font-size: 12px; font-weight: 600; color: #c9d1d9; }
.grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 7px 12px; }
.field { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.flabel {
  font-size: 11px; color: #8b949e; display: flex; align-items: center; gap: 5px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.auto {
  font-size: 9px; color: #c69026; border: 1px solid #c6902644;
  padding: 0 4px; border-radius: 3px; flex-shrink: 0;
}
.fmt {
  font-size: 9px; color: #79c0ff; border: 1px solid #79c0ff33;
  padding: 0 4px; border-radius: 3px; flex-shrink: 0;
  font-family: ui-monospace, Consolas, monospace;
  cursor: help;
}
.finput { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.code { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.jsonbody { display: flex; }
.hint {
  margin: 0; font-size: 11px; line-height: 1.7; color: #9aa4b2;
  background: #161b22; border-left: 3px solid #58a6ff66;
  padding: 6px 10px; border-radius: 0 4px 4px 0;
}
</style>
