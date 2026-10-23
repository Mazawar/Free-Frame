<script setup lang="ts">
import { nextTick, ref, watch } from 'vue'
import { NInput, NTooltip } from 'naive-ui'
import { api } from '../api'
import { bpfSuggest, type BpfSuggest, type HintData } from '../utils/bpf'

/**
 * BPF 过滤输入框:输入联想(文法引导 + 协议配方)+ 实时校验(libpcap 裁决)。
 * 联想替换「光标处当前词」,校验只提示不阻断——最终裁决在启动采集时(同一编译器)。
 */
const props = defineProps<{ value: string }>()
const emit = defineEmits<{ (e: 'update:value', v: string): void }>()

const wrapEl = ref<HTMLElement | null>(null)
const open = ref(false)
const items = ref<BpfSuggest[]>([])
const active = ref(0)
const tokenStart = ref(0)
const tokenEnd = ref(0)
let caret = 0

// 提示素材(配方/本机地址):首次聚焦拉取,失败静默降级
const hints = ref<HintData>({ recipes: [], localAddresses: [] })
let hintsLoaded = false
function loadHints() {
  if (hintsLoaded) return
  hintsLoaded = true
  api.bpfHints().then(h => { hints.value = h }).catch(() => {})
}
// 素材是异步的:到达后重算一次,否则首次聚焦的下拉只有静态文法词条
watch(hints, () => refresh())

// ---- 实时校验(防抖 300ms;结论 = libpcap 编译结果) ----

type Verdict = 'idle' | 'checking' | 'ok' | 'err'
const verdict = ref<Verdict>('idle')
const verdictMsg = ref('')
let validateSeq = 0
let validateTimer: ReturnType<typeof setTimeout> | undefined

function scheduleValidate(v: string) {
  clearTimeout(validateTimer)
  const seq = ++validateSeq
  if (!v.trim()) {
    verdict.value = 'idle'
    verdictMsg.value = ''
    return
  }
  verdict.value = 'checking'
  validateTimer = setTimeout(async () => {
    try {
      const r = await api.bpfValidate(v)
      if (seq !== validateSeq) return
      verdict.value = r.ok ? 'ok' : 'err'
      verdictMsg.value = r.ok ? '' : (r.error ?? '无效的 BPF 表达式')
    } catch {
      if (seq !== validateSeq) return
      verdict.value = 'idle'   // 校验端点不可达:不做判断,不误报
    }
  }, 300)
}

watch(() => props.value, v => {
  scheduleValidate(v)
  refresh()
})

function refresh() {
  const ctx = bpfSuggest(props.value, Math.min(caret, props.value.length), hints.value)
  items.value = ctx.items
  tokenStart.value = ctx.tokenStart
  tokenEnd.value = ctx.tokenEnd
  active.value = 0
  open.value = ctx.items.length > 0
}

function onInputEvt(v: string) {
  const el = wrapEl.value?.querySelector('input')
  caret = el?.selectionStart ?? v.length
  emit('update:value', v)
}

function onFocus() {
  caret = wrapEl.value?.querySelector('input')?.selectionStart ?? props.value.length
  loadHints()
  refresh()
}

function onBlur() {
  open.value = false
}

/** 选中一项:替换光标所在的整个词(词中间不劈词),补尾空格,光标落在词后继续联想。 */
function apply(s: BpfSuggest) {
  if (!s.text) return
  const v = props.value
  const next = v.slice(0, tokenStart.value) + s.text + ' '
    + v.slice(tokenEnd.value).replace(/^\s+/, '')
  caret = tokenStart.value + s.text.length + 1
  open.value = false
  emit('update:value', next)
  nextTick(() => {
    const el = wrapEl.value?.querySelector('input')
    if (!el) return
    el.focus()
    el.setSelectionRange(caret, caret)
    scrollCaretIntoView(el)
  })
}

/** 程序设值 + setSelectionRange 后,浏览器不会像键入那样自动把光标滚进可视区——
 *  用镜像 span 按输入框同字体测量光标前文本的像素宽度,手动滚动保证光标(及其后一词)可见。 */
function scrollCaretIntoView(el: HTMLInputElement) {
  const pos = el.selectionStart ?? 0
  if (!el.value) return
  const m = document.createElement('span')
  const cs = getComputedStyle(el)
  m.style.cssText = 'position:absolute;visibility:hidden;white-space:pre;'
  m.style.font = cs.font
  m.style.letterSpacing = cs.letterSpacing
  m.style.textTransform = cs.textTransform
  m.textContent = el.value.slice(0, pos)
  document.body.appendChild(m)
  const x = m.getBoundingClientRect().width
  m.remove()
  const w = el.clientWidth
  if (x - el.scrollLeft > w - 24) {
    el.scrollLeft = x - w + 48
  } else if (x < el.scrollLeft) {
    el.scrollLeft = Math.max(0, x - 48)
  }
}

function onKeydown(e: KeyboardEvent) {
  // 光标移动键:keydown 先于默认移动,帧后再读新光标位置并重算联想
  if (e.key === 'ArrowLeft' || e.key === 'ArrowRight' || e.key === 'Home' || e.key === 'End') {
    requestAnimationFrame(() => {
      const el = wrapEl.value?.querySelector('input')
      caret = el?.selectionStart ?? caret
      refresh()
    })
    return
  }
  if (!open.value || items.value.length === 0) return
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault()
    const delta = e.key === 'ArrowDown' ? 1 : -1
    active.value = (active.value + delta + items.value.length) % items.value.length
    scrollActiveIntoView()
  } else if (e.key === 'Enter' || e.key === 'Tab') {
    const s = items.value[active.value]
    if (s?.text) {
      e.preventDefault()
      apply(s)
    }
  } else if (e.key === 'Escape') {
    open.value = false
  }
}

function scrollActiveIntoView() {
  nextTick(() => {
    wrapEl.value?.querySelector('.it.active')?.scrollIntoView({ block: 'nearest' })
  })
}
</script>

<template>
  <!-- data-verdict 供 :deep 染边框:绿=libpcap 编译通过,红=语法错误(hover 看原文) -->
  <div ref="wrapEl" class="bpf-input" :data-verdict="verdict">
    <!-- keydown 经 input-props 直绑原生 input:naive-ui 不透传 @keydown 到内部输入框 -->
    <n-input :value="props.value" size="small"
             :input-props="{ spellcheck: false, onKeydown: onKeydown }"
             placeholder="BPF 过滤,输入有提示"
             @update:value="onInputEvt" @focus="onFocus" @blur="onBlur" />
    <n-tooltip v-if="verdict === 'err'" trigger="hover" placement="bottom-start" :show-arrow="false">
      <template #trigger>
        <span class="dot err" title=""></span>
      </template>
      <span class="verdict-msg">{{ verdictMsg }}</span>
    </n-tooltip>
    <span v-else-if="verdict === 'ok'" class="dot ok"></span>

    <div v-if="open && items.length" class="pop">
      <div v-for="(s, i) in items" :key="s.kind + ':' + s.text + ':' + i"
           class="it" :class="{ active: i === active, hint: !s.text }"
           @mousedown.prevent @click="apply(s)" @mousemove="active = i">
        <span class="tx" :data-kind="s.kind">{{ s.text || '·' }}</span>
        <span class="ds">{{ s.desc }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.bpf-input { position: relative; }

/* 校验状态:绿点/红点悬于输入框右缘,并染同色边框(主题内不额外发光) */
.dot {
  position: absolute; right: 7px; top: 50%; transform: translateY(-50%);
  width: 7px; height: 7px; border-radius: 50%; pointer-events: auto; z-index: 1;
}
.dot.ok { background: #57ab5a; }
.dot.err { background: #f85149; cursor: help; }
.bpf-input[data-verdict='ok'] :deep(.n-input .n-input__border),
.bpf-input[data-verdict='ok'] :deep(.n-input .n-input__state-border) { border-color: #2ea04366; }
.bpf-input[data-verdict='err'] :deep(.n-input .n-input__border),
.bpf-input[data-verdict='err'] :deep(.n-input .n-input__state-border) { border-color: #f85149aa; }
.bpf-input :deep(.n-input .n-input__input-el) { padding-right: 18px; }

.pop {
  position: absolute; top: calc(100% + 5px); left: 0; z-index: 60;
  width: 340px; max-height: 288px; overflow-y: auto;
  background: #161b22; border: 1px solid #30363d; border-radius: 6px;
  box-shadow: 0 8px 24px rgba(1, 4, 9, .6);
  padding: 4px; user-select: none;
}
.it {
  display: flex; align-items: baseline; gap: 8px;
  padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 12px; line-height: 1.5;
}
.it.active { background: #21262d; }
.it .tx {
  flex-shrink: 0; max-width: 62%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-family: ui-monospace, Consolas, monospace; color: #e6edf3;
}
.it .tx[data-kind='recipe'] { color: #79c0ff; }
.it .tx[data-kind='value'] { color: #7ee787; }
.it .tx[data-kind='op'] { color: #d2a8ff; }
.it .ds {
  flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  color: #8b949e; font-size: 11px;
}
/* 纯说明行:不可选、弱化 */
.it.hint { cursor: default; }
.it.hint .tx { visibility: hidden; width: 0; flex-shrink: 1; }
.it.hint .ds { color: #6e7681; font-style: normal; }
.it.hint.active { background: transparent; }

.verdict-msg { font-family: ui-monospace, Consolas, monospace; font-size: 11px; max-width: 320px; display: inline-block; white-space: normal; }
</style>
