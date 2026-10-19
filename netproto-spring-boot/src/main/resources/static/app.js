/* netproto 观测台前端:vanilla JS,无构建链 */
'use strict';

const $ = (id) => document.getElementById(id);
const state = {
    protocols: [],          // [{id,name,builtin,fields}]
    checked: new Set(),     // 勾选的协议 id(过滤)
    packets: [],            // 最近帧(有界)
    maxPackets: 2000,
    selected: null,
    running: false,
};

// ---- 初始化 ----
async function init() {
    await Promise.all([loadProtocols(), loadInterfaces(), refreshStatus()]);
    connectStream();
    pollStatus();
    bindControls();
    defaultSendTemplate();
}

async function loadProtocols() {
    const list = await (await fetch('/api/netproto/protocols')).json();
    state.protocols = list;
    list.forEach(p => state.checked.add(p.id));
    renderProtocols();
}

async function loadInterfaces() {
    try {
        const list = await (await fetch('/api/netproto/interfaces')).json();
        const opts = list.map(i => {
            const label = (i.description || i.name).slice(0, 50);
            return `<option value="${esc(i.name)}">${esc(label)}</option>`;
        }).join('');
        $('iface').innerHTML = opts;
        $('send-iface').innerHTML = opts;
    } catch (e) {
        $('iface').innerHTML = '<option>枚举网卡失败(需 Npcap)</option>';
    }
}

function bindControls() {
    $('btn-start').onclick = async () => {
        await post('/api/netproto/capture/start', { iface: $('iface').value, bpf: $('bpf').value });
    };
    $('btn-stop').onclick = async () => { await post('/api/netproto/capture/stop', {}); };
    $('detail-close').onclick = () => { state.selected = null; $('detail').classList.add('hidden'); };
    $('btn-send').onclick = sendPacket;
}

// ---- SSE 实时流 ----
function connectStream() {
    const es = new EventSource('/api/netproto/stream');
    es.addEventListener('packet', ev => {
        const p = JSON.parse(ev.data);
        onPacket(p);
    });
    es.onerror = () => setStatus('error', 'stream 断开,自动重连…');
    es.onopen = () => { if (state.running) setStatus('running', 'live'); };
}

function onPacket(p) {
    state.packets.push(p);
    if (state.packets.length > state.maxPackets) state.packets.splice(0, state.packets.length - state.maxPackets);
    $('count').textContent = state.packets.length + ' pkts';
    if (matchesFilter(p)) appendRow(p);
}

function matchesFilter(p) {
    return p.layers.some(l => state.checked.has(l.id));
}

// ---- 渲染 ----
function renderProtocols() {
    $('proto-list').innerHTML = state.protocols.map(p => `
        <li>
            <input type="checkbox" data-id="${esc(p.id)}" ${state.checked.has(p.id) ? 'checked' : ''}>
            <span title="${esc(p.id)}">${esc(p.name)}</span>
            ${p.builtin ? '<span class="badge">内置</span>' : ''}
        </li>`).join('');
    $('proto-list').querySelectorAll('input').forEach(cb => {
        cb.onchange = () => {
            cb.checked ? state.checked.add(cb.dataset.id) : state.checked.delete(cb.dataset.id);
            rebuildRows();
        };
    });
}

function rebuildRows() {
    const tbody = $('pkt-body');
    tbody.innerHTML = '';
    const shown = state.packets.filter(matchesFilter).slice(-500);
    shown.forEach(p => appendRow(p));
    $('empty').style.display = shown.length ? 'none' : 'block';
}

function appendRow(p) {
    $('empty').style.display = 'none';
    const tbody = $('pkt-body');
    const tr = document.createElement('tr');
    tr.dataset.seq = p.seq;
    tr.innerHTML = `
        <td>${p.seq}</td>
        <td>${new Date(p.ts).toLocaleTimeString()}</td>
        <td class="path">${pathHtml(p)}</td>
        <td>${p.len}</td>
        <td title="${esc(summary(p))}">${esc(summary(p))}</td>`;
    tr.onclick = () => showDetail(p, tr);
    tbody.appendChild(tr);
    while (tbody.children.length > 500) tbody.removeChild(tbody.firstChild);
}

function pathHtml(p) {
    return p.layers.map(l => `<span class="p">${esc(l.id)}</span>`)
        .join('<span class="sep">▸</span>');
}

/** 概要:优先 IP 五元组,否则首层字段拼接。 */
function summary(p) {
    const ipv4 = p.layers.find(l => l.id === 'ipv4');
    const tp = p.layers.find(l => l.id === 'udp' || l.id === 'tcp');
    const app = p.layers[p.layers.length - 1];
    let s = '';
    if (ipv4) {
        s += `${ipv4.fields.sourceIp ?? '?'} → ${ipv4.fields.destinationIp ?? '?'}`;
        if (tp) s += ` :${tp.fields.srcPort}→${tp.fields.dstPort}`;
        if (app && app.id !== 'ipv4' && app.id !== 'udp' && app.id !== 'tcp' && app.id !== 'ethernet') {
            s += ` [${app.name}]`;
        }
        return s;
    }
    const arp = p.layers.find(l => l.id === 'arp');
    if (arp) return `ARP ${arp.fields.operation === 1 ? 'request' : 'reply'} ${arp.fields.senderIp} → ${arp.fields.targetIp}`;
    return p.layers.map(l => l.id).join('▸');
}

// ---- 详情:层级手风琴 + hex 高亮 ----
function showDetail(p, tr) {
    state.selected = p.seq;
    document.querySelectorAll('#pkt-body tr.selected').forEach(r => r.classList.remove('selected'));
    tr.classList.add('selected');
    $('detail').classList.remove('hidden');
    $('detail-title').textContent = `#${p.seq} · ${p.path} · ${p.len}B`;
    $('detail-layers').innerHTML = p.layers.map((l, i) => `
        <details class="layer" ${i === p.layers.length - 1 ? 'open' : ''}>
            <summary>
                <span class="b${i % 6}">■</span> ${esc(l.name)}
                <span class="off">@${l.offset} +${l.headerLength}B</span>
            </summary>
            <table>${Object.entries(l.fields).map(([k, v]) => `
                <tr><td class="k">${esc(k)}</td><td class="v">${esc(fmtVal(v))}</td></tr>`).join('')}
            </table>
        </details>`).join('');
    $('detail-hex').innerHTML = hexDump(p);
}

function fmtVal(v) {
    if (Array.isArray(v)) return v.map(x => typeof x === 'object' ? JSON.stringify(x) : String(x)).join(', ');
    if (v === null) return 'null';
    return String(v);
}

function hexDump(p) {
    const bytes = p.hex.length / 2;
    const spans = p.layers.map((l, i) => ({ start: l.offset, end: l.offset + l.headerLength, cls: `b${i % 6}` }));
    let out = '';
    for (let row = 0; row * 16 < bytes; row++) {
        const base = row * 16;
        let hexPart = '', asciiPart = '';
        for (let col = 0; col < 16 && base + col < bytes; col++) {
            const idx = base + col;
            const hexByte = p.hex.substr(idx * 2, 2);
            const code = parseInt(hexByte, 16);
            const span = spans.find(s => idx >= s.start && idx < s.end);
            const cls = span ? span.cls : '';
            hexPart += `<span class="${cls}">${hexByte}</span> `;
            asciiPart += `<span class="${cls}">${code >= 32 && code < 127 ? String.fromCharCode(code) : '.'}</span>`;
        }
        out += `<span class="hx-off">${base.toString(16).padStart(4, '0')}</span>  ${hexPart} <span class="hx-ascii">${asciiPart}</span>\n`;
    }
    return out;
}

// ---- 发包 ----
function defaultSendTemplate() {
    $('send-json').value = JSON.stringify({
        iface: '(选择下方网卡)',
        layers: [
            { protocol: 'ethernet', fields: { dstMac: 'ff:ff:ff:ff:ff:ff', srcMac: '02:00:00:00:00:01' } },
            { protocol: 'ipv4', fields: { sourceIp: '192.168.1.100', destinationIp: '255.255.255.255', ttl: 64 } },
            { protocol: 'udp', fields: { srcPort: 44444, dstPort: 9999 } },
            { protocol: 'my-app', fields: { version: 1, type: 2, sequenceId: 1, payloadData: '68656c6c6f' } },
        ]
    }, null, 0);
}

async function sendPacket() {
    const result = $('send-result');
    result.className = '';
    result.textContent = '发送中…';
    try {
        const body = JSON.parse($('send-json').value);
        body.iface = $('send-iface').value;
        const resp = await post('/api/netproto/send', body);
        result.textContent = `已注入 ${resp.bytes} 字节`;
    } catch (e) {
        result.className = 'err';
        result.textContent = '失败: ' + (e.message || e);
    }
}

// ---- 状态 ----
async function refreshStatus() {
    try {
        const s = await (await fetch('/api/netproto/capture/status')).json();
        state.running = s.running;
        setStatus(s.running ? 'running' : 'idle', s.running ? `live @${s.iface}` : 'idle');
        if (!s.running && state.packets.length === 0) {
            const recent = await (await fetch('/api/netproto/packets?limit=100')).json();
            recent.reverse().forEach(onPacket);
        }
    } catch (e) { /* 服务未起 */ }
}

function pollStatus() { setInterval(refreshStatus, 3000); }

function setStatus(cls, text) {
    $('status').className = 'status ' + cls;
    $('status').textContent = text;
}

// ---- 工具 ----
async function post(url, body) {
    const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.message || data.error || resp.status);
    return data;
}

function esc(s) {
    return String(s).replace(/[&<>"']/g,
        c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

init();
