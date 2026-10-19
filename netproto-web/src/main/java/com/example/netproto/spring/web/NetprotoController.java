package com.example.netproto.spring.web;

import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.spring.capture.CaptureEngine;
import com.example.netproto.spring.capture.NetIfaces;
import com.example.netproto.spring.capture.RawSender;
import com.example.netproto.stack.DecodedPacket;
import com.example.netproto.stack.ProtocolRegistry;
import com.example.netproto.stack.StackEncoder;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Field;
import java.util.*;
import java.util.function.Consumer;

/**
 * 内置 REST/SSE API(页面由 static/index.html 提供)。
 * <p>
 * 注意:本控制器经 NetprotoAutoConfiguration 以 @Bean 注册(starter 语义),
 * 不依赖组件扫描也能生效。
 */
@RestController
@RequestMapping("/api/netproto")
public class NetprotoController {

    private static final Logger log = LoggerFactory.getLogger(NetprotoController.class);

    private final ProtocolRegistry registry;
    private final CaptureEngine capture;
    private final RawSender sender;
    private final StackEncoder encoder;
    private final ObjectMapper objectMapper;

    public NetprotoController(ProtocolRegistry registry, CaptureEngine capture, RawSender sender,
                              StackEncoder encoder, ApplicationContext appContext) {
        this.registry = registry;
        this.capture = capture;
        this.sender = sender;
        this.encoder = encoder;
        this.objectMapper = appContext.getBeanProvider(ObjectMapper.class).getIfAvailable(ObjectMapper::new);
    }

    // ---- 协议元数据 ----

    @GetMapping("/protocols")
    public List<Map<String, Object>> protocols() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (ProtocolRegistry.Entry e : registry.all()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", e.id());
            m.put("name", e.name());
            m.put("builtin", e.builtin());
            m.put("fields", fieldMeta(e.type()));
            out.add(m);
        }
        return out;
    }

    private static List<Map<String, Object>> fieldMeta(Class<?> type) {
        List<Map<String, Object>> fields = new ArrayList<>();
        for (Field f : type.getDeclaredFields()) {
            ProtocolField ann = f.getAnnotation(ProtocolField.class);
            if (ann == null) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", f.getName());
            m.put("order", ann.order());
            m.put("size", ann.size());
            m.put("type", f.getType().getSimpleName());
            fields.add(m);
        }
        fields.sort(Comparator.comparingInt(m -> (Integer) m.get("order")));
        return fields;
    }

    // ---- 采集 ----

    @GetMapping("/interfaces")
    public List<Map<String, String>> interfaces() throws Exception {
        List<Map<String, String>> out = new ArrayList<>();
        for (var nif : NetIfaces.list()) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("name", nif.getName());
            m.put("description", nif.getDescription() == null ? "" : nif.getDescription());
            out.add(m);
        }
        return out;
    }

    @PostMapping("/capture/start")
    public Map<String, Object> startCapture(@RequestBody Map<String, String> body) throws Exception {
        String iface = body.get("iface");
        if (iface == null || iface.isBlank()) {
            throw new IllegalArgumentException("iface is required");
        }
        capture.start(iface, body.get("bpf"));
        return capture.status();
    }

    @PostMapping("/capture/stop")
    public Map<String, Object> stopCapture() {
        capture.stop();
        return capture.status();
    }

    @GetMapping("/capture/status")
    public Map<String, Object> status() {
        return capture.status();
    }

    @GetMapping("/packets")
    public List<Map<String, Object>> packets(@RequestParam(defaultValue = "100") int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (DecodedPacket p : capture.recent(limit)) {
            out.add(toJson(p));
        }
        return out;
    }

    /** SSE 保活:定期发注释事件,防止代理/浏览器把空闲连接掐断。 */
    private final java.util.concurrent.ScheduledExecutorService sseKeepalive =
            java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "netproto-sse-keepalive");
                t.setDaemon(true);
                return t;
            });

    /** SSE 实时推送(事件名 packet,断线由浏览器自动重连;服务端每 15s 发 keepalive 注释)。 */
    @GetMapping(path = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream() {
        SseEmitter emitter = new SseEmitter(0L);
        Consumer<DecodedPacket> listener = p -> {
            try {
                emitter.send(SseEmitter.event().name("packet")
                        .data(objectMapper.writeValueAsString(toJson(p)), MediaType.APPLICATION_JSON));
            } catch (IOException e) {
                emitter.completeWithError(e);
            }
        };
        java.util.concurrent.ScheduledFuture<?> ping = sseKeepalive.scheduleAtFixedRate(() -> {
            try {
                emitter.send(SseEmitter.event().comment("keepalive"));
            } catch (Exception e) {
                emitter.completeWithError(e);
            }
        }, 15, 15, java.util.concurrent.TimeUnit.SECONDS);
        Runnable cleanup = () -> {
            capture.removeListener(listener);
            ping.cancel(false);
        };
        capture.addListener(listener);
        emitter.onCompletion(cleanup);
        emitter.onTimeout(cleanup);
        emitter.onError(x -> cleanup.run());
        return emitter;
    }

    @jakarta.annotation.PreDestroy
    void shutdownKeepalive() {
        sseKeepalive.shutdownNow();
    }

    // ---- 发包(原始以太网注入) ----

    /** {iface, layers:[{protocol:"my-app", fields:{…}}, …]} 外层→内层。byte[] 字段给 hex 字符串。 */
    @PostMapping("/send")
    public Map<String, Object> send(@RequestBody Map<String, Object> body) throws Exception {
        String iface = (String) body.get("iface");
        if (iface == null || iface.isBlank()) {
            throw new IllegalArgumentException("iface is required");
        }
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> layerSpecs = (List<Map<String, Object>>) body.get("layers");
        if (layerSpecs == null || layerSpecs.isEmpty()) {
            throw new IllegalArgumentException("layers is required (outer → inner)");
        }
        List<Object> layers = new ArrayList<>();
        for (Map<String, Object> spec : layerSpecs) {
            layers.add(bindLayer((String) spec.get("protocol"), (Map<String, Object>) spec.get("fields")));
        }
        int sent = sender.send(iface, layers);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "sent");
        out.put("bytes", sent);
        return out;
    }

    /** JSON 字段 → @Protocol POJO(byte[] 目标字段接受 hex 字符串)。 */
    @SuppressWarnings("unchecked")
    private Object bindLayer(String protocolId, Map<String, Object> fields) {
        if (protocolId == null) {
            throw new IllegalArgumentException("layer.protocol is required");
        }
        ProtocolRegistry.Entry entry = registry.get(protocolId);
        if (entry == null) {
            throw new IllegalArgumentException("unknown protocol: " + protocolId);
        }
        Map<String, Object> src = fields == null ? Map.of() : fields;
        Map<String, Object> prepared = new LinkedHashMap<>(src);
        // 便捷格式:byte[] 字段接受 hex 字符串(Jackson 默认 Base64,先转换);
        // *Mac 字段接受 "aa:bb:cc:dd:ee:ff";*Ip 字段接受点分十进制。
        for (Field f : entry.type().getDeclaredFields()) {
            Object v = prepared.get(f.getName());
            if (!(v instanceof String s)) {
                continue;
            }
            if (f.getType() == byte[].class) {
                prepared.put(f.getName(), Base64.getEncoder().encodeToString(hexToBytes(s)));
            } else if (f.getName().endsWith("Mac") && isMacLiteral(s)) {
                prepared.put(f.getName(), parseMac(s));
            } else if (f.getName().endsWith("Ip") && s.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                prepared.put(f.getName(), parseIp(s));
            }
        }
        return objectMapper.convertValue(prepared, entry.type());
    }

    private static boolean isMacLiteral(String s) {
        return s.matches("([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}");
    }

    static long parseMac(String mac) {
        long out = 0;
        for (String part : mac.split(":")) {
            out = (out << 8) | Long.parseLong(part, 16);
        }
        return out;
    }

    static int parseIp(String ip) {
        String[] parts = ip.split("\\.");
        int out = 0;
        for (String p : parts) {
            out = (out << 8) | (Integer.parseInt(p) & 0xFF);
        }
        return out;
    }

    static byte[] hexToBytes(String hex) {
        String h = hex.replace(" ", "").replace(":", "");
        if (h.length() % 2 != 0) {
            throw new IllegalArgumentException("hex string must have even length: " + hex);
        }
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    // ---- JSON 视图 ----

    Map<String, Object> toJson(DecodedPacket p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("seq", p.capturedCount());
        m.put("ts", p.timestampMillis());
        m.put("iface", p.iface());
        m.put("len", p.raw().length);
        m.put("path", p.protocolPath());
        List<Map<String, Object>> layers = new ArrayList<>();
        for (DecodedPacket.DecodedLayer l : p.layers()) {
            Map<String, Object> lm = new LinkedHashMap<>();
            lm.put("id", l.id());
            lm.put("name", l.name());
            lm.put("offset", l.offset());
            lm.put("headerLen", l.headerLength());
            lm.put("fields", LayerViews.fieldsOf(l.packet()));
            layers.add(lm);
        }
        m.put("layers", layers);
        m.put("hex", LayerViews.hex(p.raw(), 4096));
        return m;
    }
}
