package com.netproto.spring.web;

import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.spring.capture.CaptureSession;
import com.netproto.spring.capture.FrameSummary;
import com.netproto.spring.capture.NetIfaces;
import com.netproto.spring.capture.PcapFile;
import com.netproto.spring.capture.RawSender;
import com.netproto.spring.capture.SessionManager;
import com.netproto.stack.DecodedPacket;
import com.netproto.stack.ProtocolRegistry;
import com.netproto.stack.StackEncoder;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
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
    private final SessionManager sessions;
    private final RawSender sender;
    private final StackEncoder encoder;
    private final ObjectMapper objectMapper;
    private final com.netproto.spring.config.NetprotoProperties props;

    public NetprotoController(ProtocolRegistry registry, SessionManager sessions, RawSender sender,
                              StackEncoder encoder, ApplicationContext appContext,
                              com.netproto.spring.config.NetprotoProperties props) {
        this.registry = registry;
        this.sessions = sessions;
        this.sender = sender;
        this.encoder = encoder;
        this.props = props;
        this.objectMapper = appContext.getBeanProvider(ObjectMapper.class).getIfAvailable(ObjectMapper::new);
    }

    /** 运行配置只读视图(前端按它适配显示,如缓冲上限跟随 ring-size)。 */
    @GetMapping("/config")
    public Map<String, Object> config() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("rootProtocol", props.getRootProtocol());
        m.put("ringSize", props.getRingSize());
        m.put("ringBytes", props.getRingBytes().toBytes());
        m.put("snaplen", props.getSnaplen());
        return m;
    }

    // ---- 协议元数据 ----

    @GetMapping("/protocols")
    public List<Map<String, Object>> protocols() {
        // 三分类:element=被 LIST elementClass/TLV dispatch 引用的实体;
        // stack=挂 @BindOn 或被引用为 parent(树根);island=其余(不参与以太网分派)
        Set<Class<?>> elementClasses = new HashSet<>();
        Set<String> parentIds = new HashSet<>();
        for (ProtocolRegistry.Entry e : registry.all()) {
            for (com.netproto.annotation.BindOn b :
                    e.type().getAnnotationsByType(com.netproto.annotation.BindOn.class)) {
                parentIds.add(b.parent());
            }
            for (Field f : e.type().getDeclaredFields()) {
                ProtocolField ann = f.getAnnotation(ProtocolField.class);
                if (ann == null) {
                    continue;
                }
                if (ann.elementClass() != void.class) {
                    elementClasses.add(ann.elementClass());
                }
                for (String d : ann.dispatch()) {
                    Class<?> c = resolveDispatchEntity(d.substring(d.indexOf('=') + 1), e.type());
                    if (c != null) {
                        elementClasses.add(c);
                    }
                }
            }
        }
        List<Map<String, Object>> out = new ArrayList<>();
        // 组路径推导:子协议 group 只声明自己的子组,完整路径 = 沿 @BindOn 父链收集各级 group
        // (如 pd-reg"接入管理" → pd"智能配电" → ["智能配电","接入管理"]);跳过空组名。
        // 以数组传输而非拼接字符串:组名含任意字符(包括 '/' )都不会破坏层级结构,
        // 深度不限(父链环由 visited 防护)。
        Map<String, List<String>> parentsByChild = new HashMap<>();
        Map<String, String> groupById = new HashMap<>();
        for (ProtocolRegistry.Entry e : registry.all()) {
            Protocol ann = e.type().getAnnotation(Protocol.class);
            groupById.put(e.id(), ann != null ? ann.group() : "");
            List<String> parents = new ArrayList<>();
            for (com.netproto.annotation.BindOn b :
                    e.type().getAnnotationsByType(com.netproto.annotation.BindOn.class)) {
                parents.add(b.parent());
                parentIds.add(b.parent());
            }
            parentsByChild.put(e.id(), parents);
        }
        for (ProtocolRegistry.Entry e : registry.all()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", e.id());
            m.put("name", e.name());
            m.put("builtin", e.builtin());
            m.put("groupPath", deriveGroupSegments(parentsByChild, groupById, e.id()));
            m.put("fields", fieldMeta(e.type()));
            String category;
            Protocol ann = e.type().getAnnotation(Protocol.class);
            if (ann != null && ann.internal()) {
                category = "internal";   // 公共头/中间产物:不进侧栏、不参与命中、不进发包目标
            } else if (elementClasses.contains(e.type())) {
                category = "element";
                // 可重复 @BindOn 多实例时 isAnnotationPresent 返回 false,须用 getAnnotationsByType
            } else if (e.type().getAnnotationsByType(com.netproto.annotation.BindOn.class).length > 0
                    || parentIds.contains(e.id())) {
                category = "stack";
            } else {
                category = "island";
            }
            m.put("category", category);
            out.add(m);
        }
        return out;
    }

    /** 组路径推导:沿 @BindOn 父链收集各级非空 group,自己最里层;返回段数组(不拼接,防特殊字符);
     *  环与多父(取第一个)安全,深度不限。 */
    private static List<String> deriveGroupSegments(Map<String, List<String>> parentsByChild,
                                                    Map<String, String> groupById, String id) {
        java.util.LinkedList<String> parts = new java.util.LinkedList<>();
        java.util.Set<String> visited = new java.util.HashSet<>();
        String cur = id;
        while (cur != null && visited.add(cur)) {
            String g = groupById.getOrDefault(cur, "");
            if (!g.isEmpty()) {
                parts.addFirst(g);
            }
            List<String> ps = parentsByChild.get(cur);
            cur = ps == null || ps.isEmpty() ? null : ps.get(0);
        }
        return parts;
    }

    /** TLV dispatch 目标类:简单名按声明类所在包解析,全限定名直接加载;找不到忽略。 */
    private static Class<?> resolveDispatchEntity(String cls, Class<?> declaring) {
        try {
            if (cls.contains(".")) {
                return Class.forName(cls);
            }
            return Class.forName(declaring.getPackage().getName() + "." + cls);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    /**
     * 发包模板生成:GET /template?path=mqtt-connect → 按分派树推导祖先链
     * (ethernet▸ipv4▸tcp▸mqtt-connect)并实例化各层 POJO 取字段默认值。
     * 只给「用户可填」的字段值;长度/计数/校验和等编码期自动的字段省略(编码器会补)。
     */
    @GetMapping("/template")
    public Map<String, Object> template(@RequestParam String path) throws Exception {
        String[] ids = path.split(",");
        for (String id : ids) {
            if (registry.get(id.trim()) == null) {
                throw new IllegalArgumentException("unknown protocol: " + id);
            }
        }
        // 从最深层向上推导祖先:每层取一条 @BindOn 链回溯到根,去重
        LinkedHashSet<String> chain = new LinkedHashSet<>();
        for (String id : ids) {
            for (String anc : ancestorsOf(id.trim(), new java.util.ArrayDeque<>())) {
                chain.add(anc);
            }
            chain.add(id.trim());
        }
        List<Map<String, Object>> layers = new ArrayList<>();
        for (String id : chain) {
            ProtocolRegistry.Entry e = registry.get(id);
            Map<String, Object> layer = new LinkedHashMap<>();
            layer.put("protocol", id);
            layer.put("fields", templateFields(e.type().getDeclaredConstructor().newInstance()));
            layers.add(layer);
        }
        return Map.of("layers", layers);
    }

    /** 回溯协议到根的祖先序列(根在前);多条绑定取注册顺序第一条,环/超深防御 32 层。 */
    private List<String> ancestorsOf(String id, java.util.Deque<String> seen) {
        ProtocolRegistry.Entry e = registry.get(id);
        if (e == null || seen.contains(id) || seen.size() > 32) {
            return List.of();
        }
        seen.push(id);
        try {
            com.netproto.annotation.BindOn[] binds =
                    e.type().getAnnotationsByType(com.netproto.annotation.BindOn.class);
            if (binds.length == 0) {
                return List.of();
            }
            List<String> out = new ArrayList<>(ancestorsOf(binds[0].parent(), seen));
            out.add(binds[0].parent());
            return out;
        } finally {
            seen.pop();
        }
    }

    /** 实例化对象的字段默认值。排除:被本层其他字段引用的长度/计数指示字段(编码器算)、
     *  校验和、payload;带 lengthField 的变长内容字段(如 LLVAR 的 PAN)保留给用户填。 */
    private static Map<String, Object> templateFields(Object instance) {
        // 收集被引用的指示字段名(lengthField/countField 指向谁,谁就是自动的)
        java.util.Set<String> indicators = new java.util.HashSet<>();
        for (Field f : instance.getClass().getDeclaredFields()) {
            ProtocolField ann = f.getAnnotation(ProtocolField.class);
            if (ann == null) {
                continue;
            }
            if (!ann.lengthField().isEmpty()) {
                indicators.add(ann.lengthField());
            }
            if (!ann.countField().isEmpty()) {
                indicators.add(ann.countField());
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Field f : instance.getClass().getDeclaredFields()) {
            ProtocolField ann = f.getAnnotation(ProtocolField.class);
            if (ann == null || f.isAnnotationPresent(Payload.class)
                    || f.isAnnotationPresent(com.netproto.annotation.ChecksumField.class)
                    || indicators.contains(f.getName())) {
                continue;
            }
            f.setAccessible(true);
            Object v;
            try {
                v = f.get(instance);
            } catch (IllegalAccessException ex) {
                continue;
            }
            if (v instanceof byte[] || v instanceof java.util.List || v instanceof java.util.Set) {
                continue;   // 列表/字节载荷留空,由用户按需填
            }
            out.put(f.getName(), v);
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
            if (!ann.group().isEmpty()) {
                m.put("group", ann.group());
            }
            if (!ann.label().isEmpty()) {
                m.put("label", ann.label());
            }
            // 动态模板所需的注解元数据(透传,前端表单据此显隐/自动算/锁灰)
            if (!ann.presentIf().isEmpty()) {
                m.put("presentIf", ann.presentIf());
            }
            if (!ann.lengthField().isEmpty()) {
                m.put("lengthField", ann.lengthField());
                m.put("lengthUnit", ann.lengthUnit().name());
                m.put("lengthAdjust", ann.lengthAdjust());
            }
            if (!ann.countField().isEmpty()) {
                m.put("countField", ann.countField());
                m.put("countUnit", ann.countUnit().name());
            }
            if (ann.lengthAscii()) {
                m.put("lengthAscii", true);
            }
            if (!ann.elementClass().equals(void.class)) {
                m.put("elementClass", ann.elementClass().getSimpleName());
            }
            if (f.isAnnotationPresent(com.netproto.annotation.ChecksumField.class)) {
                m.put("checksum", true);
            }
            if (f.isAnnotationPresent(com.netproto.annotation.Payload.class)) {
                m.put("payload", true);
            }
            // 位标志字段:暴露每个标志的掩码(Wireshark 式逐位展开的依据),按掩码降序 = 树中高位在前
            if (ann.flagClass() != void.class) {
                List<Map<String, Object>> flags = new ArrayList<>();
                for (Object c : ann.flagClass().getEnumConstants()) {
                    if (c instanceof com.netproto.core.ProtocolFlag pf) {
                        flags.add(Map.of("name", ((Enum<?>) c).name(), "mask", pf.mask()));
                    }
                }
                flags.sort((a, b) -> Integer.compare((Integer) b.get("mask"), (Integer) a.get("mask")));
                m.put("flagClass", ann.flagClass().getSimpleName());
                m.put("flags", flags);
            }
            fields.add(m);
        }
        fields.sort(Comparator.comparingInt(m -> (Integer) m.get("order")));
        return fields;
    }

    // ---- 采集:旧端点(全部落在 default 会话上,路径/入参/返回结构不变,前端零改动) ----

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
        String iface = requiredIface(body);
        CaptureSession def = sessions.defaultSession();
        if (def.isRunning()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "capture already running on " + def.iface() + " — stop it first"
                            + " (parallel captures: POST /sessions)");
        }
        def.start(iface, body.get("bpf"));
        return def.status();
    }

    @PostMapping("/capture/stop")
    public Map<String, Object> stopCapture() {
        CaptureSession def = sessions.defaultSession();
        def.stop();
        return def.status();
    }

    @GetMapping("/capture/status")
    public Map<String, Object> status() {
        return sessions.defaultSession().status();
    }

    @GetMapping("/packets")
    public List<Map<String, Object>> packets(@RequestParam(defaultValue = "100") int limit) {
        return packetRows(sessions.defaultSession(), limit);
    }

    /** 单帧完整详情(树/字段/字节区间/hex):摘要不常驻解析树,按需重解码(Wireshark 点击时解析)。 */
    @GetMapping("/packet/{seq}")
    public ResponseEntity<Map<String, Object>> packetDetail(@PathVariable long seq) {
        return packetDetail(sessions.defaultSession(), seq);
    }

    // ---- 多会话采集(每会话独立网卡句柄/BPF/缓冲/序号:多页面并行抓不同包) ----

    /** 全部会话状态(default 在前),含各自丢帧计数。 */
    @GetMapping("/sessions")
    public List<Map<String, Object>> listSessions() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (CaptureSession s : sessions.all()) {
            out.add(s.status());
        }
        return out;
    }

    /** 会话注册端点:带 iface = 创建/重启并启动采集;只带 id = 空闲注册(页面加载即占位,
     *  不启动采集);都不带 = 400。无 id 时后端自动命名(s1、s2…)。 */
    @PostMapping("/sessions")
    public Map<String, Object> createSession(@RequestBody Map<String, String> body) throws Exception {
        String id = body.get("id");
        String iface = body.get("iface");
        if (iface == null || iface.isBlank()) {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException("iface is required (or pass id to idle-register)");
            }
            return sessions.registerIdle(id.trim()).status();
        }
        if (id != null && !id.isBlank()) {
            id = id.trim();
            CaptureSession existing = sessions.get(id);
            if (existing != null && existing.isRunning()) {
                throw new ResponseStatusException(HttpStatus.CONFLICT,
                        "session '" + id + "' already running on " + existing.iface() + " — stop it first");
            }
            return sessions.register(id, iface, body.get("bpf")).status();
        }
        if (!sessions.canCreate()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "session limit reached (" + sessions.maxSessions()
                            + ") — delete one first: DELETE /api/netproto/sessions/{id}");
        }
        return sessions.create(iface, body.get("bpf")).status();
    }

    /** 重启已有会话(页面稳定会话模型:同一页面反复「采集」复用同一会话,
     *  启停是会话内操作;缓冲清空、序号从 1 重新计数)。 */
    @PostMapping("/sessions/{id}/start")
    public Map<String, Object> startSession(@PathVariable String id,
                                            @RequestBody Map<String, String> body) throws Exception {
        String iface = requiredIface(body);
        CaptureSession s = sessionOr404(id);
        if (s.isRunning()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "session '" + id + "' already running on " + s.iface() + " — stop it first");
        }
        s.start(iface, body.get("bpf"));
        return s.status();
    }

    @GetMapping("/sessions/{id}/status")
    public Map<String, Object> sessionStatus(@PathVariable String id) {
        return sessionOr404(id).status();
    }

    @PostMapping("/sessions/{id}/stop")
    public Map<String, Object> stopSession(@PathVariable String id) {
        CaptureSession s = sessionOr404(id);
        s.stop();
        return s.status();
    }

    /** 删除会话:停止并释放缓冲;SSE 订阅端先收到 session-closed 事件再断开。
     *  default 也可删——旧端点下次调用会懒重建。 */
    @DeleteMapping("/sessions/{id}")
    public Map<String, Object> deleteSession(@PathVariable String id) {
        if (!sessions.delete(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown session: " + id);
        }
        return Map.of("sessionId", id, "status", "deleted");
    }

    @GetMapping("/sessions/{id}/packets")
    public List<Map<String, Object>> sessionPackets(@PathVariable String id,
                                                    @RequestParam(defaultValue = "100") int limit) {
        return packetRows(sessionOr404(id), limit);
    }

    @GetMapping("/sessions/{id}/packet/{seq}")
    public ResponseEntity<Map<String, Object>> sessionPacketDetail(@PathVariable String id,
                                                                   @PathVariable long seq) {
        return packetDetail(sessionOr404(id), seq);
    }

    /** 会话版 SSE(事件格式与 /stream 完全一致;会话删除时发 session-closed 后断开)。 */
    @GetMapping(path = "/sessions/{id}/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter sessionStream(@PathVariable String id) {
        return openStream(sessionOr404(id));
    }

    @PostMapping("/sessions/{id}/inject")
    public Map<String, Object> sessionInject(@PathVariable String id,
                                             @RequestBody Map<String, String> body) {
        return injectBody(sessionOr404(id), body);
    }

    @GetMapping("/sessions/{id}/export")
    public ResponseEntity<byte[]> sessionExport(@PathVariable String id) {
        return exportPcap(sessionOr404(id));
    }

    @PostMapping("/sessions/{id}/import")
    public Map<String, Object> sessionImport(@PathVariable String id,
                                             @RequestParam("file") MultipartFile file) throws IOException {
        return importPcap(sessionOr404(id), file);
    }

    private CaptureSession sessionOr404(String id) {
        CaptureSession s = sessions.get(id);
        if (s == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown session: " + id);
        }
        return s;
    }

    private static String requiredIface(Map<String, String> body) {
        String iface = body.get("iface");
        if (iface == null || iface.isBlank()) {
            throw new IllegalArgumentException("iface is required");
        }
        return iface;
    }

    private static List<Map<String, Object>> packetRows(CaptureSession session, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (FrameSummary s : session.recent(limit)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("seq", s.seq());
            m.put("ts", s.ts());
            m.put("iface", s.iface());
            m.put("len", s.len());
            m.put("path", s.path());
            m.put("layerIds", s.layerIds());
            m.put("src", s.src());
            m.put("dst", s.dst());
            m.put("srcPort", s.srcPort());
            m.put("dstPort", s.dstPort());
            m.put("info", s.info());
            out.add(m);
        }
        return out;
    }

    private ResponseEntity<Map<String, Object>> packetDetail(CaptureSession session, long seq) {
        DecodedPacket p = session.detail(seq);
        return p == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(toJson(p));
    }

    /** SSE 保活调度:只往各连接队列投 keepalive 标记,实际发送由各连接的写线程完成。 */
    private final ScheduledExecutorService sseKeepalive =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "netproto-sse-keepalive");
                t.setDaemon(true);
                return t;
            });

    private static final Object KEEPALIVE = new Object();

    /** 会话删除信号:写线程收到后发 session-closed 事件并收尾(与数据同通道,天然串行)。 */
    private static final Object SESSION_CLOSED = new Object();

    /**
     * SSE 实时推送(事件名 packet,断线由浏览器自动重连;服务端每 15s 发具名 ping 事件)。
     * 旧端点:固定订阅 default 会话。
     * <p>
     * 推送轻量 {@link FrameSummary}(单帧约两百字节,不含协议树/hex);
     * 详情由前端点击时经 GET /packet/{seq} 按需拉取。
     * 发送绝不跑在抓包/解码线程上:监听器只往有界队列投递,每连接一个单写线程串行发送
     * (包 + ping 同通道,SseEmitter 并发 send 非线程安全)。队列满则丢弃本连接的
     * 新帧——冻结/慢速的浏览器只丢自己的画面,不会把背压传导回采集管线。
     * <p>
     * ping 是具名事件(非注释):前端可见并以此驱动看门狗——连接因任何原因静默
     * (半开 socket/清理竞态/中间层吞流)超过两个周期,浏览器强制断开重连,自愈。
     * 会话被 DELETE 时订阅端先收到 session-closed 再断开。
     */
    @GetMapping(path = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream() {
        return openStream(sessions.defaultSession());
    }

    /** 会话版 SSE:GET /sessions/{id}/stream(事件格式与 /stream 完全一致)。 */
    private SseEmitter openStream(CaptureSession session) {
        SseEmitter emitter = new SseEmitter(0L);
        BlockingQueue<Object> queue = new ArrayBlockingQueue<>(2048);
        var writer = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "netproto-sse-writer");
            t.setDaemon(true);
            return t;
        });
        ScheduledFuture<?> ping = sseKeepalive.scheduleAtFixedRate(
                () -> queue.offer(KEEPALIVE), 15, 15, TimeUnit.SECONDS);
        Consumer<FrameSummary> listener = queue::offer;
        Runnable closeCallback = () -> queue.offer(SESSION_CLOSED);
        var closed = new java.util.concurrent.atomic.AtomicBoolean(false);
        Runnable cleanup = () -> {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            session.removeListener(listener);
            session.removeCloseCallback(closeCallback);
            ping.cancel(false);
            writer.shutdownNow();
        };
        writer.execute(() -> {
            try {
                while (true) {
                    Object item = queue.take();
                    if (item == SESSION_CLOSED) {
                        emitter.send(SseEmitter.event().name("session-closed"));
                        emitter.complete();
                        return;
                    }
                    if (item instanceof FrameSummary s) {
                        emitter.send(SseEmitter.event().name("packet")
                                .data(objectMapper.writeValueAsString(s), MediaType.APPLICATION_JSON));
                    } else {
                        emitter.send(SseEmitter.event().name("ping"));
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();   // 清理路径:连接关闭,正常退出
            } catch (Exception e) {
                emitter.completeWithError(e);
            } finally {
                cleanup.run();
            }
        });
        session.addListener(listener);
        session.addCloseCallback(closeCallback);
        queue.offer(KEEPALIVE);   // 立即一个 ping:提前落响应头,空闲会话的浏览器 onopen 不用等 15s 首个周期
        emitter.onCompletion(cleanup);
        emitter.onTimeout(cleanup);
        emitter.onError(x -> cleanup.run());
        return emitter;
    }

    @jakarta.annotation.PreDestroy
    void shutdownKeepalive() {
        sseKeepalive.shutdownNow();
    }

    /** 参数/文件校验类错误 → 400 + 明确原因(如 pcap 导入的非法文件信息)。 */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }

    /** 发包被系统/驱动拒绝 → 502 + 可行动的原因(权限/Wi-Fi 限制等)。 */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, String>> sendRejected(IllegalStateException e) {
        return ResponseEntity.status(502).body(Map.of("error", e.getMessage()));
    }

    // ---- 报文注入(不经过网卡:直接进解析+展示管线) ----

    /** {hex: "aa bb ..", iface?: "inject"} 注入原始字节帧,页面经 SSE 实时看到解析结果。 */
    @PostMapping("/inject")
    public Map<String, Object> inject(@RequestBody Map<String, String> body) {
        return injectBody(sessions.defaultSession(), body);
    }

    private Map<String, Object> injectBody(CaptureSession session, Map<String, String> body) {
        String hex = body.getOrDefault("hex", "").replace(" ", "").replace("\n", "");
        if (hex.isEmpty() || (hex.length() & 1) != 0) {
            throw new IllegalArgumentException("hex is required (even-length hex string)");
        }
        byte[] raw = new byte[hex.length() / 2];
        try {
            for (int i = 0; i < raw.length; i++) {
                raw[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("hex contains non-hex characters");
        }
        session.inject(body.getOrDefault("iface", "inject"), raw);
        return Map.of("status", "injected", "bytes", raw.length);
    }

    // ---- pcap 导出/导入(与 tcpdump/Wireshark 互通) ----

    /** 导出环形缓冲(旧→新)为标准 pcap,Ethernet 链路;文件名带会话与帧数。 */
    @GetMapping("/export")
    public ResponseEntity<byte[]> exportPcap() {
        return exportPcap(sessions.defaultSession());
    }

    private ResponseEntity<byte[]> exportPcap(CaptureSession session) {
        List<FrameSummary> newest = session.recent(Integer.MAX_VALUE);   // 新→旧
        List<PcapFile.Record> records = new ArrayList<>(newest.size());
        for (int i = newest.size() - 1; i >= 0; i--) {
            FrameSummary s = newest.get(i);
            records.add(new PcapFile.Record(s.ts(), s.raw()));
        }
        String ts = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss").format(new java.util.Date());
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header("Content-Disposition",
                        "attachment; filename=netproto-" + session.id() + "-"
                                + records.size() + "f-" + ts + ".pcap")
                .body(PcapFile.write(records));
    }

    /** pcap 导入大小上限:multipart 超过该值直接拒绝,防超大文件占住容器临时目录。 */
    private static final int MAX_IMPORT_BYTES = 64 * 1024 * 1024;

    /** 导入 pcap(仅以太网链路):「打开文件」语义——先清空环形缓冲再注入,时间戳取文件内原始值。
     *  采集运行中拒绝(seq 会与导入帧冲突)。 */
    @PostMapping("/import")
    public Map<String, Object> importPcap(@RequestParam("file") MultipartFile file) throws IOException {
        return importPcap(sessions.defaultSession(), file);
    }

    private Map<String, Object> importPcap(CaptureSession session, MultipartFile file) throws IOException {
        if (session.isRunning()) {
            throw new IllegalArgumentException("capture is running: stop it before importing a pcap");
        }
        if (file.getSize() > MAX_IMPORT_BYTES) {
            throw new IllegalArgumentException("pcap too large: " + file.getSize()
                    + " bytes (max " + MAX_IMPORT_BYTES + ")");
        }
        List<PcapFile.Record> records = PcapFile.read(file.getBytes());
        String source = file.getOriginalFilename() == null || file.getOriginalFilename().isBlank()
                ? "import" : file.getOriginalFilename();
        session.reset();
        for (PcapFile.Record r : records) {
            session.inject(source, r.raw(), r.tsMillis());
        }
        return Map.of("imported", records.size());
    }

    // ---- 发包(原始以太网注入) ----

    /** {iface, layers:[{protocol:"modbus", fields:{…}}, …]} 外层→内层。byte[] 字段给 hex 字符串。 */
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
        int sent;
        try {
            sent = sender.send(iface, layers);
        } catch (org.pcap4j.core.PcapNativeException e) {
            // Windows 上最常见原因:Npcap 管理员限制 / Wi-Fi 网卡拒绝裸帧注入(错误 31)
            throw new IllegalStateException("发包被系统拒绝:" + e.getMessage()
                    + "。常见原因:①应用未以管理员身份运行(Npcap 默认限制发包权限);"
                    + "②Wi-Fi 网卡通常不支持原始帧注入,建议改用有线网卡。", e);
        }
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
            // 只输出真实解析到的字段:presentIf 缺席的字段引擎不读字节、无区间,
            // 对象里留的是 Java 默认值(0/空串),展示出来是假值
            Map<String, Object> fields = LayerViews.fieldsOf(l.packet());
            fields.keySet().removeIf(k -> !l.fieldRanges().containsKey(k));
            lm.put("fields", fields);
            lm.put("ranges", l.fieldRanges());
            lm.put("bitRanges", l.bitRanges());
            layers.add(lm);
        }
        m.put("layers", layers);
        m.put("hex", LayerViews.hex(p.raw(), 4096));
        return m;
    }
}
