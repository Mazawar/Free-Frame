package com.netproto.stack;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.Expr;
import com.netproto.core.FieldContext;
import com.netproto.core.PacketCodec;
import com.netproto.core.ProtocolCodec;

import java.util.*;

/**
 * 协议注册表(重设计版):id → 编解码器 + parent → 绑定列表(分派树)。
 * <p>
 * 注册期校验:id 唯一;@BindOn 的 parent 存在;when 标识符是父协议的 @ProtocolField 字段名;
 * 同父同优先级多绑定启动告警。实例化使用(非静态单例),Spring 装配为 bean;
 * 测试可用 {@link #create(Class[])}。
 */
public final class ProtocolRegistry {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ProtocolRegistry.class);

    /** 注册项:id/name/builtin/实体类型/编解码器。 */
    public record Entry(String id, String name, boolean builtin, Class<?> type, PacketCodec<?> codec) {}

    /** 一条分派绑定(parent 的某个子协议命中规则)。 */
    private record Binding(String childId, Expr.Node when, String rawWhen, int priority) {}

    private final Map<String, Entry> byId = new LinkedHashMap<>();
    private final Map<String, List<Binding>> children = new LinkedHashMap<>();

    public static ProtocolRegistry create(Class<?>... classes) {
        return create(Arrays.asList(classes));
    }

    public static ProtocolRegistry create(List<Class<?>> classes) {
        ProtocolRegistry r = new ProtocolRegistry();
        for (Class<?> c : classes) {
            r.register(c);
        }
        r.validateBindings();
        return r;
    }

    /** 注册一个 @Protocol 类(不校验绑定;全部注册完调用 validateBindings)。 */
    public void register(Class<?> clazz) {
        Protocol ann = clazz.getAnnotation(Protocol.class);
        if (ann == null) {
            throw new IllegalArgumentException(clazz.getName() + " is not annotated with @Protocol");
        }
        if (byId.containsKey(ann.id())) {
            throw new IllegalArgumentException(
                    "duplicate protocol id '" + ann.id() + "' (" + byId.get(ann.id()).type.getName()
                            + " vs " + clazz.getName() + ")");
        }
        PacketCodec<?> codec;
        if (ann.codec() != void.class) {
            codec = instantiateCustom(ann.codec(), ann.id());
        } else {
            codec = new ProtocolCodec<>(clazz);
        }
        byId.put(ann.id(), new Entry(ann.id(),
                ann.name().isEmpty() ? ann.id() : ann.name(), ann.builtin(), clazz, codec));
    }

    /** 全部注册后校验绑定关系并构建分派树(未知父/未知 when 标识符 → 启动失败)。 */
    public void validateBindings() {
        children.clear();
        for (Entry e : byId.values()) {
            for (BindOn b : e.type().getAnnotationsByType(BindOn.class)) {
                Entry parent = byId.get(b.parent());
                if (parent == null) {
                    throw new IllegalArgumentException(
                            "protocol '" + e.id + "' @BindOn references unknown parent '" + b.parent() + "'");
                }
                Expr.Node when = Expr.compile(b.when());  // 语法错误在此暴露
                Set<String> identNames = new LinkedHashSet<>();
                Expr.collectIdents(when, identNames);
                Set<String> parentFields = annotatedFieldNames(parent.type());
                for (String ident : identNames) {
                    if (!parentFields.contains(ident)) {
                        throw new IllegalArgumentException(
                                "protocol '" + e.id + "' @BindOn when '" + b.when()
                                        + "' references unknown parent field '" + ident + "'");
                    }
                }
                children.computeIfAbsent(b.parent(), k -> new ArrayList<>())
                        .add(new Binding(e.id(), when, b.when(), b.priority()));
            }
        }
        for (Map.Entry<String, List<Binding>> en : children.entrySet()) {
            List<Binding> list = en.getValue();
            list.sort(Comparator.comparingInt(Binding::priority).reversed());
            for (int i = 1; i < list.size(); i++) {
                if (list.get(i).priority() == list.get(i - 1).priority()) {
                    log.warn("protocols '{}' and '{}' both bind to parent '{}' with priority {}: {} wins (registration order)",
                            list.get(i - 1).childId, list.get(i).childId, en.getKey(), list.get(i).priority(),
                            list.get(i - 1).childId);
                }
            }
        }
    }

    /**
     * 求值 parent 的所有子绑定,返回命中的子协议 id;未命中返回 null。
     * 宽松模式:when 引用的父字段未解析(被条件跳过)时该绑定视为不命中。
     */
    public String matchChild(String parentId, Object parentObj) {
        List<Binding> bs = children.get(parentId);
        if (bs == null || bs.isEmpty()) {
            return null;
        }
        FieldContext ctx = contextOf(parentObj);
        for (Binding b : bs) {
            try {
                if (b.when.eval(name -> resolveLenient(ctx, name)) != 0) {
                    return b.childId;
                }
            } catch (Expr.UnknownIdentifier e) {
                // 父字段未解析:该绑定不命中,继续下一个
            }
        }
        return null;
    }

    /** 供 StackEncoder 选择子自动接线:parent→child 绑定的 when 提取「字段=常量」赋值。 */
    public Map<String, Long> autoWireAssignments(String parentId, String childId) {
        List<Binding> bs = children.get(parentId);
        if (bs != null) {
            for (Binding b : bs) {
                if (b.childId.equals(childId)) {
                    Map<String, Long> out = Expr.assignments(b.rawWhen);
                    if (out.isEmpty() && !b.rawWhen.isBlank()) {
                        log.warn("binding {}->{} when '{}' is not auto-wirable (needs manual selector fields)",
                                parentId, childId, b.rawWhen);
                    }
                    return out;
                }
            }
        }
        return Collections.emptyMap();
    }

    public Entry get(String id) {
        return byId.get(id);
    }

    /** 按实体类型反查注册项(StackEncoder 用)。 */
    public Optional<Entry> byType(Class<?> type) {
        return byId.values().stream().filter(e -> e.type == type).findFirst();
    }

    public Collection<Entry> all() {
        return Collections.unmodifiableCollection(byId.values());
    }

    public Set<String> ids() {
        return Collections.unmodifiableSet(byId.keySet());
    }

    // ---- 内部工具 ----

    private static PacketCodec<?> instantiateCustom(Class<?> codecClass, String id) {
        try {
            Object inst = codecClass.getDeclaredConstructor().newInstance();
            if (!(inst instanceof PacketCodec<?> pc)) {
                throw new IllegalArgumentException(
                        "@Protocol(codec=…) of '" + id + "' must implement PacketCodec");
            }
            return pc;
        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException(
                    "cannot instantiate codec " + codecClass.getName() + " for protocol '" + id
                            + "' (needs public no-arg ctor)", e);
        }
    }

    /** 收集一个类的 @ProtocolField + @Payload 字段名(when 标识符合法性校验用)。 */
    private static Set<String> annotatedFieldNames(Class<?> type) {
        Set<String> names = new LinkedHashSet<>();
        for (java.lang.reflect.Field f : type.getDeclaredFields()) {
            if (f.isAnnotationPresent(ProtocolField.class) || f.isAnnotationPresent(Payload.class)) {
                names.add(f.getName());
            }
        }
        return names;
    }

    /** 已解析对象的字段视图(matchChild 求值用)。 */
    static FieldContext contextOf(Object obj) {
        FieldContext ctx = FieldContext.create(obj);
        for (java.lang.reflect.Field f : obj.getClass().getDeclaredFields()) {
            if (f.isAnnotationPresent(ProtocolField.class) || f.isAnnotationPresent(Payload.class)) {
                f.setAccessible(true);
                try {
                    ctx.put(f.getName(), f.get(obj));
                } catch (IllegalAccessException e) {
                    throw new IllegalStateException("cannot read field " + f.getName(), e);
                }
            }
        }
        return ctx;
    }

    private static long resolveLenient(FieldContext ctx, String name) {
        // 位索引标识符 name[n](与 presentIf 侧同款一等语法)
        Long bit = Expr.resolveBitIndex(n -> ctx.hasRead(n) ? ctx.get(n) : null, name);
        if (bit != null) {
            return bit;
        }
        if (!ctx.hasRead(name)) {
            throw new Expr.UnknownIdentifier(name);
        }
        Object v = ctx.get(name);
        if (v instanceof Number n) {
            return n.longValue();
        }
        if (v instanceof Boolean b) {
            return b ? 1 : 0;
        }
        throw new Expr.UnknownIdentifier(name + " (non-numeric)");
    }
}
