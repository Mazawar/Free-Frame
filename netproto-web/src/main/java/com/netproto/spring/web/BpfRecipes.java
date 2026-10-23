package com.netproto.spring.web;

import com.netproto.annotation.BindOn;
import com.netproto.stack.ProtocolRegistry;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 协议配方推导:从 {@code @BindOn.when} 提取可直接使用的 BPF 过滤表达式 ——
 * 以太网 EtherType 分派 → {@code ether proto 0xNNNN};TCP/UDP 端口分派 → {@code udp port N}。
 * 提示与注册表同源:新协议上线,配方自动跟进,无需手维护清单。
 * <p>
 * 只推导「when 全部条件都能落进一个 BPF 表达式」的绑定(字段全是 etherType 或全是
 * 同值 src/dstPort);混合条件(如 dstPort==9000 && foo==1)、业务头内选择子
 * (如 signalType)BPF 表达不了,不推导 —— 宁缺毋滥,提示必须是真等效的。
 */
final class BpfRecipes {

    private BpfRecipes() {}

    /** 字段 == 字面量(0x 十六进制或十进制);when 由 {@code Expr} 保证此形态可解析。 */
    private static final Pattern EQ = Pattern.compile("(\\w+)\\s*==\\s*(0x[0-9a-fA-F]+|\\d+)");

    /** 上限防下拉刷屏;正常协议栈(EtherType+端口合计)远达不到。 */
    private static final int MAX_RECIPES = 32;

    static List<Map<String, Object>> from(ProtocolRegistry registry) {
        Map<String, Map<String, Object>> byExpr = new LinkedHashMap<>();
        for (ProtocolRegistry.Entry e : registry.all()) {
            for (BindOn b : e.type().getAnnotationsByType(BindOn.class)) {
                literal(b.when(), "etherType").ifPresent(v ->
                        add(byExpr, "ether proto 0x" + String.format("%04X", v), e.name(), e.builtin()));
                if (b.parent().equals("tcp") || b.parent().equals("udp")) {
                    literal(b.when(), "srcPort", "dstPort").ifPresent(v ->
                            add(byExpr, b.parent() + " port " + v, e.name(), e.builtin()));
                }
            }
        }
        return new ArrayList<>(byExpr.values());
    }

    /** when 的全部等值条件字段都在 fields 内且字面量同值 → 返回该值;否则 empty(推导不动)。 */
    private static java.util.OptionalInt literal(String when, String... fields) {
        Matcher m = EQ.matcher(when);
        int value = -1;
        boolean any = false;
        while (m.find()) {
            String field = m.group(1);
            boolean known = false;
            for (String f : fields) {
                known |= f.equals(field);
            }
            if (!known) {
                return java.util.OptionalInt.empty();
            }
            int v = m.group(2).startsWith("0x") || m.group(2).startsWith("0X")
                    ? Integer.parseInt(m.group(2).substring(2), 16)
                    : Integer.parseInt(m.group(2));
            if (any && v != value) {
                return java.util.OptionalInt.empty();
            }
            value = v;
            any = true;
        }
        return any ? java.util.OptionalInt.of(value) : java.util.OptionalInt.empty();
    }

    private static void add(Map<String, Map<String, Object>> byExpr, String expr,
                            String label, boolean builtin) {
        if (byExpr.containsKey(expr) || byExpr.size() >= MAX_RECIPES) {
            return;
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("expr", expr);
        m.put("label", label);
        m.put("builtin", builtin);
        byExpr.put(expr, m);
    }
}
