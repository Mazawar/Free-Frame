package com.netproto.core;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 条件表达式小语言(presentIf 与 @BindOn.when 共用)。
 * <p>
 * 文法(手写递归下降,非 SpEL——无方法调用、无赋值、确定性、可 AOT):
 * <pre>
 * orExpr  := andExpr ('||' andExpr)*
 * andExpr := unary ('&&' unary)*
 * unary   := '!' unary | cmp
 * cmp     := operand (('=='|'!='|'<'|'<='|'>'|'>=') operand)?
 * operand := '(' orExpr ')' | ident | [-]int(十进制|0xHH)
 * </pre>
 * 标识符由 Resolver 解析为 long。裸标识符/裸括号式按「非零为真」。
 * <p>
 * 严格模式(presentIf):未知标识符抛 IllegalArgumentException(注册期已校验存在,
 * 运行期出现说明字段被条件跳过,属协议定义错误)。
 * 宽松模式(@BindOn.when):未解析字段使整个表达式为 false,不抛异常。
 */
public final class Expr {

    private Expr() {}

    /** 标识符 → 数值的解析函数。未知标识符抛 {@link UnknownIdentifier}。 */
    public interface Resolver {
        long value(String name);
    }

    /** 宽松模式下未知/未解析标识符的内部信号。 */
    public static final class UnknownIdentifier extends RuntimeException {
        public final String name;

        public UnknownIdentifier(String name) {
            super("unknown or unread field: " + name);
            this.name = name;
        }
    }

    /** 编译表达式为 AST(语法错误立即抛出,注册期用)。 */
    public static Node compile(String expr) {
        Parser p = new Parser(expr);
        p.skipWs();
        if (p.eof()) {
            throw new IllegalArgumentException("empty expression");
        }
        Node n = p.orExpr();
        p.skipWs();
        if (!p.eof()) {
            throw new IllegalArgumentException("unexpected trailing input at " + p.pos + " in: " + expr);
        }
        return n;
    }

    /** 便捷入口:编译并求值。 */
    public static boolean eval(String expr, Resolver resolver, boolean lenient) {
        if (expr == null || expr.isBlank()) {
            return true;
        }
        Node node = compile(expr);
        return evalNode(node, resolver, lenient);
    }

    private static boolean evalNode(Node node, Resolver resolver, boolean lenient) {
        try {
            return node.eval(resolver) != 0;
        } catch (UnknownIdentifier e) {
            if (lenient) {
                return false;
            }
            throw new IllegalArgumentException(e.getMessage() + " (in expression)", e);
        }
    }

    /** 求值接口(长整型,非零为真)。 */
    public interface Node {
        long eval(Resolver r);
    }

    /** 递归收集 AST 中的全部标识符(注册期校验 when 引用的字段存在)。 */
    /**
     * 解析位索引标识符 "name[n]":按 lookup 取字段值,返回从最高有效位起第 n 位(0/1)。
     * 位宽按 Java 装箱类型(Integer=32/Long=64/Short=16/Byte=8,其余 Number 按 64)。
     * name 不是位索引语法时返回 null;字段不存在抛 UnknownIdentifier,非数值抛异常。
     */
    public static Long resolveBitIndex(java.util.function.Function<String, Object> lookup, String ident) {
        int lb = ident.indexOf('[');
        if (lb < 0 || !ident.endsWith("]") || ident.indexOf(']', lb) != ident.length() - 1) {
            return null;
        }
        String base = ident.substring(0, lb);
        int bit;
        try {
            bit = Integer.parseInt(ident.substring(lb + 1, ident.length() - 1));
        } catch (NumberFormatException e) {
            return null;
        }
        Object v = lookup.apply(base);
        if (v == null) {
            throw new UnknownIdentifier(base);
        }
        long raw;
        int width;
        if (v instanceof Long l) {
            raw = l;
            width = 64;
        } else if (v instanceof Integer i) {
            raw = i;
            width = 32;
        } else if (v instanceof Short h) {
            raw = h;
            width = 16;
        } else if (v instanceof Byte b) {
            raw = b;
            width = 8;
        } else if (v instanceof java.lang.Number n) {
            raw = n.longValue();
            width = 64;
        } else {
            throw new UnknownIdentifier(base + " (non-numeric)");
        }
        if (bit < 1 || bit > width) {
            throw new IllegalArgumentException(ident + ": bit index out of range (1-" + width + ")");
        }
        return (raw >>> (width - bit)) & 1L;
    }

    public static void collectIdents(Node n, java.util.Set<String> out) {
        if (n instanceof Ident i) {
            out.add(i.name());
        } else if (n instanceof Not x) {
            collectIdents(x.inner(), out);
        } else if (n instanceof Unary u) {
            collectIdents(u.left(), out);
            collectIdents(u.right(), out);
        } else if (n instanceof And a) {
            collectIdents(a.l(), out);
            collectIdents(a.rr(), out);
        } else if (n instanceof Or o) {
            collectIdents(o.l(), out);
            collectIdents(o.rr(), out);
        }
        // Lit:无数
    }

    // ---- AST 节点 ----

    record Lit(long v) implements Node {
        @Override
        public long eval(Resolver r) {
            return v;
        }
    }

    record Ident(String name) implements Node {
        @Override
        public long eval(Resolver r) {
            return r.value(name);
        }
    }

    record Not(Node inner) implements Node {
        @Override
        public long eval(Resolver r) {
            return inner.eval(r) == 0 ? 1 : 0;
        }
    }

    record Unary(long op, Node left, Node right) implements Node {  // op: 0==,1!=,2<,3<=,4>,5>=
        @Override
        public long eval(Resolver r) {
            long a = left.eval(r);
            long b = right.eval(r);
            return switch ((int) op) {
                case 0 -> a == b ? 1 : 0;
                case 1 -> a != b ? 1 : 0;
                case 2 -> a < b ? 1 : 0;
                case 3 -> a <= b ? 1 : 0;
                case 4 -> a > b ? 1 : 0;
                case 5 -> a >= b ? 1 : 0;
                default -> throw new IllegalStateException("bad op " + op);
            };
        }
    }

    record And(Node l, Node rr) implements Node {
        @Override
        public long eval(Resolver r) {
            return (l.eval(r) != 0 && rr.eval(r) != 0) ? 1 : 0;
        }
    }

    record Or(Node l, Node rr) implements Node {
        @Override
        public long eval(Resolver r) {
            return (l.eval(r) != 0 || rr.eval(r) != 0) ? 1 : 0;
        }
    }

    // ---- 递归下降解析器 ----

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        boolean eof() {
            return pos >= s.length();
        }

        void skipWs() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
                pos++;
            }
        }

        Node orExpr() {
            Node v = andExpr();
            while (true) {
                skipWs();
                if (matchWord("||")) {
                    v = new Or(v, andExpr());
                } else {
                    return v;
                }
            }
        }

        Node andExpr() {
            Node v = unary();
            while (true) {
                skipWs();
                if (matchWord("&&")) {
                    v = new And(v, unary());
                } else {
                    return v;
                }
            }
        }

        Node unary() {
            skipWs();
            if (pos < s.length() && s.charAt(pos) == '!' && !peekWord("!=")) {
                pos++;
                return new Not(unary());
            }
            return cmp();
        }

        Node cmp() {
            Node left = operand();
            skipWs();
            String op = peekCmpOp();
            if (op == null) {
                return left;
            }
            pos += op.length();
            Node right = operand();
            int k = switch (op) {
                case "==" -> 0;
                case "!=" -> 1;
                case "<" -> 2;
                case "<=" -> 3;
                case ">" -> 4;
                case ">=" -> 5;
                default -> throw new IllegalStateException();
            };
            return new Unary(k, left, right);
        }

        Node operand() {
            skipWs();
            if (eof()) {
                throw new IllegalArgumentException("unexpected end of expression: " + s);
            }
            char c = s.charAt(pos);
            if (c == '(') {
                pos++;
                Node v = orExpr();
                skipWs();
                if (eof() || s.charAt(pos) != ')') {
                    throw new IllegalArgumentException("missing ')' at " + pos + " in: " + s);
                }
                pos++;
                return v;
            }
            if (c == '-' || Character.isDigit(c)) {
                return new Lit(readNumber());
            }
            if (Character.isJavaIdentifierStart(c)) {
                String ident = readIdent();
                // 位索引语法:name[n] —— "name[n]" 整体作为一个标识符传给 resolver,
                // 由 resolver 取字段值从最高有效位起第 n 位(presentIf/when 通用,
                // 位图驱动条件的一等语法,如 bitmap[3] == 1)。
                skipWs();
                if (!eof() && s.charAt(pos) == '[') {
                    pos++;
                    skipWs();
                    int bs = pos;
                    while (!eof() && Character.isDigit(s.charAt(pos))) {
                        pos++;
                    }
                    if (pos == bs) {
                        throw new IllegalArgumentException("bad bit index at " + bs + " in: " + s);
                    }
                    String idx = s.substring(bs, pos);
                    skipWs();
                    if (eof() || s.charAt(pos) != ']') {
                        throw new IllegalArgumentException("missing ']' for bit index in: " + s);
                    }
                    pos++;
                    ident = ident + "[" + idx + "]";
                }
                return new Ident(ident);
            }
            throw new IllegalArgumentException("unexpected char '" + c + "' at " + pos + " in: " + s);
        }

        private long readNumber() {
            int start = pos;
            boolean neg = false;
            if (s.charAt(pos) == '-') {
                neg = true;
                pos++;
            }
            skipWs();
            if (eof() || !Character.isDigit(s.charAt(pos))) {
                throw new IllegalArgumentException("bad number at " + start + " in: " + s);
            }
            if (s.startsWith("0x", pos) || s.startsWith("0X", pos)) {
                pos += 2;
                int hexStart = pos;
                while (pos < s.length() && isHex(s.charAt(pos))) {
                    pos++;
                }
                if (pos == hexStart) {
                    throw new IllegalArgumentException("bad hex number at " + hexStart + " in: " + s);
                }
                return (neg ? -1 : 1) * Long.parseUnsignedLong(s.substring(hexStart, pos), 16);
            }
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
                pos++;
            }
            long v = Long.parseLong(s.substring(start, pos).trim());
            return v;
        }

        private String readIdent() {
            int start = pos;
            while (pos < s.length() && Character.isJavaIdentifierPart(s.charAt(pos))) {
                pos++;
            }
            return s.substring(start, pos);
        }

        private boolean matchWord(String w) {
            if (peekWord(w)) {
                pos += w.length();
                return true;
            }
            return false;
        }

        private boolean peekWord(String w) {
            return s.startsWith(w, pos);
        }

        private String peekCmpOp() {
            if (peekWord("==")) return "==";
            if (peekWord("!=")) return "!=";
            if (peekWord("<=")) return "<=";
            if (peekWord(">=")) return ">=";
            if (peekWord("<")) return "<";
            if (peekWord(">")) return ">";
            return null;
        }

        private static boolean isHex(char c) {
            return Character.digit(c, 16) >= 0;
        }
    }

    // ---- 组装期选择子自动接线 ----

    /**
     * 从 when 表达式提取「字段=常量」赋值(供 StackEncoder 自动接线父层选择子):
     * 取第一个顶层 || 子句;该子句必须全部由 ident==literal 的 && 合取构成,
     * 否则(含 !=/&lt;/!/括号等)返回空 Map 表示不可自动接线。
     */
    public static Map<String, Long> assignments(String expr) {
        Map<String, Long> out = new LinkedHashMap<>();
        if (expr == null || expr.isBlank()) {
            return out;
        }
        String first = splitTopLevelOr(expr)[0].trim();
        for (String conjunct : first.split("&&")) {
            String c = conjunct.trim();
            java.util.regex.Matcher m = ASSIGN_PATTERN.matcher(c);
            if (!m.matches()) {
                out.clear();  // 含不可接线成分 → 整体放弃
                return out;
            }
            String lit = m.group(2).trim();
            long v = lit.toLowerCase().startsWith("0x")
                    ? Long.parseUnsignedLong(lit.substring(2), 16)
                    : Long.parseLong(lit);
            out.put(m.group(1).trim(), v);
        }
        return out;
    }

    private static final java.util.regex.Pattern ASSIGN_PATTERN =
            java.util.regex.Pattern.compile("([A-Za-z_][A-Za-z0-9_]*)\\s*==\\s*(-?(?:0[xX][0-9a-fA-F]+|\\d+))");

    /** 按顶层 || 切分(跳过括号内)。 */
    private static String[] splitTopLevelOr(String expr) {
        java.util.List<String> parts = new java.util.ArrayList<>();
        int depth = 0;
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < expr.length(); i++) {
            char c = expr.charAt(i);
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
            }
            if (depth == 0 && c == '|' && i + 1 < expr.length() && expr.charAt(i + 1) == '|') {
                parts.add(cur.toString());
                cur.setLength(0);
                i++;
            } else {
                cur.append(c);
            }
        }
        parts.add(cur.toString());
        return parts.toArray(new String[0]);
    }
}
