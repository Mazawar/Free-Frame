package com.example.demo.protocol.core;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/** Expr 小语言:运算符、括号、0x 字面量、严格/宽松模式、赋值提取。 */
class ExprTest {

    /** 标识符表:a=1 b=2 port=9999 zero=0;其余未知。 */
    private static long val(String name) {
        return switch (name) {
            case "a" -> 1;
            case "b" -> 2;
            case "port" -> 9999;
            case "zero" -> 0;
            default -> throw new Expr.UnknownIdentifier(name);
        };
    }

    @Test
    void equalityAndHexLiteral() {
        assertTrue(Expr.eval("port == 0x270F", ExprTest::val, false));
        assertTrue(Expr.eval("port == 9999", ExprTest::val, false));
        assertFalse(Expr.eval("port != 9999", ExprTest::val, false));
    }

    @Test
    void relational() {
        assertTrue(Expr.eval("b > a", ExprTest::val, false));
        assertTrue(Expr.eval("a >= 1", ExprTest::val, false));
        assertFalse(Expr.eval("a < 0", ExprTest::val, false));
        assertTrue(Expr.eval("a <= b", ExprTest::val, false));
    }

    @Test
    void logicAndParen() {
        assertTrue(Expr.eval("(a == 1 || b == 3) && port == 9999", ExprTest::val, false));
        assertFalse(Expr.eval("a == 2 || b == 3 && port == 1", ExprTest::val, false));
        // && 优先级高于 ||:b==3 为假 → 左支只看 a==1
        assertTrue(Expr.eval("a == 1 || b == 3 && port == 1", ExprTest::val, false));
    }

    @Test
    void unaryNotAndBareTruthiness() {
        assertTrue(Expr.eval("!zero", ExprTest::val, false));
        assertFalse(Expr.eval("!a", ExprTest::val, false));
        assertTrue(Expr.eval("a", ExprTest::val, false));
        assertFalse(Expr.eval("zero", ExprTest::val, false));
    }

    @Test
    void negativeLiteral() {
        assertTrue(Expr.eval("a == 1 && -1 < 0", ExprTest::val, false));
    }

    @Test
    void strictModeThrowsOnUnknownIdent() {
        assertThrows(IllegalArgumentException.class,
                () -> Expr.eval("missing == 1", ExprTest::val, false));
    }

    @Test
    void lenientModeFalseOnUnknownIdent() {
        assertFalse(Expr.eval("missing == 1", ExprTest::val, true));
    }

    @Test
    void syntaxErrorsFailFast() {
        assertThrows(IllegalArgumentException.class, () -> Expr.compile("a =="));
        assertThrows(IllegalArgumentException.class, () -> Expr.compile("(a == 1"));
        assertThrows(IllegalArgumentException.class, () -> Expr.compile("a == 1 extra"));
        assertThrows(IllegalArgumentException.class, () -> Expr.compile(""));
    }

    @Test
    void assignmentsTakeFirstOrClause() {
        assertEquals(Map.of("dstPort", 9999L), Expr.assignments("dstPort == 9999 || srcPort == 9999"));
        assertEquals(Map.of("etherType", 0x0800L), Expr.assignments("etherType == 0x0800"));
        assertEquals(Map.of("protocol", 17L, "version", 4L), Expr.assignments("protocol == 17 && version == 4"));
    }

    @Test
    void assignmentsRejectNonEquality() {
        assertTrue(Expr.assignments("port != 1").isEmpty());
        assertTrue(Expr.assignments("port > 1").isEmpty());
        assertTrue(Expr.assignments("!(port == 1)").isEmpty());
    }

    @Test
    void collectIdentsWalksAst() {
        var node = Expr.compile("(a == 1 || b == 2) && port == 3");
        var idents = new java.util.TreeSet<String>();
        Expr.collectIdents(node, idents);
        assertEquals(new java.util.TreeSet<>(java.util.List.of("a", "b", "port")), idents);
    }

    @Test
    void resolverSeesLiveValues() {
        AtomicLong v = new AtomicLong(5);
        assertTrue(Expr.eval("x > 4", n -> v.get(), false));
        v.set(3);
        assertFalse(Expr.eval("x > 4", n -> v.get(), false));
    }
}
