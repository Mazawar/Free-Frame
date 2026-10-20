package com.example.netproto.core;

import com.example.netproto.annotation.CountUnit;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * FieldType 扩展能力:FLOAT(IEEE 754)、BCD(压缩十进制)、多字节终结符
 * sentinelStr、countUnit=BYTES(字节计数循环)、lengthAscii(LLVAR 文本长度前缀)。
 */
class FieldTypeExtrasTest {

    // ---- 夹具 ----

    @Data
    @ToString
    @Protocol(id = "t-float")
    static class FloatMsg {
        @ProtocolField(order = 1, size = 32)
        private float f32;
        @ProtocolField(order = 2, size = 64)
        private double f64;
    }

    @Data
    @ToString
    @Protocol(id = "t-bcd")
    static class BcdMsg {
        @ProtocolField(order = 1, size = 32, type = FieldType.BCD)
        private long energy;   // 8 位十进制数字
    }

    @Data
    @ToString
    @Protocol(id = "t-crlf")
    static class CrlfMsg {
        @ProtocolField(order = 1, type = FieldType.STRING, sentinelStr = "\r\n")
        private String line;
    }

    @Data
    @ToString
    @Protocol(id = "t-elem2")
    static class Elem2 {
        @ProtocolField(order = 1, size = 16)
        private int v;
    }

    @Data
    @ToString
    @Protocol(id = "t-count-bytes")
    static class CountBytesMsg {
        @ProtocolField(order = 1, size = 8)
        private int byteCount;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "byteCount",
                countUnit = CountUnit.BYTES, elementClass = Elem2.class)
        private List<Elem2> items = new ArrayList<>();
    }

    /** null 数组语义:countField=-1(Kafka topicsCount 同款)。 */
    @Data
    @ToString
    @Protocol(id = "t-null-array")
    static class NullArrayMsg {
        @ProtocolField(order = 1, size = 32, type = FieldType.UNSIGNED)
        private long topicsCount;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "topicsCount",
                elementClass = Elem2.class)
        private List<Elem2> topics = new ArrayList<>();
    }

    /** 多字节终结符驱动的 LIST:元素读到 "\r\n" 停。 */
    @Data
    @ToString
    @Protocol(id = "t-crlf-list")
    static class CrlfListMsg {
        @ProtocolField(order = 1, type = FieldType.LIST,
                sentinelStr = "\r\n", elementClass = Elem2.class)
        private List<Elem2> items = new ArrayList<>();
    }

    @Data
    @ToString
    @Protocol(id = "t-llvar")
    static class LlvarMsg {
        /** LLVAR 两位 ASCII 长度前缀。 */
        @ProtocolField(order = 1, type = FieldType.STRING, size = 16)
        private String panLen = "00";
        @ProtocolField(order = 2, type = FieldType.STRING, lengthField = "panLen", lengthAscii = true)
        private String pan = "";
    }

    @Data
    @ToString
    @Protocol(id = "t-bcd-bad-size")
    static class BadBcdSize {
        @ProtocolField(order = 1, size = 10, type = FieldType.BCD)
        private long x;
    }

    // ---- FLOAT ----

    @Test
    void floatRoundTripMatchesIeee754Bits() {
        FloatMsg m = new FloatMsg();
        m.setF32(3.14f);
        m.setF64(-2.718281828459045);
        byte[] out = new ProtocolCodec<>(FloatMsg.class).serialize(m);
        assertEquals(12, out.length);
        assertEquals(Float.floatToIntBits(3.14f) >>> 24, out[0] & 0xFF);   // 大端 IEEE 位
        assertEquals(Double.doubleToLongBits(-2.718281828459045) >>> 56, out[4] & 0xFF);

        FloatMsg back = new ProtocolCodec<>(FloatMsg.class).deserialize(out);
        assertEquals(3.14f, back.getF32());
        assertEquals(-2.718281828459045, back.getF64());
    }

    // ---- BCD ----

    @Test
    void bcdDecodesNibbleDigits() {
        byte[] raw = new byte[]{0x33, 0x33, 0x33, 0x33};
        BcdMsg m = new ProtocolCodec<>(BcdMsg.class).deserialize(raw);
        assertEquals(33333333L, m.getEnergy());

        BcdMsg out = new BcdMsg();
        out.setEnergy(12345678L);
        assertArrayEquals(new byte[]{0x12, 0x34, 0x56, 0x78},
                new ProtocolCodec<>(BcdMsg.class).serialize(out));
    }

    @Test
    void bcdRejectsInvalidNibbleAndBadSize() {
        assertThrows(RuntimeException.class, () ->
                new ProtocolCodec<>(BcdMsg.class).deserialize(new byte[]{0x0A, 0x00, 0x00, 0x00}));
        assertThrows(IllegalArgumentException.class, () -> new ProtocolCodec<>(BadBcdSize.class));
    }

    // ---- sentinelStr ----

    @Test
    void multiByteSentinelCrlf() {
        CrlfMsg m = new ProtocolCodec<>(CrlfMsg.class).deserialize("PING\r\n".getBytes());
        assertEquals("PING", m.getLine());

        CrlfMsg out = new CrlfMsg();
        out.setLine("+OK");
        assertArrayEquals("+OK\r\n".getBytes(), new ProtocolCodec<>(CrlfMsg.class).serialize(out));
    }

    // ---- countUnit=BYTES ----

    @Test
    void countUnitBytesDividesByElementSize() {
        // byteCount=6(字节),元素 2B → 3 个元素
        CountBytesMsg m = new ProtocolCodec<>(CountBytesMsg.class).deserialize(
                new byte[]{6, 0x0B, (byte) 0xEE, 0x12, 0x34, 0x56, 0x78});
        assertEquals(6, m.getByteCount());
        assertEquals(3, m.getItems().size());
        assertEquals(0x0BEE, m.getItems().get(0).getV());
        assertEquals(0x5678, m.getItems().get(2).getV());

        CountBytesMsg out = new CountBytesMsg();   // 不设 byteCount → 组装期自动回填 2×2=4
        out.getItems().add(elem(1));
        out.getItems().add(elem(2));
        assertArrayEquals(new byte[]{4, 0, 1, 0, 2},
                new ProtocolCodec<>(CountBytesMsg.class).serialize(out));
        assertEquals(4, out.getByteCount());
    }

    private static Elem2 elem(int v) {
        Elem2 e = new Elem2();
        e.setV(v);
        return e;
    }

    // ---- lengthAscii(LLVAR) ----

    @Test
    void llvarAsciiLengthPrefix() {
        LlvarMsg m = new ProtocolCodec<>(LlvarMsg.class).deserialize("124111111111111".getBytes());
        assertEquals("12", m.getPanLen());
        assertEquals("411111111111", m.getPan());   // 12 位,由 "12" 文本长度驱动

        LlvarMsg out = new LlvarMsg();
        out.setPan("4222222");
        out.setPanLen("07");
        assertArrayEquals("074222222".getBytes(),
                new ProtocolCodec<>(LlvarMsg.class).serialize(out));
    }

    // ---- null 数组(count=-1) ----

    @Test
    void nullArrayNegativeCountRoundTrip() {
        NullArrayMsg out = new NullArrayMsg();
        out.setTopicsCount(-1L);   // unsigned 32 位读出为 0xFFFFFFFF,语义即 -1
        byte[] encoded = new ProtocolCodec<>(NullArrayMsg.class).serialize(out);
        assertEquals(4, encoded.length);            // 仅 count 字段,无元素

        NullArrayMsg back = new ProtocolCodec<>(NullArrayMsg.class).deserialize(encoded);
        assertEquals(0xFFFFFFFFL, back.getTopicsCount());
        assertTrue(back.getTopics().isEmpty());     // 负计数 = 空列表,不报错
    }

    // ---- sentinelStr + LIST ----

    @Test
    void multiByteSentinelDrivesList() {
        // 3 个 2 字节元素 + "\r\n" 终结
        byte[] raw = new byte[]{0x0B, (byte) 0xEE, 0x12, 0x34, 0x56, 0x78, '\r', '\n'};
        CrlfListMsg m = new ProtocolCodec<>(CrlfListMsg.class).deserialize(raw);
        assertEquals(3, m.getItems().size());
        assertEquals(0x1234, m.getItems().get(1).getV());

        CrlfListMsg out = new CrlfListMsg();
        out.getItems().add(elem(7));
        out.getItems().add(elem(8));
        assertArrayEquals(new byte[]{0, 7, 0, 8, '\r', '\n'},
                new ProtocolCodec<>(CrlfListMsg.class).serialize(out));
    }
}
