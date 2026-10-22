package com.netproto.protocols.real.bson;

import com.netproto.annotation.Endian;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BSON 文档真实向量测试(bsonspec.org)。
 * <p>
 * 全小端。两个手导向量:
 * <ul>
 *   <li>{@code {a: 1}} → {@code 0C 00 00 00 10 61 00 01 00 00 00 00}
 *       (int32 元素,key 为 0x00 结尾 C-string);</li>
 *   <li>{@code {hello: "world"}} → {@code 16 00 00 00 02 68 65 6C 6C 6F 00 06 00 00 00 77 6F 72 6C 64 00 00}
 *       (string 的 int32 长度含结尾 NUL → lengthAdjust=-1)。</li>
 * </ul>
 * 顶层 int32 长度自包含(含自身 4B + 结尾 0x00)。
 */
class BsonRealTest {

    @Data
    @Protocol(id = "real-bson-int32")
    static class Int32Doc {
        @ProtocolField(order = 1, size = 32, endian = Endian.LITTLE)
        private int docLen = 12;
        /** 0x10 = int32。 */
        @ProtocolField(order = 2, size = 8)
        private int type = 0x10;
        @ProtocolField(order = 3, type = FieldType.STRING, sentinel = 0)
        private String key;
        @ProtocolField(order = 4, size = 32, endian = Endian.LITTLE)
        private int value;
        @ProtocolField(order = 5, size = 8)
        private int terminator;
    }

    @Data
    @Protocol(id = "real-bson-string")
    static class StringDoc {
        @ProtocolField(order = 1, size = 32, endian = Endian.LITTLE)
        private int docLen = 22;
        /** 0x02 = UTF-8 string。 */
        @ProtocolField(order = 2, size = 8)
        private int type = 0x02;
        @ProtocolField(order = 3, type = FieldType.STRING, sentinel = 0)
        private String key;
        /** BSON string 长度含结尾 NUL。 */
        @ProtocolField(order = 4, size = 32, endian = Endian.LITTLE)
        private int strLen = 6;
        @ProtocolField(order = 5, type = FieldType.STRING, lengthField = "strLen", lengthAdjust = -1)
        private String value;
        @ProtocolField(order = 6, size = 8)
        private int strNull;
        @ProtocolField(order = 7, size = 8)
        private int terminator;
    }

    @Test
    void int32DocumentMatchesVector() {
        ProtocolCodec<Int32Doc> codec = new ProtocolCodec<>(Int32Doc.class);
        Int32Doc doc = new Int32Doc();
        doc.setKey("a");
        doc.setValue(1);
        assertThat(codec.serialize(doc)).containsExactly(
                0x0C, 0x00, 0x00, 0x00,
                0x10, 0x61, 0x00,
                0x01, 0x00, 0x00, 0x00,
                0x00);

        Int32Doc back = codec.deserialize(new byte[]{
                0x0C, 0x00, 0x00, 0x00,
                0x10, 0x61, 0x00,
                0x01, 0x00, 0x00, 0x00,
                0x00});
        assertThat(back.getKey()).isEqualTo("a");
        assertThat(back.getValue()).isEqualTo(1);
        assertThat(back.getDocLen()).isEqualTo(12);
    }

    @Test
    void stringDocumentMatchesVector() {
        ProtocolCodec<StringDoc> codec = new ProtocolCodec<>(StringDoc.class);
        StringDoc doc = new StringDoc();
        doc.setKey("hello");
        doc.setValue("world");
        assertThat(codec.serialize(doc)).containsExactly(
                0x16, 0x00, 0x00, 0x00,
                0x02, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00,
                0x06, 0x00, 0x00, 0x00,
                0x77, 0x6F, 0x72, 0x6C, 0x64, 0x00,
                0x00);

        StringDoc back = codec.deserialize(new byte[]{
                0x16, 0x00, 0x00, 0x00,
                0x02, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00,
                0x06, 0x00, 0x00, 0x00,
                0x77, 0x6F, 0x72, 0x6C, 0x64, 0x00,
                0x00});
        assertThat(back.getKey()).isEqualTo("hello");
        assertThat(back.getValue()).isEqualTo("world");
        assertThat(back.getStrLen()).isEqualTo(6);   // 含结尾 NUL 的 BSON 口径
    }
}
