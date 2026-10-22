package com.netproto.protocols.real.dns;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DNS A 查询真实报文测试(RFC 1035)。
 * <p>
 * 权威向量(教学/工具广泛引用的 www.example.com A 查询,ID=0x1234,RD=1):
 * {@code 12 34 01 00 00 01 00 00 00 00 00 00 03 77 77 77 07 65 78 61 6D 70 6C 65
 * 03 63 6F 6D 00 00 01 00 01}
 * <p>机制:flags 16bit 位拆;标签 = len 前缀 + 根 0x00 终止(sentinel 驱动 LIST);
 * question 区由 qdCount 驱动(count 驱动 LIST 套 sentinel LIST)。
 */
class DnsRealQueryTest {

    // ---- 夹具 ----

    @Data
    @Protocol(id = "real-dns-label")
    static class Label {
        @ProtocolField(order = 1, size = 8)
        private int len;
        @ProtocolField(order = 2, type = FieldType.STRING, lengthField = "len")
        private String name;
    }

    @Data
    @Protocol(id = "real-dns-question")
    static class Question {
        /** 标签序列,根标记 0x00 结束(sentinel)。 */
        @ProtocolField(order = 1, type = FieldType.LIST, sentinel = 0, elementClass = Label.class)
        private List<Label> labels = new ArrayList<>();
        @ProtocolField(order = 2, size = 16)
        private int qtype = 1;   // A
        @ProtocolField(order = 3, size = 16)
        private int qclass = 1;  // IN
    }

    @Data
    @Protocol(id = "real-dns-query")
    static class DnsQuery {
        @ProtocolField(order = 1, size = 16)
        private int id;
        @ProtocolField(order = 2, size = 1)
        private int qr;
        @ProtocolField(order = 3, size = 4)
        private int opcode;
        @ProtocolField(order = 4, size = 1)
        private int aa;
        @ProtocolField(order = 5, size = 1)
        private int tc;
        @ProtocolField(order = 6, size = 1)
        private int rd;
        @ProtocolField(order = 7, size = 1)
        private int ra;
        @ProtocolField(order = 8, size = 3)
        private int zero;
        @ProtocolField(order = 9, size = 4)
        private int rcode;
        @ProtocolField(order = 10, size = 16)
        private int qdCount;
        @ProtocolField(order = 11, size = 16)
        private int anCount;
        @ProtocolField(order = 12, size = 16)
        private int nsCount;
        @ProtocolField(order = 13, size = 16)
        private int arCount;
        @ProtocolField(order = 14, type = FieldType.LIST, countField = "qdCount",
                elementClass = Question.class)
        private List<Question> questions = new ArrayList<>();
    }

    // ---- 测试 ----

    @Test
    void classicAQueryRoundTrip() {
        ProtocolCodec<DnsQuery> codec = new ProtocolCodec<>(DnsQuery.class);
        DnsQuery q = new DnsQuery();
        q.setId(0x1234);
        q.setRd(1);
        q.setQdCount(1);
        Question question = new Question();
        for (String part : new String[]{"www", "example", "com"}) {
            Label l = new Label();
            l.setName(part);
            l.setLen(part.length());
            question.getLabels().add(l);
        }
        q.setQuestions(new ArrayList<>(List.of(question)));

        byte[] wire = codec.serialize(q);
        assertThat(wire).containsExactly(
                0x12, 0x34, 0x01, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x03, 0x77, 0x77, 0x77,
                0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
                0x03, 0x63, 0x6F, 0x6D, 0x00,
                0x00, 0x01, 0x00, 0x01);

        DnsQuery back = codec.deserialize(wire);
        assertThat(back.getId()).isEqualTo(0x1234);
        assertThat(back.getRd()).isEqualTo(1);
        assertThat(back.getQdCount()).isEqualTo(1);
        assertThat(back.getQuestions().get(0).getLabels()).hasSize(3);
        assertThat(back.getQuestions().get(0).getLabels().get(1).getName()).isEqualTo("example");
        assertThat(back.getQuestions().get(0).getQtype()).isEqualTo(1);
    }
}
