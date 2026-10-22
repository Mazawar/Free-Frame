package com.netproto.core;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 能力边界测试:长度语义族。
 * <ul>
 *   <li>字单位(word=4B)长度 —— IPv4 IHL / SNA 半字 / 部分车载协议;LengthUnit 只有
 *       BYTES/BITS,声明式不支持,须 DynamicSize 钩子;</li>
 *   <li>自包含长度(长度字段计入自身,如「总帧长含头」)—— lengthAdjust 可解;</li>
 *   <li>长度字段在数据之后(尾部长度,如某些车载/总线协议)—— 前向引用禁止,注册期拒绝;</li>
 *   <li>LLVAR 文本长度非数字 —— 干净失败。</li>
 * </ul>
 */
class BoundaryLengthSemanticsTest {

    // ---- 夹具 ----

    /** 字单位长度:payloadLen 以 32bit 字计。DynamicSize 钩子实现 ×32 换算。 */
    @Data
    @Protocol(id = "b-word-len")
    static class WordUnitFrame implements DynamicSize {
        @ProtocolField(order = 1, size = 8)
        private int wordCount;
        @ProtocolField(order = 2, type = FieldType.BYTES)
        private byte[] data = new byte[0];

        @Override
        public long computeSize(String fieldName, FieldContext ctx) {
            if (!"data".equals(fieldName)) {
                return -1;
            }
            return ctx.getInt("wordCount") * 32L;
        }
    }

    /** 自包含长度:len = 整帧字节数(含 len 字段自身 2B、不含尾随 1B 标志)。 */
    @Data
    @Protocol(id = "b-self-len")
    static class SelfInclusiveFrame {
        @ProtocolField(order = 1, size = 16)
        private int len;
        @ProtocolField(order = 2, lengthField = "len", lengthAdjust = -3, type = FieldType.BYTES)
        private byte[] body = new byte[0];
        @ProtocolField(order = 3, size = 8)
        private int tailFlag;
    }

    /** 尾部长度(前向引用):注册期应拒绝。 */
    @Data
    @Protocol(id = "b-tail-len")
    static class TailLengthFrame {
        @ProtocolField(order = 1, lengthField = "len", type = FieldType.BYTES)
        private byte[] body = new byte[0];
        @ProtocolField(order = 2, size = 16)
        private int len;
    }

    @Data
    @Protocol(id = "b-llvar-bad")
    static class LlvarBadFrame {
        @ProtocolField(order = 1, type = FieldType.STRING, size = 16)
        private String panLen = "00";
        @ProtocolField(order = 2, type = FieldType.STRING, lengthField = "panLen", lengthAscii = true)
        private String pan = "";
    }

    // ---- 测试 ----

    /** 字单位长度经 DynamicSize 钩子可用(声明式本身无 WORDS 单位 —— 已记录缺口)。 */
    @Test
    void wordUnitLengthViaDynamicSizeHook() {
        ProtocolCodec<WordUnitFrame> codec = new ProtocolCodec<>(WordUnitFrame.class);
        WordUnitFrame f = new WordUnitFrame();
        f.setWordCount(3);
        byte[] data = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88,
                (byte) 0x99, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC};   // 3 字 = 12B
        f.setData(data);
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(13);   // 1B wordCount + 12B data
        WordUnitFrame back = codec.deserialize(wire);
        assertThat(back.getWordCount()).isEqualTo(3);
        assertThat(back.getData()).containsExactly(data);
    }

    /** lengthAdjust 负偏移:自包含长度(总长含头 3B)round-trip。 */
    @Test
    void selfInclusiveLengthWithNegativeAdjust() {
        ProtocolCodec<SelfInclusiveFrame> codec = new ProtocolCodec<>(SelfInclusiveFrame.class);
        SelfInclusiveFrame f = new SelfInclusiveFrame();
        byte[] body = {0x01, 0x02, 0x03, 0x04, 0x05};
        f.setBody(body);
        f.setLen(body.length + 3);   // 整帧 = 2 + 5 + 1 = 8
        f.setTailFlag(0x7E);
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(8);
        SelfInclusiveFrame back = codec.deserialize(wire);
        assertThat(back.getLen()).isEqualTo(8);
        assertThat(back.getBody()).containsExactly(body);
        assertThat(back.getTailFlag()).isEqualTo(0x7E);
    }

    /** 尾部长度(前向引用)注册期拒绝 —— 机制边界:长度只能引用更早的字段。 */
    @Test
    void tailLengthForwardReferenceRejectedAtRegistration() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new ProtocolCodec<>(TailLengthFrame.class));
        assertThat(ex).hasMessageContaining("not earlier in order");
    }

    /** LLVAR 文本长度非数字:干净失败。 */
    @Test
    void asciiLengthGarbageFailsCleanly() {
        ProtocolCodec<LlvarBadFrame> codec = new ProtocolCodec<>(LlvarBadFrame.class);
        LlvarBadFrame f = new LlvarBadFrame();
        f.setPanLen("AB");
        RuntimeException ex = assertThrows(RuntimeException.class, () -> codec.serialize(f));
        assertThat(ex).hasMessageContaining("not ASCII decimal");
    }

    /**
     * 普通 BYTES 的 lengthField 与实际长度不一致 → 修复后序列化干净拒绝
     * (此前静默产出尾部零填充的毒数据;与 @Payload 模式对齐同一标准)。
     */
    @Test
    void plainBytesLengthMismatchRejected() {
        ProtocolCodec<SelfInclusiveFrame> codec = new ProtocolCodec<>(SelfInclusiveFrame.class);
        SelfInclusiveFrame f = new SelfInclusiveFrame();
        byte[] body = {0x01, 0x02, 0x03, 0x04, 0x05};   // 5B
        f.setBody(body);
        f.setLen(99);   // 声称 99 → implied (99-3)*8=768bit,实际 40bit
        f.setTailFlag(0x7E);
        RuntimeException ex = assertThrows(RuntimeException.class, () -> codec.serialize(f));
        assertThat(ex).hasMessageContaining("implies 768 bits but value has 40 bits");
    }

    /** STRING + ASCII 长度前缀的不一致同样拒绝(LLVAR)。 */
    @Test
    void llvarLengthMismatchRejected() {
        ProtocolCodec<LlvarBadFrame> codec = new ProtocolCodec<>(LlvarBadFrame.class);
        LlvarBadFrame f = new LlvarBadFrame();
        f.setPanLen("02");
        f.setPan("ABCD");   // 声称 2 字节,实际 4
        RuntimeException ex = assertThrows(RuntimeException.class, () -> codec.serialize(f));
        assertThat(ex).hasMessageContaining("implies 16 bits but value has 32 bits");
    }
}
