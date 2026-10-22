package com.netproto.protocols.real.icmp;

import com.netproto.annotation.ChecksumField;
import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.Checksum;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 真实协议测试 2:ICMPv4 Echo Request(RFC 792)。
 * <p>
 * 向量出处:
 * <ul>
 *   <li>校验和参考实现在测试内自证,用 RFC 1071 §4.1 的经典例:
 *       字节 00 01 F2 03 F4 F5 F6 F7 → 折叠和 0xDDF2 → 校验和 0x220D,
 *       「数据 + 校验和」折叠和必为 0xFFFF(校验通过性质);</li>
 *   <li>echo request 载荷 "abcd" 的线格式为 08 00 SS SS 00 01 00 01 61 62 63 64,
 *       SS SS 由引擎 @ChecksumField 钩子回写;测试内独立手算 SS SS = 0x3337
 *       (= ~(0x0800 + 0x0001 + 0x0001 + 0x6162 + 0x6364) & 0xFFFF,校验和字段按 0 参与求和),
 *       并用 0xFFFF 性质交叉验证。</li>
 * </ul>
 * 声明式说明:data(BYTES)= 报文剩余全部字节;DSL 没有指向「剩余长度」的 lengthField 目标,
 * 引擎的一等形态是 @Payload(rest-of-layer),此处用它表达(与 builtin IcmpPacket 同款,非逃生舱)。
 */
class IcmpEchoRealTest {

    @Data
    @Protocol(id = "real-icmp-echo")
    static class IcmpEcho implements Checksum {
        /** 8 = Echo Request。 */
        @ProtocolField(order = 1, size = 8)
        private int type;
        @ProtocolField(order = 2, size = 8)
        private int code;
        /** 引擎序列化时置 0 → compute → 回写。 */
        @ProtocolField(order = 3, size = 16)
        @ChecksumField
        private int checksum;
        @ProtocolField(order = 4, size = 16)
        private int id;
        @ProtocolField(order = 5, size = 16)
        private int seq;
        /** echo 数据 = 报文剩余全部字节(rest-of-layer 一等形态)。 */
        @Payload
        private byte[] data;

        /** RFC 1071:16bit 反码和(校验和字段已被引擎置 0,此处覆盖整个报文)。 */
        @Override
        public long compute(String field, byte[] serialized) {
            if (!"checksum".equals(field)) {
                return -1;
            }
            return (~foldedSum(serialized)) & 0xFFFF;
        }
    }

    /** 16bit 反码求和(折叠进位、不求补)。校验通过 ⟺ foldedSum(含校验和) == 0xFFFF。 */
    private static int foldedSum(byte[] data) {
        long sum = 0;
        for (int i = 0; i + 1 < data.length; i += 2) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
        }
        if ((data.length & 1) != 0) {
            sum += (data[data.length - 1] & 0xFF) << 8;   // 奇数长:末字节按低 8 位补零
        }
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (int) sum;
    }

    // ---- 测试 ----

    /** 参考实现自证:RFC 1071 §4.1 经典例(0x0001+0xF203+0xF4F5+0xF6F7)。 */
    @Test
    void referenceChecksumSelfChecksWithRfc1071Example() {
        byte[] words = hex("00 01 F2 03 F4 F5 F6 F7");
        int folded = foldedSum(words);
        assertThat(folded).isEqualTo(0xDDF2);   // RFC 1071 给出的折叠和

        int checksum = (~folded) & 0xFFFF;
        assertThat(checksum).isEqualTo(0x220D);   // RFC 1071 给出的校验和

        // 数据 + 校验和 一起求折叠和必为 0xFFFF —— 即校验通过
        byte[] withChecksum = hex("00 01 F2 03 F4 F5 F6 F7 22 0D");
        assertThat(foldedSum(withChecksum)).isEqualTo(0xFFFF);
    }

    /** 编码帧:字节级命中向量(SS SS 由引擎回写,独立手算 = 33 37),含校验和必为 0xFFFF。 */
    @Test
    void echoRequestAbcdWireMatchesVectorAndChecksumVerifies() {
        ProtocolCodec<IcmpEcho> codec = new ProtocolCodec<>(IcmpEcho.class);
        IcmpEcho echo = new IcmpEcho();
        echo.setType(8);
        echo.setCode(0);
        echo.setId(1);
        echo.setSeq(1);
        echo.setData("abcd".getBytes(StandardCharsets.US_ASCII));

        byte[] wire = codec.serialize(echo);
        // SS SS = 33 37:0x0800+0x0000(校验和置 0)+0x0001+0x0001+0x6162+0x6364 = 0xCCC8,~0xCCC8 = 0x3337
        assertThat(wire).containsExactly(0x08, 0x00, 0x33, 0x37, 0x00, 0x01, 0x00, 0x01,
                0x61, 0x62, 0x63, 0x64);

        // 编码帧含校验和重算折叠和必为 0xFFFF(即校验通过)
        assertThat(foldedSum(wire)).isEqualTo(0xFFFF);
    }

    /** round-trip:解码后逐字段一致,校验和字段读回引擎写入的 0x3337。 */
    @Test
    void echoRequestRoundTripsThroughEngineChecksum() {
        ProtocolCodec<IcmpEcho> codec = new ProtocolCodec<>(IcmpEcho.class);
        IcmpEcho echo = new IcmpEcho();
        echo.setType(8);
        echo.setCode(0);
        echo.setId(1);
        echo.setSeq(1);
        echo.setData("abcd".getBytes(StandardCharsets.US_ASCII));

        IcmpEcho back = codec.deserialize(codec.serialize(echo));
        assertThat(back.getType()).isEqualTo(8);
        assertThat(back.getCode()).isEqualTo(0);
        assertThat(back.getChecksum()).isEqualTo(0x3337);   // 引擎回写值
        assertThat(back.getId()).isEqualTo(1);
        assertThat(back.getSeq()).isEqualTo(1);
        assertThat(back.getData()).containsExactly(0x61, 0x62, 0x63, 0x64);
    }

    /** 奇数长载荷(3 字节 "abc"):末字节补零参与求和;0xFFFF 性质 + round-trip 仍成立。 */
    @Test
    void oddLengthDataChecksumPadsAndRoundTrips() {
        ProtocolCodec<IcmpEcho> codec = new ProtocolCodec<>(IcmpEcho.class);
        IcmpEcho echo = new IcmpEcho();
        echo.setType(8);
        echo.setId(1);
        echo.setSeq(1);
        echo.setData("abc".getBytes(StandardCharsets.US_ASCII));

        byte[] wire = codec.serialize(echo);
        assertThat(wire).hasSize(8 + 3);
        // 独立手算:0x0802 + 0x6162 + 0x6300(补零)= 0xCC64 → 校验和 0x339B
        assertThat(wire[2]).isEqualTo((byte) 0x33);
        assertThat(wire[3]).isEqualTo((byte) 0x9B);
        assertThat(foldedSum(wire)).isEqualTo(0xFFFF);

        IcmpEcho back = codec.deserialize(wire);
        assertThat(back.getData()).containsExactly(0x61, 0x62, 0x63);
        assertThat(back.getChecksum()).isEqualTo(0x339B);
    }

    // ---- 小工具 ----

    private static byte[] hex(String s) {
        String clean = s.replaceAll("\\s+", "");
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
