package com.netproto.protocols.real.arp;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 真实协议测试 1:ARP 报文体(RFC 826;Ethernet 承载省略,只测 28 字节 ARP 体)。
 * <p>
 * 向量出处:
 * <ul>
 *   <li>请求向量 = tcpdump 教科书输出「arp who-has 192.168.1.1 tell 192.168.1.100」
 *       对应的字节(RFC 826 布局手工展开):sha=00:11:22:33:44:55,spa=192.168.1.100,
 *       tha=全零(未知),tpa=192.168.1.1;</li>
 *   <li>免费 ARP(gratuitous ARP,应答形式)形态见 RFC 5227:oper=2、sha==tha、spa==tpa。</li>
 * </ul>
 * 声明式要点:四个地址字段全部 lengthField 驱动 —— sha/tha 用 hlen(6),spa/tpa 用 plen(4)。
 */
class ArpRealTest {

    /** who-has 192.168.1.1 tell 192.168.1.100(权威向量,28 字节)。 */
    private static final byte[] WHO_HAS_VECTOR = hex(
            "00 01 08 00 06 04 00 01"      // htype=1 ptype=0x0800 hlen=6 plen=4 oper=1(request)
          + " 00 11 22 33 44 55"           // sha = 00:11:22:33:44:55
          + " C0 A8 01 64"                 // spa = 192.168.1.100
          + " 00 00 00 00 00 00"           // tha = 00:00:00:00:00:00(目标未知)
          + " C0 A8 01 01");               // tpa = 192.168.1.1

    /** 免费 ARP 应答:同一主机通告自身 IP(oper=2,sha==tha,spa==tpa=192.168.1.100)。 */
    private static final byte[] GRATUITOUS_VECTOR = hex(
            "00 01 08 00 06 04 00 02"      // oper=2(reply)
          + " 00 11 22 33 44 55"           // sha = 本机 MAC
          + " C0 A8 01 64"                 // spa = 本机 IP
          + " 00 11 22 33 44 55"           // tha = 本机 MAC(免费 ARP 特征)
          + " C0 A8 01 64");               // tpa = 本机 IP(免费 ARP 特征)

    @Data
    @Protocol(id = "real-arp")
    static class ArpFrame {
        /** 硬件类型:1 = 以太网。 */
        @ProtocolField(order = 1, size = 16)
        private int htype = 1;
        /** 协议类型:0x0800 = IPv4。 */
        @ProtocolField(order = 2, size = 16)
        private int ptype = 0x0800;
        @ProtocolField(order = 3, size = 8)
        private int hlen = 6;
        @ProtocolField(order = 4, size = 8)
        private int plen = 4;
        /** 操作:1 = request,2 = reply。 */
        @ProtocolField(order = 5, size = 16)
        private int oper;
        @ProtocolField(order = 6, lengthField = "hlen", type = FieldType.BYTES)
        private byte[] sha;
        @ProtocolField(order = 7, lengthField = "plen", type = FieldType.BYTES)
        private byte[] spa;
        @ProtocolField(order = 8, lengthField = "hlen", type = FieldType.BYTES)
        private byte[] tha;
        @ProtocolField(order = 9, lengthField = "plen", type = FieldType.BYTES)
        private byte[] tpa;
    }

    private static ArpFrame whoHas() {
        ArpFrame f = new ArpFrame();   // 字段初值:htype=1 / ptype=0x0800 / hlen=6 / plen=4
        f.setOper(1);
        f.setSha(bytes(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
        f.setSpa(bytes(0xC0, 0xA8, 0x01, 0x64));   // 192.168.1.100
        f.setTha(new byte[6]);
        f.setTpa(bytes(0xC0, 0xA8, 0x01, 0x01));   // 192.168.1.1
        return f;
    }

    // ---- 测试 ----

    /** 权威向量解码:逐字段断言(含 hlen/plen 双长度引用正确驱动 4 个地址字段)。 */
    @Test
    void whoHasVectorDecodesFieldByField() {
        ProtocolCodec<ArpFrame> codec = new ProtocolCodec<>(ArpFrame.class);
        ArpFrame f = codec.deserialize(WHO_HAS_VECTOR);

        assertThat(f.getHtype()).isEqualTo(1);
        assertThat(f.getPtype()).isEqualTo(0x0800);
        assertThat(f.getHlen()).isEqualTo(6);
        assertThat(f.getPlen()).isEqualTo(4);
        assertThat(f.getOper()).isEqualTo(1);
        assertThat(f.getSha()).containsExactly(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        assertThat(f.getSpa()).containsExactly(0xC0, 0xA8, 0x01, 0x64);
        assertThat(f.getTha()).containsExactly(0, 0, 0, 0, 0, 0);
        assertThat(f.getTpa()).containsExactly(0xC0, 0xA8, 0x01, 0x01);
    }

    /** 编码字节级命中权威向量 + round-trip(Lombok equals:byte[] 逐元素)。 */
    @Test
    void whoHasEncodesToAuthoritativeVectorAndRoundTrips() {
        ProtocolCodec<ArpFrame> codec = new ProtocolCodec<>(ArpFrame.class);
        ArpFrame f = whoHas();

        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(28);
        assertThat(wire).containsExactly(WHO_HAS_VECTOR);

        ArpFrame back = codec.deserialize(wire);
        assertThat(back).isEqualTo(f);
        assertThat(back.getSha()).containsExactly(f.getSha());
        assertThat(back.getTpa()).containsExactly(f.getTpa());
    }

    /** 免费 ARP(oper=2)复用同一实体:sha==tha、spa==tpa,字节级向量 + round-trip。 */
    @Test
    void gratuitousArpReplyReusesSameEntity() {
        ProtocolCodec<ArpFrame> codec = new ProtocolCodec<>(ArpFrame.class);
        ArpFrame f = new ArpFrame();
        f.setOper(2);
        byte[] mac = bytes(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        byte[] ip = bytes(0xC0, 0xA8, 0x01, 0x64);
        f.setSha(mac);
        f.setSpa(ip);
        f.setTha(mac);
        f.setTpa(ip);

        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(GRATUITOUS_VECTOR);
        // oper=2 落在字节 6-7(BE):00 02
        assertThat(wire[6]).isEqualTo((byte) 0x00);
        assertThat(wire[7]).isEqualTo((byte) 0x02);

        ArpFrame back = codec.deserialize(GRATUITOUS_VECTOR);
        assertThat(back.getOper()).isEqualTo(2);
        assertThat(back.getSha()).containsExactly(back.getTha());   // sha == tha
        assertThat(back.getSpa()).containsExactly(back.getTpa());   // spa == tpa
        assertThat(back.getTpa()).containsExactly(0xC0, 0xA8, 0x01, 0x64);
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

    private static byte[] bytes(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return out;
    }
}
