package com.netproto.protocols.real.stack;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import com.netproto.protocols.builtin.ArpPacket;
import com.netproto.protocols.builtin.EthernetFrame;
import com.netproto.protocols.builtin.IcmpPacket;
import com.netproto.protocols.builtin.Icmpv6Packet;
import com.netproto.protocols.builtin.Ipv4Packet;
import com.netproto.protocols.builtin.Ipv6Packet;
import com.netproto.protocols.builtin.TcpSegment;
import com.netproto.protocols.builtin.UdpSegment;
import com.netproto.protocols.builtin.VlanFrame;
import com.netproto.stack.DecodedPacket;
import com.netproto.stack.ProtocolRegistry;
import com.netproto.stack.StackDecoder;
import com.netproto.stack.StackEncoder;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 真实协议测试 5(全栈):Ethernet II + IPv4 + UDP 承载 DNS 查询。
 * <p>
 * 向量出处:DNS 查询向量是 Wireshark 示例捕包/Wikipedia「Domain Name System」条目
 * 广泛引用的教科书向量(id=0x1234、RD=1、QDCount=1、www.example.com、A/IN,共 30 字节):
 * <pre>12 34 01 00 00 01 00 00 00 00 00 00 03 77 77 77 07 65 78 61 6D 70 6C 65 03 63 6F 6D 00 00 01 00 01</pre>
 * <p>
 * DNS 实体:question 内 labels 用 LIST sentinel=0(读到 0x00 根标记终止),
 * 元素 Label{len(8); name STRING lengthField="len"};qtype/qclass 跟在 labels 后。
 * <p>
 * 组栈:复用 builtin EthernetFrame/Ipv4Packet/UdpSegment;DNS 挂 udp 之下
 * (BindOn 端口 53 命中)。走 ProtocolRegistry + StackEncoder/StackDecoder 分派树:
 * etherType=0x0800、protocol=17、dstPort=53 由选择子自动接线,IPv4 总长/UDP 长度由
 * onPayload 回填,IPv4 头校验和由 @ChecksumField 钩子计算;总长 = 14+20+8+33 = 75
 * (任务书写的 30/72 为笔误 —— 向量逐字节数为 33)。
 */
class DnsRealStackTest {

    /** 权威 DNS 查询向量:www.example.com A IN(30 字节)。 */
    private static final byte[] DNS_QUERY_VECTOR = hex(
            "12 34 01 00 00 01 00 00 00 00 00 00"   // id=0x1234 flags=0x0100(RD) counts 1/0/0/0
          + " 03 77 77 77"                            // "www"
          + " 07 65 78 61 6D 70 6C 65"                // "example"
          + " 03 63 6F 6D"                            // "com"
          + " 00"                                     // 根标记(0x00)终止 QName
          + " 00 01 00 01");                          // qtype=A(1) qclass=IN(1)

    // ---- DNS 实体(自建) ----

    /** DNS label:1 字节长度 + 变长名字(lengthField 驱动,元素自定边界)。 */
    @Data
    @Protocol(id = "real-dns-label")
    static class DnsLabel {
        @ProtocolField(order = 1, size = 8)
        private int len;
        @ProtocolField(order = 2, type = FieldType.STRING, lengthField = "len")
        private String name;
    }

    /** DNS Question:labels 列表(sentinel=0x00 终止)+ qtype/qclass。 */
    @Data
    @Protocol(id = "real-dns-question")
    static class DnsQuestion {
        @ProtocolField(order = 1, type = FieldType.LIST, elementClass = DnsLabel.class, sentinel = 0)
        private List<DnsLabel> labels = new ArrayList<>();
        /** 1 = A。 */
        @ProtocolField(order = 2, size = 16)
        private int qtype;
        /** 1 = IN。 */
        @ProtocolField(order = 3, size = 16)
        private int qclass;
    }

    /** DNS 查询头 + question 列表(qdCount 驱动)。 */
    @Data
    @Protocol(id = "real-dns-query")
    @BindOn(parent = "udp", when = "dstPort == 53 || srcPort == 53")
    static class DnsQuery {
        @ProtocolField(order = 1, size = 16)
        private int id;
        /** 0x0100 = RD(递归期望)。 */
        @ProtocolField(order = 2, size = 16)
        private int flags;
        @ProtocolField(order = 3, size = 16)
        private int qdCount;
        @ProtocolField(order = 4, size = 16)
        private int anCount;
        @ProtocolField(order = 5, size = 16)
        private int nsCount;
        @ProtocolField(order = 6, size = 16)
        private int arCount;
        @ProtocolField(order = 7, type = FieldType.LIST, elementClass = DnsQuestion.class, countField = "qdCount")
        private List<DnsQuestion> questions = new ArrayList<>();
    }

    // ---- 测试 ----

    /** 第一步自证:单独的 DNS 实体编码字节级命中权威向量,解码逐字段一致。 */
    @Test
    void dnsQueryStandaloneMatchesAuthoritativeVector() {
        ProtocolCodec<DnsQuery> codec = new ProtocolCodec<>(DnsQuery.class);
        byte[] wire = codec.serialize(query());

        assertThat(wire).hasSize(33);   // 12 头 + 17 QName(含 0x00 根)+ 4 qtype/qclass
        assertThat(wire).containsExactly(DNS_QUERY_VECTOR);

        DnsQuery back = codec.deserialize(DNS_QUERY_VECTOR);
        assertThat(back.getId()).isEqualTo(0x1234);
        assertThat(back.getFlags()).isEqualTo(0x0100);
        assertThat(back.getQdCount()).isEqualTo(1);
        assertThat(back.getAnCount()).isZero();
        assertThat(back.getNsCount()).isZero();
        assertThat(back.getArCount()).isZero();
        assertThat(back.getQuestions()).hasSize(1);
        DnsQuestion q = back.getQuestions().get(0);
        assertThat(q.getLabels()).extracting(DnsLabel::getName)
                .containsExactly("www", "example", "com");
        assertThat(q.getLabels()).extracting(DnsLabel::getLen)
                .containsExactly(3, 7, 3);
        assertThat(q.getQtype()).isEqualTo(1);
        assertThat(q.getQclass()).isEqualTo(1);
    }

    /** 第二步全栈:分派树组装(长度/校验和/选择子自动接线)+ 逐层字节断言 + 解回。 */
    @Test
    void ethernetIpv4UdpDnsStackEncodeAndDecodeRoundTrip() {
        // builtin 实体带多重 @BindOn(ipv4 还挂 vlan、udp 还挂 ipv6…),注册表要求父协议全部在册
        ProtocolRegistry registry = ProtocolRegistry.create(EthernetFrame.class, ArpPacket.class,
                Ipv4Packet.class, Ipv6Packet.class, IcmpPacket.class, Icmpv6Packet.class,
                UdpSegment.class, TcpSegment.class, VlanFrame.class, DnsQuery.class);
        StackEncoder encoder = new StackEncoder(registry);

        EthernetFrame eth = new EthernetFrame();
        eth.setDstMac(0x001122334455L);      // 网关 MAC
        eth.setSrcMac(0x000C29A1B2C3L);      // 本机 MAC
        Ipv4Packet ip = new Ipv4Packet();
        ip.setSourceIp(ip("192.168.1.100"));
        ip.setDestinationIp(ip("8.8.8.8"));   // 公共解析器
        UdpSegment udp = new UdpSegment();
        udp.setSrcPort(12345);   // 显式临时源端口(非 0 → 不被自动接线覆盖)
        // dstPort 留 0 → 由 DNS 的 BindOn 第一子句「dstPort == 53」自动接线

        byte[] frame = encoder.encode(List.of(eth, ip, udp, query()));

        // ---- 整帧:14(eth) + 20(ip) + 8(udp) + 33(dns) = 75 ----
        // (任务书写的 30 为笔误:权威向量逐字节共 33 字节)
        assertThat(frame).hasSize(75);

        // Ethernet:etherType = 0x0800(自动接线)
        assertThat(frame[12]).isEqualTo((byte) 0x08);
        assertThat(frame[13]).isEqualTo((byte) 0x00);

        // IPv4:Ver/IHL=0x45、总长=58(20+38,钩子回填)、protocol=17(自动接线)
        assertThat(frame[14]).isEqualTo((byte) 0x45);
        int ipTotal = ((frame[16] & 0xFF) << 8) | (frame[17] & 0xFF);
        assertThat(ipTotal).isEqualTo(61);   // 20 + 41(钩子回填)
        assertThat(frame[23]).isEqualTo((byte) 17);
        assertThat(frame).containsSubsequence((byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x64);   // src 192.168.1.100 @26
        assertThat(Arrays.copyOfRange(frame, 30, 34)).containsExactly(0x08, 0x08, 0x08, 0x08);        // dst 8.8.8.8
        // IPv4 头校验和:头 20 字节反码和(含校验和)必为 0xFFFF
        long sum = 0;
        for (int i = 14; i + 1 < 34; i += 2) {
            sum += ((frame[i] & 0xFF) << 8) | (frame[i + 1] & 0xFF);
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assertThat(sum & 0xFFFF).isEqualTo(0xFFFF);

        // UDP:srcPort=12345(0x3039,显式保留)、dstPort=53(0x0035,自动接线)、length=41(8+33,钩子回填)
        int srcPort = ((frame[34] & 0xFF) << 8) | (frame[35] & 0xFF);
        int dstPort = ((frame[36] & 0xFF) << 8) | (frame[37] & 0xFF);
        int udpLen = ((frame[38] & 0xFF) << 8) | (frame[39] & 0xFF);
        assertThat(srcPort).isEqualTo(12345);
        assertThat(dstPort).isEqualTo(53);
        assertThat(udpLen).isEqualTo(41);

        // DNS:帧内 [42,75) 与权威向量一致
        assertThat(Arrays.copyOfRange(frame, 42, 75)).containsExactly(DNS_QUERY_VECTOR);

        // ---- 解码:分派树 eth → ipv4 → udp → dns ----
        DecodedPacket out = new StackDecoder(registry, "ethernet").decode(frame, "eth0", 0L, 1);
        assertThat(out.protocolPath()).isEqualTo("ethernet▸ipv4▸udp▸real-dns-query");
        assertThat(out.layers()).hasSize(4);

        EthernetFrame dEth = (EthernetFrame) out.layers().get(0).packet();
        assertThat(dEth.getDstMac()).isEqualTo(0x001122334455L);
        assertThat(dEth.getSrcMac()).isEqualTo(0x000C29A1B2C3L);

        Ipv4Packet dIp = (Ipv4Packet) out.layers().get(1).packet();
        assertThat(dIp.getVersion()).isEqualTo(4);
        assertThat(dIp.getIhl()).isEqualTo(5);
        assertThat(dIp.getTotalLength()).isEqualTo(61);
        assertThat(dIp.getProtocol()).isEqualTo(17);
        assertThat(dIp.getSourceIp()).isEqualTo(ip("192.168.1.100"));
        assertThat(dIp.getDestinationIp()).isEqualTo(ip("8.8.8.8"));

        UdpSegment dUdp = (UdpSegment) out.layers().get(2).packet();
        assertThat(dUdp.getSrcPort()).isEqualTo(12345);
        assertThat(dUdp.getDstPort()).isEqualTo(53);
        assertThat(dUdp.getLength()).isEqualTo(41);
        assertThat(dUdp.getPayload()).containsExactly(DNS_QUERY_VECTOR);

        DnsQuery dDns = (DnsQuery) out.layers().get(3).packet();
        assertThat(out.layers().get(3).offset()).isEqualTo(42);
        assertThat(out.layers().get(3).headerLength()).isEqualTo(33);
        assertThat(dDns.getId()).isEqualTo(0x1234);
        assertThat(dDns.getFlags()).isEqualTo(0x0100);
        assertThat(dDns.getQdCount()).isEqualTo(1);
        DnsQuestion dq = dDns.getQuestions().get(0);
        assertThat(dq.getLabels()).extracting(DnsLabel::getName)
                .containsExactly("www", "example", "com");
        assertThat(dq.getQtype()).isEqualTo(1);
        assertThat(dq.getQclass()).isEqualTo(1);
    }

    // ---- 夹具与工具 ----

    /** 构造 www.example.com A IN 查询(与权威向量对应)。 */
    private static DnsQuery query() {
        DnsQuery q = new DnsQuery();
        q.setId(0x1234);
        q.setFlags(0x0100);
        q.setQdCount(1);
        DnsQuestion question = new DnsQuestion();
        for (String label : new String[]{"www", "example", "com"}) {
            DnsLabel l = new DnsLabel();
            l.setLen(label.length());
            l.setName(label);
            question.getLabels().add(l);
        }
        question.setQtype(1);   // A
        question.setQclass(1);  // IN
        q.getQuestions().add(question);
        return q;
    }

    private static int ip(String s) {
        String[] p = s.split("\\.");
        return (Integer.parseInt(p[0]) << 24) | (Integer.parseInt(p[1]) << 16)
                | (Integer.parseInt(p[2]) << 8) | Integer.parseInt(p[3]);
    }

    private static byte[] hex(String s) {
        String clean = s.replaceAll("\\s+", "");
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
