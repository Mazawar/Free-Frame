package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.Protocol;
import com.netproto.protocols.builtin.EthernetFrame;
import com.netproto.protocols.builtin.Ipv4Packet;
import com.netproto.protocols.builtin.UdpSegment;
import com.netproto.stack.DecodedPacket;
import com.netproto.stack.ProtocolRegistry;
import com.netproto.stack.StackDecoder;
import com.netproto.stack.StackEncoder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 智能配电接入协议 编码/解码用法演示 —— 这份测试就是「如何用」的文档:
 * <ol>
 *   <li>{@link #encodePojoToBytes}:POJO → 字节(业务侧发报文)</li>
 *   <li>{@link #decodeBytesToPojo}:字节 → POJO(业务侧收报文,手拼 hex 也能解)</li>
 *   <li>{@link #roundTripStatusReport}:编码再解码,字段无损往返</li>
 *   <li>{@link #fullStackEthernetToBusiness}:整栈组帧 + 自顶向下分派(观测页视角)</li>
 *   <li>{@link #countDrivenListParamQueryResp}:计数驱动变长列表(个数 × 条目 + 尾随校验和)</li>
 * </ol>
 * 引擎入口只有两个:编码 {@link StackEncoder#encode}(内层→外层逐层包装)、
 * 解码 {@link StackDecoder#decode}(从根协议自顶向下按 @BindOn 分派)。
 */
class PowerDistProtocolTest {

    private static ProtocolRegistry registry;
    private static StackEncoder encoder;
    /** 根 = ethernet:观测页/抓包视角,整帧自顶向下。 */
    private static StackDecoder stackDecoder;
    /** 根 = pd:业务后端视角,拿到 UDP 数据报字节直接解业务层。 */
    private static StackDecoder pdDecoder;

    @BeforeAll
    static void init() {
        // 注册 = 内置栈 + 配电协议(与 Spring 自动装配扫描同一机制)
        List<Class<?>> classes = new ArrayList<>();
        classes.addAll(scan("com.netproto.protocols.builtin"));
        classes.addAll(scan("com.netproto.demo.protocol.powerdist"));
        registry = ProtocolRegistry.create(classes);
        registry.validateBindings();
        encoder = new StackEncoder(registry);
        stackDecoder = new StackDecoder(registry, "ethernet");
        pdDecoder = new StackDecoder(registry, "pd");
    }

    // ===== 1. 编码:POJO → 字节 =====

    @Test
    @DisplayName("编码:终端开机注册 POJO → 22 字节报文")
    void encodePojoToBytes() {
        PdFrame header = new PdFrame();          // 默认值:版本 0x21/源=1 号终端/目标=平台/流水 1/令牌 0
        PdRegister reg = new PdRegister();       // 默认值:标准DTU(01)/以太网(00)/注册时间 5F304000
        reg.setRegTime(0x5F304000L);

        // 只给两层 [pd, pd-reg]:编码器从最内层往外包装,
        // 信令类型(signalType=01)由 pd-reg 的 @BindOn 条件自动接线,报文长度由 onPayload 自动回填。
        byte[] frame = encoder.encode(List.of(header, reg));

        // 16B 头 + 6B 信令体;手写期望字节逐字节核对(大端)
        assertEquals(
                "21 01 00 00 00 01 00 00 00 00 00 01 00 00 00 16"   // 头:版本/信令/源/目标/流水/令牌/长度
                        + " 01 00 5F 30 40 00",                       // 体:型号/组网/注册时间
                hex(frame));
        assertEquals(22, frame.length);
    }

    // ===== 2. 解码:字节 → POJO =====

    @Test
    @DisplayName("解码:手拼的「注册许可」字节 → 两层 POJO 字段可读")
    void decodeBytesToPojo() {
        // 平台下发的注册许可:版本21 信令02 源=平台 目标=1号终端 流水1 令牌ABCD 长度21(0x15)
        // 信令体:注册结果 00 成功 + 令牌有效期 0E10(3600s)
        byte[] frame = hex("21 02 00 00 00 00 00 00 00 01 00 01 AB CD 00 15"
                + " 00 00 00 0E 10");

        // 业务后端视角:UDP 数据报字节直接从 pd 根开始解
        DecodedPacket p = pdDecoder.decode(frame, "udp", 0, 1);

        assertEquals("pd▸pd-reg-grant", p.protocolPath());   // 信令类型 02 命中注册许可
        PdFrame h = (PdFrame) p.layers().get(0).packet();
        assertEquals(0xABCD, h.getToken());                  // 公共头字段直接可读
        assertEquals(0, h.getSrcAddr());                    // 源 = 平台
        PdRegisterGrant g = (PdRegisterGrant) p.layers().get(1).packet();
        assertEquals(0, g.getResult());                     // 注册成功
        assertEquals(0x0E10, g.getTtl());                   // 令牌有效期 3600s
    }

    // ===== 3. 往返:编码 → 解码,字段无损 =====

    @Test
    @DisplayName("往返:状态上报 编码再解码,业务字段无损")
    void roundTripStatusReport() {
        PdFrame header = new PdFrame();
        header.setSeqNo(7);
        header.setToken(0xABCD);
        PdStatusReport r = new PdStatusReport();
        r.setVoltage(2350);
        r.setCurrent(86);
        r.setTemp(41);
        r.setRunStatus(2);                                     // 检修

        byte[] frame = encoder.encode(List.of(header, r));
        DecodedPacket p = pdDecoder.decode(frame, "udp", 0, 1);

        assertEquals("pd▸pd-status-report", p.protocolPath());
        PdStatusReport back = (PdStatusReport) p.layers().get(1).packet();
        assertEquals(2350, back.getVoltage());
        assertEquals(86, back.getCurrent());
        assertEquals(41, back.getTemp());
        assertEquals(2, back.getRunStatus());
        PdFrame backHeader = (PdFrame) p.layers().get(0).packet();
        assertEquals(7, backHeader.getSeqNo());
        assertEquals(0xABCD, backHeader.getToken());
        assertEquals(22, frame.length);                        // 16B 头 + 6B 体
    }

    // ===== 4. 整栈:观测页视角(ethernet 自顶向下分派到业务层) =====

    @Test
    @DisplayName("整栈:eth▸ipv4▸udp▸pd▸pd-reg 五层组帧并分派到底")
    void fullStackEthernetToBusiness() {
        EthernetFrame eth = new EthernetFrame();
        eth.setDstMac(0xFFFFFFFFFFFFL);
        eth.setSrcMac(0x020000000001L);
        Ipv4Packet ip = new Ipv4Packet();
        ip.setSourceIp(ip("192.168.1.100"));
        ip.setDestinationIp(ip("192.168.1.200"));
        UdpSegment udp = new UdpSegment();
        udp.setSrcPort(51888);
        udp.setDstPort(9000);                                  // UDP 9000 → 命中 pd 绑定
        PdFrame header = new PdFrame();
        PdRegister reg = new PdRegister();

        // 外层 → 内层传整条栈;etherType/protocol/端口/长度/信令类型全部自动接线
        byte[] frame = encoder.encode(List.of(eth, ip, udp, header, reg));

        DecodedPacket p = stackDecoder.decode(frame, "inject", 0, 1);
        assertEquals("ethernet▸ipv4▸udp▸pd▸pd-reg", p.protocolPath());
        UdpSegment udpBack = (UdpSegment) p.layers().get(2).packet();
        assertEquals(22, udpBack.getLength() - 8);             // UDP 长度 - 头 = pd 帧长
        PdRegister regBack = (PdRegister) p.layers().get(4).packet();
        assertEquals(1, regBack.getModel());                   // 业务字段跨四层无损
    }

    // ===== 5. 变长:计数驱动列表 + 尾随字段 =====

    @Test
    @DisplayName("变长:参数查询响应 2 条参数(1+2×3+2=9B 体),列表与尾随校验和都解出")
    void countDrivenListParamQueryResp() {
        PdFrame header = new PdFrame();
        PdParamQueryResp resp = new PdParamQueryResp();        // 默认 2 条:采集周期 3C / 告警阈值 190

        byte[] frame = encoder.encode(List.of(header, resp));
        assertEquals(25, frame.length);                        // 16 头 + 1 个数 + 2×3 条目 + 2 校验和

        DecodedPacket p = pdDecoder.decode(frame, "udp", 0, 1);
        assertEquals("pd▸pd-param-query-resp", p.protocolPath());
        PdParamQueryResp back = (PdParamQueryResp) p.layers().get(1).packet();
        assertEquals(2, back.getParamCount());
        assertEquals(2, back.getParams().size());
        assertEquals(1, back.getParams().get(0).getParamId());
        assertEquals(0x3C, back.getParams().get(0).getValue());
        assertEquals(0x190, back.getParams().get(1).getValue());
        assertEquals(0x55AA, back.getChecksum());              // 列表之后的尾随字段照常解出
    }

    // ---- 辅助 ----

    private static List<Class<?>> scan(String pkg) {
        ClassPathScanningCandidateComponentProvider scanner =
                new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(Protocol.class));
        List<Class<?>> out = new ArrayList<>();
        for (BeanDefinition bd : scanner.findCandidateComponents(pkg)) {
            try {
                out.add(Class.forName(bd.getBeanClassName()));
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException(e);
            }
        }
        return out;
    }

    private static byte[] hex(String s) {
        String clean = s.replace(" ", "");
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(String.format("%02X", b[i]));
        }
        return sb.toString();
    }

    private static int ip(String s) {
        String[] p = s.split("\\.");
        return (Integer.parseInt(p[0]) << 24) | (Integer.parseInt(p[1]) << 16)
                | (Integer.parseInt(p[2]) << 8) | Integer.parseInt(p[3]);
    }
}
