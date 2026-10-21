package com.netproto.demo.protocol;

import com.netproto.annotation.Protocol;
import com.netproto.demo.protocol.devcomm.DevFrame;
import com.netproto.demo.protocol.devcomm.DevReg;
import com.netproto.demo.protocol.iot.IotDevCfg;
import com.netproto.demo.protocol.iot.IotFrame;
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 三套协议(智能配电 9000 / 设备通信 9001 / 物联网 9002)按端口并存分派 + 各自链路解码。
 * 设备通信:6B 头 + 信令类型分派;物联网:16B 头 + 帧类型分派 + 计数列表 + 尾随保留/CRC。
 */
class MultiSystemProtocolTest {

    private static ProtocolRegistry registry;
    private static StackEncoder encoder;
    private static StackDecoder decoder;

    @BeforeAll
    static void init() {
        List<Class<?>> classes = new ArrayList<>();
        classes.addAll(scan("com.netproto.protocols.builtin"));
        classes.addAll(scan("com.netproto.demo.protocol"));
        registry = ProtocolRegistry.create(classes);
        registry.validateBindings();          // 三套同时注册:端口隔离,绑定互不冲突
        encoder = new StackEncoder(registry);
        decoder = new StackDecoder(registry, "ethernet");
    }

    @Test
    @DisplayName("设备通信(9001):注册帧 eth▸ipv4▸udp▸dev▸dev-reg 解到信令体")
    void devRegisterRoundTrip() {
        DevFrame header = new DevFrame();           // 默认 源=000001 终端A → 目标=000000 服务端
        DevReg reg = new DevReg();
        reg.setSecurity(0);                          // 注册:安全信息全 0

        byte[] frame = encoder.encode(List.of(eth(), ipv4("192.168.2.10"), udp(40000, 9001), header, reg));
        DecodedPacket p = decoder.decode(frame, "inject", 0, 1);

        assertEquals("ethernet▸ipv4▸udp▸dev▸dev-reg", p.protocolPath());
        DevFrame h = (DevFrame) p.layers().get(3).packet();
        assertEquals(1, h.getSrcDev());
        assertEquals(0, h.getDstDev());
        DevReg back = (DevReg) p.layers().get(4).packet();
        assertEquals(0, back.getSecurity());
    }

    @Test
    @DisplayName("物联网(9002):设备配置 计数列表+尾随保留/CRC 与头字段(源IP/端口/GPS)并存")
    void iotConfigWithTrailingFields() {
        IotFrame header = new IotFrame();
        header.setFrameType(1);
        IotDevCfg cfg = new IotDevCfg();             // 默认 1 条目 + 保留 + CRC

        byte[] frame = encoder.encode(List.of(eth(), ipv4("10.0.0.1"), udp(50000, 9002), header, cfg));
        DecodedPacket p = decoder.decode(frame, "inject", 0, 1);

        // 9002 端口 → 物联网链,不会串进 9000/9001 的协议
        assertEquals("ethernet▸ipv4▸udp▸iot▸iot-dev-cfg", p.protocolPath());
        IotFrame h = (IotFrame) p.layers().get(3).packet();
        assertEquals(0xC0A80164, h.getSrcIp());
        assertEquals(51888, h.getSrcPort());
        IotDevCfg back = (IotDevCfg) p.layers().get(4).packet();
        assertEquals(1, back.getEntryCount());
        assertEquals(1, back.getEntries().size());
        assertEquals(0x55AA, back.getCrc());         // 列表后的尾随 CRC 照常解出
        // 17 头 + 1 条数 + 16 条目 + 2 保留 + 2 CRC = 38
        assertEquals(79, frame.length);   // 整帧 = 42(eth+ip+udp) + 37(iot 层)
    }

    @Test
    @DisplayName("端口隔离:三套协议同注册表互不串扰")
    void portsKeepSystemsApart() {
        assertEquals(9000, com.netproto.demo.protocol.powerdist.PowerDistSamples.PD_PORT);
        // 分派树里 9000/9001/9002 各挂一套;任一帧只走自己的链(上面两用例已证)
        // 注册表规模:builtin 9 + 智能配电 19 + 设备通信 14 + 物联网 5 = 47
        // 47 个正式协议 + 2 个 PdCrcTrailerTest 实验夹具(同包测试类,仅测试 classpath 可见)
        assertEquals(49, registry.all().size(),
                registry.all().stream().map(e -> e.id()).sorted().toList().toString());
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

    private static EthernetFrame eth() {
        EthernetFrame e = new EthernetFrame();
        e.setDstMac(0xFFFFFFFFFFFFL);
        e.setSrcMac(0x020000000001L);
        return e;
    }

    private static Ipv4Packet ipv4(String src) {
        Ipv4Packet p = new Ipv4Packet();
        String[] a = src.split("\\.");
        String[] b = {"192", "168", "1", "200"};
        p.setSourceIp((Integer.parseInt(a[0]) << 24) | (Integer.parseInt(a[1]) << 16)
                | (Integer.parseInt(a[2]) << 8) | Integer.parseInt(a[3]));
        p.setDestinationIp((Integer.parseInt(b[0]) << 24) | (Integer.parseInt(b[1]) << 16)
                | (Integer.parseInt(b[2]) << 8) | Integer.parseInt(b[3]));
        return p;
    }

    private static UdpSegment udp(int srcPort, int dstPort) {
        UdpSegment u = new UdpSegment();
        u.setSrcPort(srcPort);
        u.setDstPort(dstPort);
        return u;
    }
}
