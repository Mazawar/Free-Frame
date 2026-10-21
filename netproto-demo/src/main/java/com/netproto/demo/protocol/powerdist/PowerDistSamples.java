package com.netproto.demo.protocol.powerdist;

import com.netproto.protocols.builtin.EthernetFrame;
import com.netproto.protocols.builtin.Ipv4Packet;
import com.netproto.protocols.builtin.UdpSegment;
import com.netproto.stack.StackEncoder;

import java.util.List;

/**
 * 智能配电样例帧工厂(页面注入与测试共用):
 * 完整 eth▸ipv4▸udp▸pd▸信令 栈组装,演示一次注册 → 许可 → 上报的典型交互。
 */
public final class PowerDistSamples {

    /** 业务协议 UDP 端口(与 PdFrame @BindOn 一致)。 */
    public static final int PD_PORT = 9000;

    private final StackEncoder encoder;

    public PowerDistSamples(StackEncoder encoder) {
        this.encoder = encoder;
    }

    /** 终端开机注册(信令 0x01,令牌全 0)。 */
    public byte[] register() {
        PdFrame h = header(0x0001, 0);
        PdRegister reg = new PdRegister();     // 默认值:标准DTU/以太网/固定时间
        return encoder.encode(List.of(eth(), ipv4(), udp(51888), h, reg));
    }

    /** 平台注册许可(信令 0x02,分配令牌 0xABCD)。 */
    public byte[] registerGrant() {
        PdFrame h = header(0x0001, 0xABCD);
        h.setSrcAddr(0);                        // 平台 → 终端
        h.setDstAddr(1);
        return encoder.encode(List.of(eth(), ipv4(), udp(PD_PORT), h, new PdRegisterGrant()));
    }

    /** 终端状态上报(信令 0x21,携带许可后的令牌)。 */
    public byte[] statusReport() {
        PdFrame h = header(0x0002, 0xABCD);
        PdStatusReport r = new PdStatusReport();
        r.setRunStatus(1);                      // 告警态
        return encoder.encode(List.of(eth(), ipv4(), udp(51888), h, r));
    }

    /** 平台参数查询响应(信令 0x14,含 2 条参数的计数驱动列表)。 */
    public byte[] paramQueryResp() {
        PdFrame h = header(0x0003, 0xABCD);
        h.setSrcAddr(0);
        h.setDstAddr(1);
        return encoder.encode(List.of(eth(), ipv4(), udp(PD_PORT), h, new PdParamQueryResp()));
    }

    // ---- 栈组装辅助(字段默认值之外只填演示所需的) ----

    private static PdFrame header(int seq, int token) {
        PdFrame h = new PdFrame();
        h.setSeqNo(seq);
        h.setToken(token);
        return h;
    }

    private static EthernetFrame eth() {
        EthernetFrame e = new EthernetFrame();
        e.setDstMac(0xFFFFFFFFFFFFL);
        e.setSrcMac(0x020000000001L);
        return e;
    }

    private static Ipv4Packet ipv4() {
        Ipv4Packet p = new Ipv4Packet();
        p.setSourceIp(ip("192.168.1.100"));
        p.setDestinationIp(ip("192.168.1.200"));
        return p;
    }

    private static UdpSegment udp(int srcPort) {
        UdpSegment u = new UdpSegment();
        u.setSrcPort(srcPort);
        u.setDstPort(PD_PORT);
        return u;
    }

    private static int ip(String s) {
        String[] p = s.split("\\.");
        return (Integer.parseInt(p[0]) << 24) | (Integer.parseInt(p[1]) << 16)
                | (Integer.parseInt(p[2]) << 8) | Integer.parseInt(p[3]);
    }
}
