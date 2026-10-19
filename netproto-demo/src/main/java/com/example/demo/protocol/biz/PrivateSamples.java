package com.example.demo.protocol.biz;

import com.example.demo.protocol.biz.gxtp.GxConfBlob;
import com.example.demo.protocol.biz.gxtp.GxConfNumber;
import com.example.demo.protocol.biz.gxtp.GxConfString;
import com.example.demo.protocol.biz.gxtp.GxConfigBody;
import com.example.demo.protocol.biz.gxtp.GxFileChunk;
import com.example.demo.protocol.biz.gxtp.GxLoginReq;
import com.example.demo.protocol.biz.gxtp.GxSensor;
import com.example.demo.protocol.biz.gxtp.GxTelemetryReport;
import com.example.demo.protocol.biz.gxtp.GxtpFlag;
import com.example.demo.protocol.biz.gxtp.GxtpHeader;
import com.example.demo.protocol.biz.mtalk.MtalkEvent;
import com.example.demo.protocol.biz.mtalk.MtalkEventBatch;
import com.example.demo.protocol.biz.mtalk.MtalkHeader;
import com.example.demo.protocol.biz.mtalk.MtalkHello;
import com.example.demo.protocol.biz.xeth.XethAlarm;
import com.example.demo.protocol.biz.xeth.XethFrame;
import com.example.demo.protocol.biz.xeth.XethOption;
import com.example.demo.protocol.biz.xeth.XethSample;
import com.example.demo.protocol.biz.xeth.XethTelemetry;
import com.example.netproto.protocols.builtin.EthernetFrame;
import com.example.netproto.protocols.builtin.Ipv4Packet;
import com.example.netproto.protocols.builtin.TcpSegment;
import com.example.netproto.protocols.builtin.UdpSegment;
import com.example.netproto.stack.StackEncoder;

import java.util.List;

/**
 * 私有协议族样例报文工厂(测试与页面「注入样例」端点共用)。
 * <p>
 * 注意:组装时从不手写 etherType/protocol/端口/msgType —— 这些选择器字段
 * 全部由 StackEncoder 按 @BindOn 条件自动回填(autoWire),这正是注解式组包的卖点。
 */
public final class PrivateSamples {

    private final StackEncoder encoder;

    public PrivateSamples(StackEncoder encoder) {
        this.encoder = encoder;
    }

    // ---- 链路层辅助(etherType/protocol/端口均由 autoWire 自动填) ----

    private static EthernetFrame eth(long dst, long src) {
        EthernetFrame e = new EthernetFrame();
        e.setDstMac(dst);
        e.setSrcMac(src);
        return e;
    }

    private static int ip(String s) {
        String[] p = s.split("\\.");
        return (Integer.parseInt(p[0]) << 24) | (Integer.parseInt(p[1]) << 16)
                | (Integer.parseInt(p[2]) << 8) | Integer.parseInt(p[3]);
    }

    private static Ipv4Packet ipv4(String src, String dst) {
        Ipv4Packet p = new Ipv4Packet();
        p.setSourceIp(ip(src));
        p.setDestinationIp(ip(dst));
        return p;
    }

    private static UdpSegment udp(int srcPort) {
        UdpSegment u = new UdpSegment();
        u.setSrcPort(srcPort);       // dstPort 留零 → autoWire 按 7788 填
        return u;
    }

    private static TcpSegment tcp(int srcPort) {
        TcpSegment t = new TcpSegment();
        t.setSrcPort(srcPort);
        t.setSequenceNumber(1000);
        t.setAcknowledgmentNumber(0);
        return t;
    }

    // ---- 形态一:EtherType 0x88B5 直挂以太网 ----

    public byte[] xethTelemetry() {
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                XethFrame.of(1, 0x0102, List.of(
                        XethOption.of(1, new byte[]{0x11}),
                        XethOption.of(2, new byte[]{0x22, 0x33}))),
                XethTelemetry.of(0x0701, List.of(
                        XethSample.of(1_728_000_000L, 2350),
                        XethSample.of(1_728_000_100L, 2380),
                        XethSample.of(1_728_000_200L, 2410)))));
    }

    public byte[] xethAlarm() {
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                XethFrame.of(2, 0x0103, List.of()),
                XethAlarm.of(2, 0x3001, "PSU voltage below threshold")));
    }

    // ---- 形态二:UDP 7788 公共头 + msgType 分派 ----

    public byte[] gxLogin() {
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("192.168.10.30", "192.168.10.99"),
                udp(53210),
                GxtpHeader.of(1, 0x9AC1F00DL, GxtpFlag.ACK_REQ),
                GxLoginReq.of("gateway-07",
                        new byte[]{0x5A, 0x6F, 0x6B, 0x65, 0x6E},
                        "reboot after upgrade")));
    }

    public byte[] gxTelemetry() {
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("192.168.10.30", "192.168.10.99"),
                udp(53211),
                GxtpHeader.of(2, 0x9AC1F00EL),
                GxTelemetryReport.of(0x0000A1B2L, List.of(
                        GxSensor.of(1, 2345),
                        GxSensor.of(2, 876),
                        GxSensor.of(3, 1502)))));
    }

    public byte[] gxConfig() {
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("192.168.10.99", "192.168.10.30"),
                udp(7788),
                GxtpHeader.of(3, 0x9AC1F00FL),
                GxConfigBody.of(List.of(
                        GxConfNumber.of(0x1001, 300),
                        GxConfString.of(0x1002, "upload.example.com:9443"),
                        GxConfBlob.of(0x1003, new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})))));
    }

    public byte[] gxFileChunk() {
        byte[] data = new byte[64];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("192.168.10.30", "192.168.10.99"),
                udp(53212),
                GxtpHeader.of(4, 0x9AC1F010L, GxtpFlag.RETRANSMIT),
                GxFileChunk.of(7, 3, 12, data)));
    }

    // ---- 形态三:TCP 8899 公共头 + cmd 分派 ----

    public byte[] mtalkHello() {
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("10.20.30.40", "10.20.30.41"),
                tcp(49152),
                MtalkHeader.of(0x10, 0, 0x5EEDBEEFL),
                MtalkHello.of(new byte[]{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F})));
    }

    public byte[] mtalkEvents() {
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("10.20.30.40", "10.20.30.41"),
                tcp(49153),
                MtalkHeader.of(0x20, 0, 0x5EEDBEF0L),
                MtalkEventBatch.of(List.of(
                        MtalkEvent.of(1, new byte[]{0x01}),
                        MtalkEvent.of(2, new byte[]{0x02, 0x03}),
                        MtalkEvent.of(3, new byte[]{})))));
    }
}
