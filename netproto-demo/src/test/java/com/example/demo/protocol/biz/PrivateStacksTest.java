package com.example.demo.protocol.biz;

import com.example.demo.protocol.biz.gxtp.GxConfBlob;
import com.example.demo.protocol.biz.gxtp.GxConfNumber;
import com.example.demo.protocol.biz.gxtp.GxConfString;
import com.example.demo.protocol.biz.gxtp.GxConfigBody;
import com.example.demo.protocol.biz.gxtp.GxFileChunk;
import com.example.demo.protocol.biz.gxtp.GxLoginReq;
import com.example.demo.protocol.biz.gxtp.GxTelemetryReport;
import com.example.demo.protocol.biz.gxtp.GxtpHeader;
import com.example.demo.protocol.biz.mtalk.MtalkEventBatch;
import com.example.demo.protocol.biz.mtalk.MtalkHeader;
import com.example.demo.protocol.biz.xeth.XethAlarm;
import com.example.demo.protocol.biz.xeth.XethFrame;
import com.example.demo.protocol.biz.xeth.XethTelemetry;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.core.ProtocolCodec;
import com.example.netproto.protocols.builtin.EthernetFrame;
import com.example.netproto.protocols.builtin.Ipv4Packet;
import com.example.netproto.protocols.builtin.TcpSegment;
import com.example.netproto.protocols.builtin.UdpSegment;
import com.example.netproto.stack.DecodedPacket;
import com.example.netproto.stack.ProtocolRegistry;
import com.example.netproto.stack.StackDecoder;
import com.example.netproto.stack.StackEncoder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 私有协议族(三形态)后端核心验证:
 * <ol>
 *   <li>自顶向下分派:EtherType 直挂 / UDP 端口+字段两级分派 / TCP 端口+字段两级分派;</li>
 *   <li>注解式组包:选择器字段(etherType/protocol/端口/msgType/cmd)全部由 autoWire 自动回填;</li>
 *   <li>复杂度机制:presentIf 条件、countField/untilEnd 列表、lengthField 变长、
 *       sentinel 字符串、异质 TLV、校验和回写。</li>
 * </ol>
 */
class PrivateStacksTest {

    private static ProtocolRegistry registry;
    private static StackEncoder encoder;
    private static StackDecoder decoder;
    private static PrivateSamples samples;

    @BeforeAll
    static void init() {
        List<Class<?>> classes = new ArrayList<>();
        classes.addAll(scan("com.example.netproto.protocols.builtin"));
        classes.addAll(scan("com.example.demo.protocol.biz"));
        registry = ProtocolRegistry.create(classes);
        registry.validateBindings();
        encoder = new StackEncoder(registry);
        decoder = new StackDecoder(registry, "ethernet");
        samples = new PrivateSamples(encoder);
    }

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

    private static List<String> ids(DecodedPacket p) {
        return p.layers().stream().map(DecodedPacket.DecodedLayer::id).toList();
    }

    // ================= 形态一:EtherType 0x88B5 直挂 =================

    @Test
    void xethTelemetryDescendsAndAutoWires() {
        DecodedPacket p = decoder.decode(samples.xethTelemetry(), "t", 0L, 1);
        assertEquals(List.of("ethernet", "xeth", "xeth-tele"), ids(p));

        // autoWire:组装时未手写 etherType,由 xeth 的 @BindOn 条件自动回填
        EthernetFrame eth = (EthernetFrame) p.layers().get(0).packet();
        assertEquals(0x88B5, eth.getEtherType());

        XethFrame xeth = (XethFrame) p.layers().get(1).packet();
        assertEquals(1, xeth.getVersion());          // 4bit 位拆分字段
        assertEquals(1, xeth.getChannel());
        assertEquals(2, xeth.getOptCount());         // countField 列表
        assertEquals(2, xeth.getOptions().get(1).getOptLen());
        assertArrayEquals(new byte[]{0x22, 0x33}, xeth.getOptions().get(1).getValue());

        // untilEnd 列表:无 count 字段,读到帧尾
        XethTelemetry tele = (XethTelemetry) p.layers().get(2).packet();
        assertEquals(0x0701, tele.getDeviceId());
        assertEquals(3, tele.getSamples().size());
        assertEquals(1_728_000_200L, tele.getSamples().get(2).getTsMs());
        assertEquals(2410, tele.getSamples().get(2).getValue());
    }

    @Test
    void xethAlarmConditionalDetailBothBranches() {
        // 分支一:hasDetail=1(presentIf 字段组出现)
        DecodedPacket p = decoder.decode(samples.xethAlarm(), "t", 0L, 2);
        assertEquals(List.of("ethernet", "xeth", "xeth-alarm"), ids(p));
        XethAlarm alarm = (XethAlarm) p.layers().get(2).packet();
        assertEquals(2, alarm.getSeverity());
        assertEquals(0x3001, alarm.getAlarmCode());
        assertEquals("PSU voltage below threshold", alarm.getDetail());
        assertEquals(27, alarm.getDetailLen());

        // 分支二:hasDetail=0 → detailLen/detail 不存在,保持默认
        byte[] body = new byte[5];
        body[0] = 1;                       // severity
        body[1] = 0x30; body[2] = 0x02;    // alarmCode
        body[3] = 0;                       // hasDetail = 0
        XethAlarm bare = new ProtocolCodec<>(XethAlarm.class).deserialize(body);
        assertEquals(0, bare.getHasDetail());
        assertEquals("", bare.getDetail());
        assertEquals(0, bare.getDetailLen());
    }

    // ================= 形态二:UDP 7788 公共头 + msgType 分派 =================

    @Test
    void gxLoginDescendsThroughTwoLevelDispatch() {
        DecodedPacket p = decoder.decode(samples.gxLogin(), "t", 0L, 3);
        assertEquals(List.of("ethernet", "ipv4", "udp", "gxtp", "gx-login"), ids(p));

        // 三层选择器全部自动回填(样例只设了 srcPort/源目的 IP)
        assertEquals(0x0800, ((EthernetFrame) p.layers().get(0).packet()).getEtherType());
        assertEquals(17, ((Ipv4Packet) p.layers().get(1).packet()).getProtocol());
        assertEquals(7788, ((UdpSegment) p.layers().get(2).packet()).getDstPort());

        GxtpHeader h = (GxtpHeader) p.layers().get(3).packet();
        assertEquals(0x4758, h.getMagic());
        assertEquals(1, h.getMsgType());
        assertEquals(0x9AC1F00DL, h.getReqId());
        assertTrue(h.getFlags().contains(com.example.demo.protocol.biz.gxtp.GxtpFlag.ACK_REQ));

        GxLoginReq login = (GxLoginReq) p.layers().get(4).packet();
        assertEquals("gateway-07", login.getUsername());       // lengthField 字符串
        assertEquals(10, login.getUserLen());
        assertArrayEquals(new byte[]{0x5A, 0x6F, 0x6B, 0x65, 0x6E}, login.getToken());
        assertEquals("reboot after upgrade", login.getRemark());  // sentinel 零终止
    }

    @Test
    void gxLoginWithoutTokenOmitsConditionalFields() {
        // 手工字节:userLen=3 "abc" + hasToken=0 + remark "hi" + 0x00
        byte[] body = new byte[]{3, 'a', 'b', 'c', 0, 'h', 'i', 0};
        GxLoginReq r = new ProtocolCodec<>(GxLoginReq.class).deserialize(body);
        assertEquals("abc", r.getUsername());
        assertEquals(0, r.getHasToken());
        assertEquals(0, r.getTokenLen());   // presentIf 字段缺席,保持默认
        assertEquals("hi", r.getRemark());
    }

    @Test
    void gxTelemetryCountDrivenSensorList() {
        DecodedPacket p = decoder.decode(samples.gxTelemetry(), "t", 0L, 4);
        assertEquals(List.of("ethernet", "ipv4", "udp", "gxtp", "gx-telemetry"), ids(p));
        GxTelemetryReport r = (GxTelemetryReport) p.layers().get(4).packet();
        assertEquals(0x0000A1B2L, r.getGatewayId());
        assertEquals(3, r.getSensorCount());
        assertEquals(3, r.getSensors().size());      // countField 驱动,恰好吃满
        assertEquals(876, r.getSensors().get(1).getValueRaw());
    }

    @Test
    void gxConfigTlvDispatchWithEndMarkerAndUnknownTypeSkip() {
        DecodedPacket p = decoder.decode(samples.gxConfig(), "t", 0L, 5);
        assertEquals(List.of("ethernet", "ipv4", "udp", "gxtp", "gx-config"), ids(p));

        GxConfigBody cfg = (GxConfigBody) p.layers().get(4).packet();
        assertEquals(3, cfg.getItems().size());      // 异质 TLV:三种 value 实体
        GxConfNumber n = (GxConfNumber) cfg.getItems().get(0);
        assertEquals(0x1001, n.getConfId());
        assertEquals(300, n.getValue());
        GxConfString s = (GxConfString) cfg.getItems().get(1);
        assertEquals("upload.example.com:9443", s.getText());
        GxConfBlob b = (GxConfBlob) cfg.getItems().get(2);
        assertEquals(8, b.getBlobLen());

        byte[] frame = samples.gxConfig();
        assertEquals(0x00, frame[frame.length - 1]);  // tlvEndMarker 写入帧尾

        // 手工字节:插入未知 type=99 的 TLV 项 → 解析时跳过,不影响后续元素
        byte[] body = new byte[]{
                99, 2, 0x11, 0x22,                                    // 未知 type,跳过
                1, 6, 0x10, 0x01, 0x00, 0x00, 0x01, 0x2C,              // GxConfNumber(300)
                0                                                     // endMarker
        };
        GxConfigBody parsed = new ProtocolCodec<>(GxConfigBody.class).deserialize(body);
        assertEquals(1, parsed.getItems().size());
        assertEquals(300L, ((GxConfNumber) parsed.getItems().get(0)).getValue());
    }

    @Test
    void gxFileChunkChecksumWrittenBackByEngine() {
        byte[] frame = samples.gxFileChunk();
        // body 布局:fileId2+chunkIdx4+total4+dataLen2+data64+crc2 = 78 字节。
        // 引擎语义:整实体序列化(crc 字段置 0)→ compute → 回写(与 IPv4/TCP 校验和一致)。
        int bodyLen = 78;
        byte[] body = Arrays.copyOfRange(frame, frame.length - bodyLen, frame.length);
        body[bodyLen - 2] = 0;
        body[bodyLen - 1] = 0;
        int expected = GxFileChunk.crc16CcittFalse(body);
        int written = ((frame[frame.length - 2] & 0xFF) << 8) | (frame[frame.length - 1] & 0xFF);
        assertEquals(expected, written);   // 引擎置0→compute→回写

        DecodedPacket p = decoder.decode(frame, "t", 0L, 6);
        assertEquals(List.of("ethernet", "ipv4", "udp", "gxtp", "gx-file"), ids(p));
        GxFileChunk c = (GxFileChunk) p.layers().get(4).packet();
        assertEquals(written, c.getCrc16());
        assertEquals(64, c.getData().length);
        assertEquals(7, c.getFileId());
    }

    @Test
    void unknownMsgTypeStopsAtCommonHeader() {
        // msgType=99 未注册任何报文体 → 下降停在 gxtp 公共头(层内保留原始 payload)
        byte[] frame = encoder.encode(List.of(
                new com.example.netproto.protocols.builtin.EthernetFrame(),
                new Ipv4Packet(), new UdpSegment(),
                GxtpHeader.of(99, 1L)));
        DecodedPacket p = decoder.decode(frame, "t", 0L, 7);
        assertEquals(List.of("ethernet", "ipv4", "udp", "gxtp"), ids(p));
    }

    // ================= 形态三:TCP 8899 公共头 + cmd 分派 =================

    @Test
    void mtalkHelloOverTcpDispatch() {
        DecodedPacket p = decoder.decode(samples.mtalkHello(), "t", 0L, 8);
        assertEquals(List.of("ethernet", "ipv4", "tcp", "mtalk", "mtalk-hello"), ids(p));

        TcpSegment tcp = (TcpSegment) p.layers().get(2).packet();
        assertEquals(8899, tcp.getDstPort());                     // autoWire 填 TCP 端口
        MtalkHeader h = (MtalkHeader) p.layers().get(3).packet();
        assertEquals(0x10, h.getCmd());
        assertEquals(0x5EEDBEEFL, h.getSessionKey());
        var hello = (com.example.demo.protocol.biz.mtalk.MtalkHello) p.layers().get(4).packet();
        assertEquals("MTALK", hello.getProtoName());              // 定长字符串
        assertEquals(6, hello.getNonceLen());
    }

    @Test
    void mtalkEventsUntilEndWithSelfDelimitedElements() {
        DecodedPacket p = decoder.decode(samples.mtalkEvents(), "t", 0L, 9);
        assertEquals(List.of("ethernet", "ipv4", "tcp", "mtalk", "mtalk-events"), ids(p));
        MtalkEventBatch b = (MtalkEventBatch) p.layers().get(4).packet();
        assertEquals(3, b.getEvents().size());     // 变长元素 untilEnd(靠 dataLen 自定界)
        assertEquals(0, b.getEvents().get(2).getDataLen());
        assertArrayEquals(new byte[]{0x02, 0x03}, b.getEvents().get(1).getData());
    }
}
