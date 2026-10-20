package com.netproto.demo.protocol.realworld;

import com.netproto.demo.protocol.realworld.dlt645.Dlt645Frame;
import com.netproto.demo.protocol.realworld.iso8583.Iso8583Message;
import com.netproto.demo.protocol.realworld.modbus.MbReadHoldingResp;
import com.netproto.demo.protocol.realworld.modbus.MbWriteMultiReq;
import com.netproto.demo.protocol.realworld.modbus.ModbusTcpFrame;
import com.netproto.demo.protocol.realworld.mqtt.MqttConnect;
import com.netproto.demo.protocol.realworld.mqtt.MqttFixedHeader;
import com.netproto.demo.protocol.realworld.s7.S7Header;
import com.netproto.demo.protocol.realworld.s7.S7Item;
import com.netproto.demo.protocol.realworld.s7.S7ReadJob;
import com.netproto.annotation.Protocol;
import com.netproto.core.ProtocolCodec;
import com.netproto.protocols.builtin.TcpSegment;
import com.netproto.stack.DecodedPacket;
import com.netproto.stack.ProtocolRegistry;
import com.netproto.stack.StackDecoder;
import com.netproto.stack.StackEncoder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 真实协议满足度验证:Modbus TCP / S7comm / DL/T 645 / ISO 8583 / MQTT / Kafka。
 * 每个用例都是「真实字节布局 ↔ 注解 POJO」的双向验证(手拼字节→解析、POJO→组装)。
 */
class RealWorldTest {

    private static ProtocolRegistry registry;
    private static StackEncoder encoder;
    private static StackDecoder decoder;
    private static RealWorldSamples samples;

    @BeforeAll
    static void init() {
        List<Class<?>> classes = new ArrayList<>();
        classes.addAll(scan("com.netproto.protocols.builtin"));
        classes.addAll(scan("com.netproto.demo.protocol.realworld"));
        registry = ProtocolRegistry.create(classes);
        registry.validateBindings();
        encoder = new StackEncoder(registry);
        decoder = new StackDecoder(registry, "ethernet");
        samples = new RealWorldSamples(encoder);
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

    // ================= Modbus TCP =================

    @Test
    void modbusReadRespRegistersUntilEnd() {
        DecodedPacket p = decoder.decode(samples.modbusReadResp(), "t", 0L, 1);
        assertEquals(List.of("ethernet", "ipv4", "tcp", "modbus", "modbus-read-resp"), ids(p));
        assertEquals(502, ((TcpSegment) p.layers().get(2).packet()).getDstPort());  // autoWire

        ModbusTcpFrame mb = (ModbusTcpFrame) p.layers().get(3).packet();
        assertEquals(3, mb.getFunctionCode());
        assertEquals(9, mb.getLength());   // unitId(1)+fc(1)+byteCount(1)+寄存器(6)

        MbReadHoldingResp resp = (MbReadHoldingResp) p.layers().get(4).packet();
        assertEquals(6, resp.getByteCount());
        assertEquals(3, resp.getRegisters().size());   // untilEnd 读到帧尾
        assertEquals(0x0BEE, resp.getRegisters().get(0).getValue());
        assertEquals(0x5678, resp.getRegisters().get(2).getValue());

        // LIST 元素级字节区间:层 @62,byteCount 1B → 寄存器 i 占 [63+2i, 65+2i)
        var respRanges = p.layers().get(4).fieldRanges();
        assertArrayEquals(new int[]{63, 65}, respRanges.get("registers[0]"));
        assertArrayEquals(new int[]{67, 69}, respRanges.get("registers[2]"));
    }

    @Test
    void modbusWriteMultiQuantityDrivenList() {
        DecodedPacket p = decoder.decode(samples.modbusWriteMulti(), "t", 0L, 2);
        assertEquals(List.of("ethernet", "ipv4", "tcp", "modbus", "modbus-write-multi"), ids(p));
        MbWriteMultiReq req = (MbWriteMultiReq) p.layers().get(4).packet();
        assertEquals(0x0064, req.getStartAddress());
        assertEquals(2, req.getQuantity());
        assertEquals(4, req.getByteCount());
        assertEquals(0x1111, req.getRegisters().get(0).getValue());   // countField=quantity 直接驱动
        assertEquals(0x2222, req.getRegisters().get(1).getValue());
    }

    // ================= S7comm =================

    @Test
    void s7ReadJobDescendsSevenLayers() {
        byte[] frame = samples.s7ReadJob();
        DecodedPacket p = decoder.decode(frame, "t", 0L, 3);
        assertEquals(List.of("ethernet", "ipv4", "tcp", "tpkt", "cotp", "s7", "s7-read-job"), ids(p));
        assertEquals(102, ((TcpSegment) p.layers().get(2).packet()).getDstPort());

        var tpkt = (com.netproto.demo.protocol.realworld.s7.TpktFrame) p.layers().get(3).packet();
        int paramLen = 1 + 1 + 12;                       // function + itemCount + 1 个 item
        assertEquals(4 + 3 + 10 + paramLen, tpkt.getLength());   // 总长含全部头

        var s7 = (S7Header) p.layers().get(5).packet();
        assertEquals(0x32, s7.getProtocolId());
        assertEquals(1, s7.getMsgType());
        assertEquals(paramLen, s7.getParamLength());

        // item 地址:endian=LITTLE,字段即语义值 100×8=800,线上字节小端 20 03 00
        // 帧内偏移:eth(14)+ip(20)+tcp(20)=54 | tpkt(4) cotp(3) s7头(10) function+itemCount(2) item 头 9B → 地址区 @82
        var job = (S7ReadJob) p.layers().get(6).packet();
        assertEquals(1, job.getItems().size());
        S7Item item = job.getItems().get(0);
        assertEquals(800, item.getAddress());          // 语义值(不再需要手动反转)
        assertEquals(0x20, frame[82] & 0xFF);          // 线上仍为小端字节序
        assertEquals(0x03, frame[83] & 0xFF);
        assertEquals(0x00, frame[84] & 0xFF);
    }

    // ================= DL/T 645 =================

    @Test
    void dlt645ReadRespHandBuiltBytes() {
        // 手拼规约帧:68 | addr(低位在前 6B) | 68 | 控制码 0x91(dir=1,func=0x11) |
        // L=8 | DI(4B) | 数据(4B) | CS | 16
        byte[] frame = new byte[]{
                (byte) 0x68, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0x68,
                (byte) 0x91, 0x08,
                0x00, 0x00, 0x01, 0x00,                       // DI0..DI3
                0x33, 0x33, 0x33, 0x33,                       // 电能量 BCD
                0x00,                                          // CS 占位
                0x16};
        // 规约手算 CS = 除 CS 与 16H 外累加和 mod 256
        int sum = 0;
        for (int i = 0; i < frame.length - 2; i++) {
            sum += frame[i] & 0xFF;
        }
        frame[frame.length - 2] = (byte) (sum & 0xFF);

        Dlt645Frame f = new ProtocolCodec<>(Dlt645Frame.class).deserialize(frame);
        assertEquals(1, f.getDirBit());       // 控制码 1+1+1+5 位拆分
        assertEquals(0, f.getErrBit());
        assertEquals(0x11, f.getFuncCode());
        assertEquals(8, f.getDataLen());
        assertEquals(0x00000100L, f.getDataId());
        assertArrayEquals(new byte[]{0x33, 0x33, 0x33, 0x33}, f.getData());  // L-4(lengthAdjust)
        assertEquals(sum & 0xFF, f.getCs());

        // round-trip:encode 的 CS 与手算一致,全帧字节一致
        byte[] out = new ProtocolCodec<>(Dlt645Frame.class).serialize(f);
        assertArrayEquals(frame, out);
    }

    // ================= ISO 8583 =================

    @Test
    void iso8583BitmapDrivenConditionalFields() {
        // 0100 + bitmap(f3,f4,f11,f41,f42) + 条件字段
        String f3 = "123456";
        String f4 = "000000012300";
        String f11 = "000123";
        String f41 = "TERM0001";
        String f42 = "MERCHANT0001234";
        byte[] bitmap = new byte[]{
                0x30, 0x20, 0x00, 0x00, 0x00, (byte) 0xC0, 0x00, 0x00};
        byte[] frame = new byte[4 + 8 + f3.length() + f4.length() + f11.length()
                + f41.length() + f42.length()];
        System.arraycopy("0100".getBytes(), 0, frame, 0, 4);
        System.arraycopy(bitmap, 0, frame, 4, 8);
        int off = 12;
        for (String v : new String[]{f3, f4, f11, f41, f42}) {
            byte[] vb = v.getBytes();
            System.arraycopy(vb, 0, frame, off, vb.length);
            off += vb.length;
        }

        Iso8583Message m = new ProtocolCodec<>(Iso8583Message.class).deserialize(frame);
        // 位图一等语法:bitmap 为 64bit 语义值,MSB 起数 bit n == 线上第 n 个字段位
        assertEquals(0x3020000000C00000L, m.getBitmap());   // 30 20 .. C0 ..
        assertEquals(f3, m.getProcessingCode());
        assertEquals(f4, m.getAmount());
        assertEquals(f11, m.getStan());
        assertEquals(f41, m.getTerminalId());
        assertEquals(f42, m.getMerchantId());
        assertEquals("", m.getTransmission());   // bit7=0 → 缺席,默认值

        // round-trip
        byte[] out = new ProtocolCodec<>(Iso8583Message.class).serialize(m);
        assertArrayEquals(frame, out);
    }

    @Test
    void iso8583SparseBitmapOmitsFields() {
        // 只置 f3:bitmap = 20 00 .. → 仅 processingCode 出现
        byte[] frame = new byte[4 + 8 + 6];
        System.arraycopy("0810".getBytes(), 0, frame, 0, 4);
        frame[4] = 0x20;
        System.arraycopy("654321".getBytes(), 0, frame, 12, 6);
        Iso8583Message m = new ProtocolCodec<>(Iso8583Message.class).deserialize(frame);
        assertEquals("654321", m.getProcessingCode());
        assertEquals(0x2000000000000000L, m.getBitmap());   // 仅 bit3
        assertEquals("", m.getAmount());
    }

    @Test
    void iso8583LlvarPanWithAsciiLength() {
        // F2 LLVAR:bitmap bit2 + "16"(两位 ASCII 长度) + 16 位 PAN
        String pan = "4111111111111111";
        byte[] frame = new byte[4 + 8 + 2 + pan.length()];
        System.arraycopy("0100".getBytes(), 0, frame, 0, 4);
        frame[4] = 0x40;                                   // bit2 → 首字节 0100 0000
        System.arraycopy("16".getBytes(), 0, frame, 12, 2);
        System.arraycopy(pan.getBytes(), 0, frame, 14, pan.length());

        Iso8583Message m = new ProtocolCodec<>(Iso8583Message.class).deserialize(frame);
        assertEquals("16", m.getPanLen());                 // ASCII 长度前缀
        assertEquals(pan, m.getPan());                     // lengthAscii 驱动变长

        // 组装方向:setField2 自动生成两位 ASCII 长度,round-trip 字节一致
        Iso8583Message out = new Iso8583Message();
        out.setField2(pan);
        byte[] encoded = new ProtocolCodec<>(Iso8583Message.class).serialize(out);
        assertArrayEquals(frame, encoded);
    }

    // ================= MQTT =================

    @Test
    void mqttConnectWithCredentialsRoundTrip() {
        DecodedPacket p = decoder.decode(samples.mqttConnect(), "t", 0L, 4);
        assertEquals(List.of("ethernet", "ipv4", "tcp", "mqtt", "mqtt-connect"), ids(p));
        assertEquals(1883, ((TcpSegment) p.layers().get(2).packet()).getDstPort());

        MqttFixedHeader h = (MqttFixedHeader) p.layers().get(3).packet();
        assertEquals(1, h.getType());
        assertNotNull(h.getRemainingLength());

        MqttConnect c = (MqttConnect) p.layers().get(4).packet();
        assertEquals("MQTT", c.getProtoName());
        assertEquals(4, c.getLevel());
        assertEquals(1, c.getUsernameFlag());     // connectFlags 位拆分
        assertEquals("device1", c.getUsername());
        assertEquals("s3cret", c.getPassword());
        assertEquals(1, c.getCleanSession());
    }

    @Test
    void mqttRemainingLengthMultiByteVarint() {
        // clientId 长 130 字节 → 剩余长度 > 127 → varint 2 字节(无凭据分支)
        String longId = "s".repeat(130);
        MqttConnect c = MqttConnect.of(longId, null, null, true);
        byte[] body = new ProtocolCodec<>(MqttConnect.class).serialize(c);

        byte[] frame = samples.mqttConnectLongClientId();
        DecodedPacket p = decoder.decode(frame, "t", 0L, 5);
        assertEquals(List.of("ethernet", "ipv4", "tcp", "mqtt", "mqtt-connect"), ids(p));
        MqttFixedHeader hd = (MqttFixedHeader) p.layers().get(3).packet();
        assertEquals(body.length, hd.getRemainingLength().longValue());   // varint 编解码往返
        MqttConnect cd = (MqttConnect) p.layers().get(4).packet();
        assertEquals(longId, cd.getClientId());
        assertEquals(0, cd.getUsernameFlag());     // 未带凭据 → usernameFlag=0 → 字段组缺席
        assertEquals("", cd.getUsername());
    }

    // ================= Kafka =================

    @Test
    void kafkaMetadataInt32PrefixArrays() {
        DecodedPacket p = decoder.decode(samples.kafkaMetadata(), "t", 0L, 6);
        assertEquals(List.of("ethernet", "ipv4", "tcp", "kafka", "kafka-metadata"), ids(p));
        assertEquals(9092, ((TcpSegment) p.layers().get(2).packet()).getDstPort());

        var h = (com.netproto.demo.protocol.realworld.kafka.KafkaRequestHeader) p.layers().get(3).packet();
        // length = apiKey(2)+apiVersion(2)+correlationId(4)+clientIdLen(2)+"producer-1"(10)
        //        + body(4 + (2+6) + (2+8)) = 10+10+22 = 42
        assertEquals(42, h.getLength());
        assertEquals(3, h.getApiKey());
        assertEquals("producer-1", h.getClientId());

        var meta = (com.netproto.demo.protocol.realworld.kafka.KafkaMetadataReq) p.layers().get(4).packet();
        assertEquals(2, meta.getTopicsCount());
        assertEquals("orders", meta.getTopics().get(0).getName());
        assertEquals("payments", meta.getTopics().get(1).getName());
    }
}
