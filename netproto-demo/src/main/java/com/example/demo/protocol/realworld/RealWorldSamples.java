package com.example.demo.protocol.realworld;

import com.example.demo.protocol.realworld.kafka.KafkaMetadataReq;
import com.example.demo.protocol.realworld.kafka.KafkaRequestHeader;
import com.example.demo.protocol.realworld.kafka.KafkaTopic;
import com.example.demo.protocol.realworld.modbus.MbReadHoldingResp;
import com.example.demo.protocol.realworld.modbus.MbWriteMultiReq;
import com.example.demo.protocol.realworld.modbus.ModbusTcpFrame;
import com.example.demo.protocol.realworld.mqtt.MqttConnect;
import com.example.demo.protocol.realworld.mqtt.MqttFixedHeader;
import com.example.demo.protocol.realworld.s7.S7Header;
import com.example.demo.protocol.realworld.s7.S7Item;
import com.example.demo.protocol.realworld.s7.S7ReadJob;
import com.example.demo.protocol.realworld.s7.TpktFrame;
import com.example.demo.protocol.realworld.s7.CotpFrame;
import com.example.netproto.protocols.builtin.EthernetFrame;
import com.example.netproto.protocols.builtin.Ipv4Packet;
import com.example.netproto.protocols.builtin.TcpSegment;
import com.example.netproto.stack.StackEncoder;

import java.util.List;

/**
 * 真实协议样例帧工厂(测试与页面注入共用)。网络协议走完整 eth 栈组装;
 * 串口/裸流协议(DL/T 645、ISO 8583)只做单层序列化(定界属采集层,见矩阵)。
 */
public final class RealWorldSamples {

    private final StackEncoder encoder;

    public RealWorldSamples(StackEncoder encoder) {
        this.encoder = encoder;
    }

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

    private static TcpSegment tcp(int srcPort, long seq) {
        TcpSegment t = new TcpSegment();
        t.setSrcPort(srcPort);
        t.setSequenceNumber(seq);
        return t;
    }

    // ---- Modbus TCP /502 ----

    public byte[] modbusReadResp() {
        ModbusTcpFrame mb = new ModbusTcpFrame();
        mb.setTransactionId(0x1A2B);
        mb.setUnitId(1);
        mb.setFunctionCode(3);
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("192.168.1.10", "192.168.1.20"),
                tcp(502, 500),
                mb,
                MbReadHoldingResp.of(0x0BEE, 0x1234, 0x5678)));
    }

    public byte[] modbusWriteMulti() {
        ModbusTcpFrame mb = new ModbusTcpFrame();
        mb.setTransactionId(0x00C4);
        mb.setUnitId(17);
        mb.setFunctionCode(16);
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("192.168.1.10", "192.168.1.20"),
                tcp(55123, 501),
                mb,
                MbWriteMultiReq.of(0x0064, 0x1111, 0x2222)));
    }

    // ---- S7comm /102 ----

    public byte[] s7ReadJob() {
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("10.0.0.5", "10.0.0.6"),
                tcp(4512, 900),
                new TpktFrame(),
                new CotpFrame(),
                s7Header(1, 0x0777),
                S7ReadJob.of(S7Item.db(1, 100, 4))));
    }

    public byte[] s7AckData() {
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("10.0.0.6", "10.0.0.5"),
                tcp(102, 901),
                new TpktFrame(),
                new CotpFrame(),
                s7Header(3, 0x0777),
                S7ReadJob.of(S7Item.db(1, 100, 4))));
    }

    private static S7Header s7Header(int msgType, int pduRef) {
        S7Header h = new S7Header();
        h.setMsgType(msgType);
        h.setPduRef(pduRef);
        return h;
    }

    // ---- MQTT /1883 ----

    public byte[] mqttConnect() {
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("192.168.0.22", "192.168.0.1"),
                tcp(52118, 1000),
                MqttFixedHeader.of(1, 0),
                MqttConnect.of("sensor-42", "device1", "s3cret", true)));
    }

    /** clientId 130 字节 → 剩余长度 >127 → varint 多字节(无凭据分支)。 */
    public byte[] mqttConnectLongClientId() {
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("192.168.0.22", "192.168.0.1"),
                tcp(52118, 1000),
                MqttFixedHeader.of(1, 0),
                MqttConnect.of("s".repeat(130), null, null, true)));
    }

    // ---- Kafka /9092 ----

    public byte[] kafkaMetadata() {
        return encoder.encode(List.of(
                eth(0xAABBCCDDEE01L, 0xAABBCCDDEE02L),
                ipv4("172.17.0.3", "172.17.0.2"),
                tcp(49231, 2000),
                KafkaRequestHeader.of(3, 0, 77, "producer-1"),
                KafkaMetadataReq.of(KafkaTopic.of("orders"), KafkaTopic.of("payments"))));
    }
}
