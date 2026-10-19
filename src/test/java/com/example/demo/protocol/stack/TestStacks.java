package com.example.demo.protocol.stack;

import com.example.demo.protocol.HeartbeatMessage;
import com.example.demo.protocol.MyProtocol;
import com.example.demo.protocol.builtin.ArpPacket;
import com.example.demo.protocol.builtin.EthernetFrame;
import com.example.demo.protocol.builtin.IcmpPacket;
import com.example.demo.protocol.builtin.Ipv4Packet;
import com.example.demo.protocol.builtin.TcpSegment;
import com.example.demo.protocol.builtin.UdpSegment;

/** 测试栈:内置六协议 + my-app/heartbeat 业务协议。 */
final class TestStacks {

    private TestStacks() {}

    static ProtocolRegistry registry() {
        return ProtocolRegistry.create(
                EthernetFrame.class, ArpPacket.class, Ipv4Packet.class, IcmpPacket.class,
                UdpSegment.class, TcpSegment.class, MyProtocol.class, HeartbeatMessage.class);
    }

    static final long DST_MAC = 0xFFFFFFFFFFFFL;   // 广播
    static final long SRC_MAC = 0x020000000001L;
    static final int SRC_IP = ip("192.168.1.100");
    static final int DST_IP = ip("255.255.255.255");

    static int ip(String s) {
        String[] p = s.split("\\.");
        return (Integer.parseInt(p[0]) << 24) | (Integer.parseInt(p[1]) << 16)
                | (Integer.parseInt(p[2]) << 8) | Integer.parseInt(p[3]);
    }

    static EthernetFrame ethernet() {
        EthernetFrame eth = new EthernetFrame();
        eth.setDstMac(DST_MAC);
        eth.setSrcMac(SRC_MAC);
        return eth;
    }

    static Ipv4Packet ipv4() {
        Ipv4Packet ip = new Ipv4Packet();
        ip.setSourceIp(SRC_IP);
        ip.setDestinationIp(DST_IP);
        return ip;
    }

    static UdpSegment udp(int src, int dst) {
        UdpSegment udp = new UdpSegment();
        udp.setSrcPort(src);
        udp.setDstPort(dst);
        return udp;
    }

    static MyProtocol myApp(int seq, byte[] payload) {
        MyProtocol m = new MyProtocol();
        m.setType((byte) 2);
        m.setSequenceId(seq);
        m.setPayloadData(payload);
        return m;
    }

    static HeartbeatMessage heartbeat(long uptime, String host) {
        HeartbeatMessage h = new HeartbeatMessage();
        h.setDeviceType(7);
        h.setUptimeMs(uptime);
        h.setHostname(host);
        return h;
    }
}
