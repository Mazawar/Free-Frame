package com.netproto.stack;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.ChecksumField;
import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.Checksum;
import com.netproto.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

/**
 * 核心模块自包含测试栈:迷你 eth/ip/udp + 业务叶子(app/hb)。
 * 不依赖 protocols 模块 —— 栈引擎的行为用内联夹具验证,
 * 真实协议栈(ethernet/ipv4/…)的解析见 netproto-protocols 模块测试。
 */
final class TestStacks {

    private TestStacks() {}

    static ProtocolRegistry registry() {
        return ProtocolRegistry.create(MiniEth.class, MiniIp.class, MiniUdp.class,
                MiniLeaf.class, MiniApp.class, MiniHb.class);
    }

    static final long DST_MAC = 0xFFFFFFFFFFFFL;
    static final long SRC_MAC = 0x020000000001L;
    static final int SRC_IP = ip("192.168.1.100");
    static final int DST_IP = ip("255.255.255.255");

    static int ip(String s) {
        String[] p = s.split("\\.");
        return (Integer.parseInt(p[0]) << 24) | (Integer.parseInt(p[1]) << 16)
                | (Integer.parseInt(p[2]) << 8) | Integer.parseInt(p[3]);
    }

    // ---- 迷你栈定义(14B eth / 14B ip / 6B udp) ----

    @Data
    @ToString
    @Protocol(id = "mini-eth")
    static class MiniEth {
        @ProtocolField(order = 1, size = 48) private long dstMac;
        @ProtocolField(order = 2, size = 48) private long srcMac;
        @ProtocolField(order = 3, size = 16) private int etherType;
        @Payload private byte[] payload;

        static MiniEth frame() {
            MiniEth e = new MiniEth();
            e.setDstMac(DST_MAC);
            e.setSrcMac(SRC_MAC);
            return e;
        }
    }

    @Data
    @ToString
    @Protocol(id = "mini-ip")
    @BindOn(parent = "mini-eth", when = "etherType == 0x0800")
    static class MiniIp implements Checksum, PayloadAware {
        @ProtocolField(order = 1, size = 4) private int version = 4;
        @ProtocolField(order = 2, size = 4) private int ihl = 5;
        @ProtocolField(order = 3, size = 16) private int totalLength;
        @ProtocolField(order = 4, size = 8) private int proto;
        @ProtocolField(order = 5, size = 16) @ChecksumField private int checksum;
        @ProtocolField(order = 6, size = 32) private int sourceIp;
        @ProtocolField(order = 7, size = 32) private int destinationIp;
        @Payload private byte[] payload;

        static MiniIp packet(int src, int dst) {
            MiniIp p = new MiniIp();
            p.setSourceIp(src);
            p.setDestinationIp(dst);
            return p;
        }

        @Override
        public void onPayload(byte[] inner) {
            this.totalLength = 14 + inner.length;
        }

        @Override
        public long compute(String field, byte[] serialized) {
            if (!"checksum".equals(field)) {
                return -1;
            }
            long sum = 0;
            for (int i = 0; i + 1 < 14; i += 2) {
                sum += ((serialized[i] & 0xFF) << 8) | (serialized[i + 1] & 0xFF);
            }
            while (sum > 0xFFFF) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            return (~sum) & 0xFFFF;
        }
    }

    @Data
    @ToString
    @Protocol(id = "mini-udp")
    @BindOn(parent = "mini-ip", when = "proto == 17")
    static class MiniUdp implements PayloadAware {
        @ProtocolField(order = 1, size = 16) private int srcPort;
        @ProtocolField(order = 2, size = 16) private int dstPort;
        @ProtocolField(order = 3, size = 16) private int length;
        @Payload private byte[] payload;

        static MiniUdp segment(int src, int dst) {
            MiniUdp u = new MiniUdp();
            u.setSrcPort(src);
            u.setDstPort(dst);
            return u;
        }

        @Override
        public void onPayload(byte[] inner) {
            this.length = 6 + inner.length;
        }
    }

    /** 固定 8 字节叶子协议(扮演 arp 角色:eth 直接命中,无 payload)。 */
    @Data
    @ToString
    @Protocol(id = "mini-leaf")
    @BindOn(parent = "mini-eth", when = "etherType == 0x0806")
    static class MiniLeaf {
        @ProtocolField(order = 1, size = 16) private int op;
        @ProtocolField(order = 2, size = 48) private long target;
    }

    /** 业务协议 1:固定头 + payload。 */
    @Data
    @ToString
    @Protocol(id = "mini-app")
    @BindOn(parent = "mini-udp", when = "dstPort == 9999 || srcPort == 9999")
    static class MiniApp {
        @ProtocolField(order = 1, size = 8) private int version = 1;
        @ProtocolField(order = 2, size = 8) private int type;
        @ProtocolField(order = 3, size = 32) private int sequenceId;
        @Payload private byte[] payloadData = new byte[0];

        static MiniApp message(int seq, byte[] payload) {
            MiniApp m = new MiniApp();
            m.setType(2);
            m.setSequenceId(seq);
            m.setPayloadData(payload);
            return m;
        }
    }

    /** 业务协议 2:varint(L2 逃生舱)+ sentinel String,全走核心 SPI。 */
    @Data
    @ToString
    @Protocol(id = "mini-hb")
    @BindOn(parent = "mini-udp", when = "dstPort == 9998 || srcPort == 9998")
    static class MiniHb {
        @ProtocolField(order = 1, size = 8) private int deviceType;
        @ProtocolField(order = 2, custom = com.netproto.core.VarintCodec.class) private Long uptimeMs;
        @ProtocolField(order = 3, sentinel = 0) private String hostname;

        static MiniHb of(long uptime, String host) {
            MiniHb h = new MiniHb();
            h.setDeviceType(7);
            h.setUptimeMs(uptime);
            h.setHostname(host);
            return h;
        }
    }
}
