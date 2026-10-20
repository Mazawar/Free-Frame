package com.netproto.spring.capture;

import com.netproto.spring.web.LayerViews;
import com.netproto.stack.DecodedPacket;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 解码帧 → {@link FrameSummary}:提取表格列所需的端点/端口信息。
 * 与前端展示规则保持同一优先级:ipv4/ipv6 地址 → ARP 地址 → 以太网 MAC。
 */
public final class PacketSummarizer {

    private PacketSummarizer() {}

    public static FrameSummary summarize(DecodedPacket p) {
        String src = "-";
        String dst = "-";
        Integer srcPort = null;
        Integer dstPort = null;
        List<String> ids = new ArrayList<>();
        StringBuilder path = new StringBuilder();
        DecodedPacket.DecodedLayer transport = null;
        DecodedPacket.DecodedLayer arp = null;
        DecodedPacket.DecodedLayer icmp = null;
        for (DecodedPacket.DecodedLayer l : p.layers()) {
            ids.add(l.id());
            if (path.length() > 0) {
                path.append('▸');
            }
            path.append(l.id());
            Map<String, Object> f = LayerViews.fieldsOf(l.packet());
            // 外→内遍历、有值即覆盖:最终留下最深的提供者,优先级 ip > arp > eth 与前端一致
            Object s = pick(f, "sourceIp", "srcIp6", "senderIp", "srcMac");
            Object d = pick(f, "destinationIp", "dstIp6", "targetIp", "dstMac");
            if (s != null) src = String.valueOf(s);
            if (d != null) dst = String.valueOf(d);
            if (srcPort == null) {
                Object sp = f.get("srcPort");
                Object dp = f.get("dstPort");
                if (sp instanceof Number n && dp instanceof Number m) {
                    srcPort = n.intValue();
                    dstPort = m.intValue();
                }
            }
            switch (l.id()) {
                case "udp", "tcp" -> transport = l;
                case "arp" -> arp = l;
                case "icmp" -> icmp = l;
                default -> { }
            }
        }
        return new FrameSummary(p.capturedCount(), p.timestampMillis(), p.iface(),
                p.raw().length, path.toString(), List.copyOf(ids), src, dst, srcPort, dstPort,
                info(p, transport, arp, icmp), p.raw());
    }

    private static final java.util.Set<String> STACK_IDS = java.util.Set.of(
            "ethernet", "vlan", "ipv4", "ipv6", "udp", "tcp", "icmp", "icmpv6", "arp");

    /** 信息列(Wireshark 风格):端口 + 业务层名;ARP/ICMP 语义化描述。 */
    private static String info(DecodedPacket p, DecodedPacket.DecodedLayer transport,
                               DecodedPacket.DecodedLayer arp, DecodedPacket.DecodedLayer icmp) {
        var layers = p.layers();
        var last = layers.get(layers.size() - 1);
        String tailNote = tailBytes(p, last) > 0 ? ", 后续 " + tailBytes(p, last) + " B 无已注册子协议" : "";
        if (arp != null) {
            Map<String, Object> f = LayerViews.fieldsOf(arp.packet());
            Object op = f.get("operation");
            if (op instanceof Number n && n.intValue() == 1) {
                return "Who has " + f.get("targetIp") + "? Tell " + f.get("senderIp");
            }
            return f.get("senderIp") + " is at " + f.get("senderMac");
        }
        if (icmp != null) {
            Map<String, Object> f = LayerViews.fieldsOf(icmp.packet());
            int t = number(f.get("type")).intValue();
            if (t == 8) return "Echo (ping) request";
            if (t == 0) return "Echo (ping) reply";
            return "type=" + f.get("type") + " code=" + f.get("code");
        }
        if (transport != null) {
            Map<String, Object> f = LayerViews.fieldsOf(transport.packet());
            String s = f.get("srcPort") + " → " + f.get("dstPort");
            if (!STACK_IDS.contains(last.id())) {
                s += " [" + last.name() + tailNote + "]";
            }
            return s;
        }
        return last.name() + tailNote;
    }

    private static int tailBytes(DecodedPacket p, DecodedPacket.DecodedLayer last) {
        return Math.max(0, p.raw().length - (last.offset() + last.headerLength()));
    }

    private static Number number(Object v) {
        return v instanceof Number n ? n : null;
    }

    private static Object pick(Map<String, Object> f, String... keys) {
        for (String k : keys) {
            Object v = f.get(k);
            if (v != null && !"".equals(v)) {
                return v;
            }
        }
        return null;
    }
}
