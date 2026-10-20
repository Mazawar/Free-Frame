package com.netproto.stack;

import java.util.List;

/**
 * 一次自顶向下解码的结构化结果:原始字节 + 命中的层链。
 * <p>
 * 每层记录:协议 id/显示名/解析出的对象/在原始帧中的偏移/头部长度(payload 之前),
 * 以及各顶层字段的帧绝对字节区间(供 UI 做字段 ↔ 字节联动高亮)。
 * 未被子协议消费的剩余字节不单独记录(= raw 减去各层头部)。
 */
public final class DecodedPacket {

    private final long timestampMillis;
    private final String iface;
    private final byte[] raw;
    private final List<DecodedLayer> layers;
    private final int capturedCount;   // 采集序号(单调递增,UI 稳定 key)

    public DecodedPacket(long timestampMillis, String iface, byte[] raw,
                         List<DecodedLayer> layers, int capturedCount) {
        this.timestampMillis = timestampMillis;
        this.iface = iface;
        this.raw = raw;
        this.layers = List.copyOf(layers);
        this.capturedCount = capturedCount;
    }

    public long timestampMillis() {
        return timestampMillis;
    }

    public String iface() {
        return iface;
    }

    public byte[] raw() {
        return raw;
    }

    public List<DecodedLayer> layers() {
        return layers;
    }

    public int capturedCount() {
        return capturedCount;
    }

    /** 协议路径,如 "ethernet▸ipv4▸udp▸my-app"。 */
    public String protocolPath() {
        StringBuilder sb = new StringBuilder();
        for (DecodedLayer l : layers) {
            if (sb.length() > 0) {
                sb.append('▸');
            }
            sb.append(l.id());
        }
        return sb.toString();
    }

    /** 最深(最后)命中的协议 id;无层返回 null。 */
    public String deepestProtocol() {
        return layers.isEmpty() ? null : layers.get(layers.size() - 1).id();
    }

    /**
     * 一层解析结果。headerLength 为该层头部(payload 之前)的字节数;
     * fieldRanges 为顶层字段的帧绝对字节区间 [start, end)(嵌套元素内部字段不含);
     * bitRanges 为帧绝对位区间 [startBit, endBit)(bit 0 = 首字节 MSB),
     * 供 UI 对亚字节字段做 Wireshark 式「0100 ....」位展示。
     */
    public record DecodedLayer(String id, String name, Object packet, int offset, int headerLength,
                               java.util.Map<String, int[]> fieldRanges,
                               java.util.Map<String, int[]> bitRanges) {
        public DecodedLayer {
            fieldRanges = fieldRanges == null ? java.util.Map.of() : java.util.Map.copyOf(fieldRanges);
            bitRanges = bitRanges == null ? java.util.Map.of() : java.util.Map.copyOf(bitRanges);
        }

        /** 兼容旧构造(无位区间)。 */
        public DecodedLayer(String id, String name, Object packet, int offset, int headerLength,
                            java.util.Map<String, int[]> fieldRanges) {
            this(id, name, packet, offset, headerLength, fieldRanges, java.util.Map.of());
        }
    }
}
