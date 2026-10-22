package com.netproto.stack;

import com.netproto.core.ProtocolCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * 自顶向下解码器:从根协议(默认 ethernet)开始,逐层「解析 → 求值子绑定 → 下降」。
 * <p>
 * 设计要点:
 * <ul>
 *   <li>只解析注册过的协议——没有注解的协议根本不会被触碰,payload 保持原始字节;</li>
 *   <li>某层解析失败(畸形)→ 该层不记录,停止下降,剩余字节为原始尾部(不抛异常);</li>
 *   <li>无命中子绑定或 headerBytes&lt;0(自定义 codec 不支持分派)→ 到该层为止。</li>
 * </ul>
 */
public final class StackDecoder {

    private static final Logger log = LoggerFactory.getLogger(StackDecoder.class);

    private final ProtocolRegistry registry;
    private final String root;

    public StackDecoder(ProtocolRegistry registry, String root) {
        this.registry = registry;
        this.root = root;
    }

    public DecodedPacket decode(byte[] frame, String iface, long timestampMillis, int capturedCount) {
        return decode(frame, iface, timestampMillis, capturedCount, true);
    }

    /**
     * 高流量采集路径用 wantRanges=false:跳过每层位区间簿记(字段↔字节联动数据)。
     * 采集摘要只消费 POJO 字段;UI 详情由 CaptureSession.detail 按需重解码(走全量路径)。
     */
    public DecodedPacket decode(byte[] frame, String iface, long timestampMillis, int capturedCount,
                                boolean wantRanges) {
        List<DecodedPacket.DecodedLayer> layers = new ArrayList<>();
        int off = 0;
        String id = root;
        List<ProtocolCodec<?>> toggled = wantRanges ? null : new ArrayList<>(4);
        while (id != null && off < frame.length) {
            ProtocolRegistry.Entry entry = registry.get(id);
            if (entry == null) {
                log.debug("protocol '{}' not registered, stop descending", id);
                break;
            }
            Object obj;
            // 只对本层 codec 切位区间开关(而非全注册表:热路径每帧只会碰 3-6 层)
            ProtocolCodec<?> pc = entry.codec() instanceof ProtocolCodec<?> p ? p : null;
            if (pc != null && !wantRanges) {
                pc.setTrackRanges(false);
                toggled.add(pc);
            }
            try {
                obj = entry.codec().decode(frame, off, frame.length - off);
            } catch (Exception e) {
                log.debug("layer '{}' failed to decode at offset {}: {} — stop descending",
                        id, off, e.getMessage());
                break;
            }
            int header = entry.codec().headerBytes();
            if (wantRanges) {
                // 位区间 → 帧绝对字节/位区间(供 UI 字段↔字节联动与亚字节位展示;解码线程内即刻取走)
                java.util.Map<String, int[]> fieldRanges = new java.util.LinkedHashMap<>();
                java.util.Map<String, int[]> bitRanges = new java.util.LinkedHashMap<>();
                for (java.util.Map.Entry<String, int[]> fr : entry.codec().lastFieldRanges().entrySet()) {
                    int[] bits = fr.getValue();
                    int s = off + bits[0] / 8;
                    int t = Math.min(off + (bits[1] + 7) / 8, frame.length);
                    s = Math.min(s, t);
                    if (t > s) {
                        fieldRanges.put(fr.getKey(), new int[]{s, t});
                    }
                    bitRanges.put(fr.getKey(), new int[]{off * 8 + bits[0], off * 8 + bits[1]});
                }
                layers.add(new DecodedPacket.DecodedLayer(entry.id(), entry.name(), obj, off, header,
                        fieldRanges, bitRanges));
            } else {
                layers.add(new DecodedPacket.DecodedLayer(entry.id(), entry.name(), obj, off, header,
                        java.util.Map.of(), java.util.Map.of()));
            }
            if (header <= 0) {
                break;  // 该 codec 不支持子层分派(叶子)
            }
            int childOff = off + header;
            if (childOff >= frame.length) {
                break;  // 头部已吃满,无 payload
            }
            String child = registry.matchChild(entry.id(), obj);
            if (child == null) {
                break;  // 未注册的协议:payload 保持原始字节
            }
            off = childOff;
            id = child;
        }
        if (toggled != null) {
            for (ProtocolCodec<?> p : toggled) {
                p.setTrackRanges(true);   // 恢复本线程默认(详情重解码等仍需位区间)
            }
        }
        return new DecodedPacket(timestampMillis, iface, frame, layers, capturedCount);
    }
}
