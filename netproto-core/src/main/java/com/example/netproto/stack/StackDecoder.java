package com.example.netproto.stack;

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
        List<DecodedPacket.DecodedLayer> layers = new ArrayList<>();
        int off = 0;
        String id = root;
        while (id != null && off < frame.length) {
            ProtocolRegistry.Entry entry = registry.get(id);
            if (entry == null) {
                log.debug("protocol '{}' not registered, stop descending", id);
                break;
            }
            Object obj;
            try {
                obj = entry.codec().decode(frame, off, frame.length - off);
            } catch (Exception e) {
                log.debug("layer '{}' failed to decode at offset {}: {} — stop descending",
                        id, off, e.getMessage());
                break;
            }
            int header = entry.codec().headerBytes();
            layers.add(new DecodedPacket.DecodedLayer(entry.id(), entry.name(), obj, off, header));
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
        return new DecodedPacket(timestampMillis, iface, frame, layers, capturedCount);
    }
}
