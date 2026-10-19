package com.example.demo.protocol.stack;

import com.example.demo.protocol.annotation.Payload;
import com.example.demo.protocol.core.PacketCodec;
import com.example.demo.protocol.core.PayloadAware;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

/**
 * 自底向上组装器:layers 按外层→内层给出(如 [ethernet, ipv4, udp, appMessage]),
 * 从最内层开始编码,逐层向外「注入 payload → 长度钩子 → 选择子自动接线 → 编码」。
 * <p>
 * 选择子自动接线:从子协议 @BindOn.when 提取「field == literal」赋值到父层
 * (etherType=0x0800 / protocol=17 / dstPort=9999),用户无需手工填写这些字段。
 */
public final class StackEncoder {

    private static final Logger log = LoggerFactory.getLogger(StackEncoder.class);

    private final ProtocolRegistry registry;

    public StackEncoder(ProtocolRegistry registry) {
        this.registry = registry;
    }

    /** 组装整条协议栈为原始字节(最外层在前)。 */
    public byte[] encode(List<?> layers) {
        if (layers == null || layers.isEmpty()) {
            throw new IllegalArgumentException("layers must not be empty");
        }
        Object innermost = layers.get(layers.size() - 1);
        byte[] bytes = codecOf(innermost.getClass()).encode(innermost);

        for (int i = layers.size() - 2; i >= 0; i--) {
            Object layer = layers.get(i);
            Object child = layers.get(i + 1);
            setPayload(layer, bytes);
            if (layer instanceof PayloadAware aware) {
                aware.onPayload(bytes);
            }
            autoWire(layer, child.getClass());
            bytes = codecOf(layer.getClass()).encode(layer);
        }
        return bytes;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private PacketCodec codecOf(Class<?> type) {
        return registry.byType(type)
                .orElseThrow(() -> new IllegalArgumentException(
                        type.getName() + " is not a registered @Protocol class"))
                .codec();
    }

    /** 反射写入 layer 的 @Payload 字段。 */
    private static void setPayload(Object layer, byte[] payload) {
        Field f = findPayloadField(layer.getClass());
        if (f == null) {
            throw new IllegalArgumentException(
                    layer.getClass().getName() + " has no @Payload field to accept inner layer bytes");
        }
        try {
            f.setAccessible(true);
            f.set(layer, payload);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("cannot set payload of " + layer.getClass().getName(), e);
        }
    }

    private static Field findPayloadField(Class<?> type) {
        for (Field f : type.getDeclaredFields()) {
            if (f.isAnnotationPresent(Payload.class)) {
                return f;
            }
        }
        return null;
    }

    /**
     * 选择子自动接线:把「layer 的协议 → child 的协议」绑定的 when 常量赋给 layer 字段。
     * 只填充「未设置」的字段(数值 0 / 对象 null)——用户显式给过的值不会被覆盖;
     * 用户可用此特性改道(如显式设置非默认 etherType/端口)。
     */
    private void autoWire(Object layer, Class<?> childType) {
        String parentId = registry.byType(layer.getClass())
                .orElseThrow(() -> new IllegalArgumentException(layer.getClass().getName() + " not registered"))
                .id();
        String childId = registry.byType(childType)
                .orElseThrow(() -> new IllegalArgumentException(childType.getName() + " not registered"))
                .id();
        Map<String, Long> assignments = registry.autoWireAssignments(parentId, childId);
        for (Map.Entry<String, Long> a : assignments.entrySet()) {
            Field f = findNumberField(layer.getClass(), a.getKey());
            if (f == null) {
                log.warn("auto-wire: field '{}' not found on {}", a.getKey(), layer.getClass().getSimpleName());
                continue;
            }
            try {
                f.setAccessible(true);
                long v = a.getValue();
                Object current = f.get(layer);
                if (current instanceof Number n && n.longValue() != 0) {
                    continue;  // 用户已显式设置:不覆盖
                }
                if (!(current instanceof Number) && current != null) {
                    continue;
                }
                if (f.getType() == int.class || f.getType() == Integer.class) {
                    f.set(layer, (int) v);
                } else if (f.getType() == long.class || f.getType() == Long.class) {
                    f.set(layer, v);
                } else if (f.getType() == short.class || f.getType() == Short.class) {
                    f.set(layer, (short) v);
                } else if (f.getType() == byte.class || f.getType() == Byte.class) {
                    f.set(layer, (byte) v);
                } else {
                    log.warn("auto-wire: field '{}' on {} is not a numeric field", a.getKey(),
                            layer.getClass().getSimpleName());
                }
            } catch (IllegalAccessException e) {
                throw new IllegalStateException("cannot auto-wire " + a.getKey(), e);
            }
        }
    }

    private static Field findNumberField(Class<?> type, String name) {
        for (Field f : type.getDeclaredFields()) {
            if (f.getName().equals(name)) {
                return f;
            }
        }
        return null;
    }
}
