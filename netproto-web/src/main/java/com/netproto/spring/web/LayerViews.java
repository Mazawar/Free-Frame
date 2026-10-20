package com.netproto.spring.web;

import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.UnknownEnumValue;

import java.lang.reflect.Field;
import java.util.*;

/** 解析出的协议对象 → JSON 友好的字段视图(byte[]→hex、MAC/Ip 格式化、枚举/标志取名)。 */
public final class LayerViews {

    private LayerViews() {}

    /** 一个协议对象的注解字段视图(按 order 排列,@Payload 最后)。 */
    public static Map<String, Object> fieldsOf(Object packet) {
        if (packet == null) {
            return Map.of();
        }
        List<FieldEntry> entries = new ArrayList<>();
        Field payloadField = null;
        for (Field f : packet.getClass().getDeclaredFields()) {
            ProtocolField ann = f.getAnnotation(ProtocolField.class);
            if (ann != null) {
                entries.add(new FieldEntry(ann.order(), f));
            } else if (f.isAnnotationPresent(Payload.class)) {
                payloadField = f;
            }
        }
        entries.sort(Comparator.comparingInt(e -> e.order));
        if (payloadField != null) {
            entries.add(new FieldEntry(Integer.MAX_VALUE, payloadField));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (FieldEntry e : entries) {
            e.field.setAccessible(true);
            try {
                out.put(e.field.getName(), display(e.field.getName(), e.field.get(packet), 0));
            } catch (IllegalAccessException ex) {
                out.put(e.field.getName(), "<unreadable>");
            }
        }
        return out;
    }

    private record FieldEntry(int order, Field field) {}

    private static Object display(String name, Object value, int depth) {
        if (value == null) {
            return null;
        }
        if (value instanceof byte[] bytes) {
            if (name.endsWith("Ip6") && bytes.length == 16) {
                return formatIpv6(bytes);      // RFC 5952 压缩形式,如 fe80::1
            }
            return hex(bytes, 2048);
        }
        if (value instanceof UnknownEnumValue u) {
            return u.toString();
        }
        if (value instanceof Enum<?> en) {
            return en.name();
        }
        if (value instanceof Set<?> set) {
            List<Object> out = new ArrayList<>();
            for (Object o : set) {
                out.add(display(name, o, depth));
            }
            return out;
        }
        if (value instanceof List<?> list) {
            if (depth >= 3) {
                return List.of("…(" + list.size() + " items)");
            }
            List<Object> out = new ArrayList<>();
            for (Object o : list) {
                out.add(isProtocolEntity(o) ? fieldsOf(o) : display(name, o, depth + 1));
            }
            return out;
        }
        if (name.endsWith("Mac") && value instanceof Long l) {
            return formatMac(l);
        }
        if (name.endsWith("Mac") && value instanceof Integer i) {
            return formatMac(i & 0xFFFFFFFFL);
        }
        if (name.endsWith("Ip") && value instanceof Integer i) {
            return formatIp(i);
        }
        if (value instanceof Number || value instanceof String || value instanceof Boolean) {
            return value;
        }
        if (isProtocolEntity(value)) {
            return fieldsOf(value);
        }
        return String.valueOf(value);
    }

    private static boolean isProtocolEntity(Object o) {
        return o != null && o.getClass().isAnnotationPresent(Protocol.class);
    }

    public static String hex(byte[] bytes, int maxChars) {
        StringBuilder sb = new StringBuilder(Math.min(bytes.length * 2, maxChars + 8));
        for (byte b : bytes) {
            if (sb.length() >= maxChars) {
                sb.append("…");
                break;
            }
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String formatMac(long mac) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                (mac >> 40) & 0xFF, (mac >> 32) & 0xFF, (mac >> 24) & 0xFF,
                (mac >> 16) & 0xFF, (mac >> 8) & 0xFF, mac & 0xFF);
    }

    public static String formatIp(int ip) {
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
    }

    /** IPv6 文本(RFC 5952):最长零段(≥2)压缩为 ::,小写 hex。 */
    public static String formatIpv6(byte[] b) {
        long[] g = new long[8];
        for (int i = 0; i < 8; i++) {
            g[i] = ((b[i * 2] & 0xFFL) << 8) | (b[i * 2 + 1] & 0xFFL);
        }
        int bestStart = -1, bestLen = 0;
        for (int i = 0; i < 8; ) {
            if (g[i] != 0) {
                i++;
                continue;
            }
            int j = i;
            while (j < 8 && g[j] == 0) {
                j++;
            }
            if (j - i > bestLen) {
                bestStart = i;
                bestLen = j - i;
            }
            i = j;
        }
        if (bestLen < 2) {
            bestStart = -1;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (bestStart >= 0 && i >= bestStart && i < bestStart + bestLen) {
                if (i == bestStart) {
                    sb.append("::");
                }
                continue;
            }
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) != ':') {
                sb.append(':');
            }
            sb.append(Long.toHexString(g[i]));
        }
        return sb.length() == 0 ? "::" : sb.toString();
    }
}
