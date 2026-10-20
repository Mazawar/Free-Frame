package com.netproto.spring.web;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** IPv6 文本格式化(RFC 5952:最长零段压缩、小写、不压缩单零)。 */
class LayerViewsTest {

    private static byte[] ipv6(int... groups) {
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[i * 2] = (byte) (groups[i] >> 8);
            out[i * 2 + 1] = (byte) groups[i];
        }
        return out;
    }

    @Test
    void compressesLongestZeroRun() {
        assertEquals("fe80::1",
                LayerViews.formatIpv6(ipv6(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        assertEquals("::",
                LayerViews.formatIpv6(ipv6(0, 0, 0, 0, 0, 0, 0, 0)));
        assertEquals("2001:db8::1:0:0:1",
                LayerViews.formatIpv6(ipv6(0x2001, 0xdb8, 0, 0, 1, 0, 0, 1)));
        // 单个零段不压缩
        assertEquals("2001:db8:0:1:1:1:1:1",
                LayerViews.formatIpv6(ipv6(0x2001, 0xdb8, 0, 1, 1, 1, 1, 1)));
        assertEquals("::1",
                LayerViews.formatIpv6(ipv6(0, 0, 0, 0, 0, 0, 0, 1)));
    }
}
