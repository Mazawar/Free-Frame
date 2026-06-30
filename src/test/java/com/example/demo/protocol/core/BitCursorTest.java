package com.example.demo.protocol.core;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class BitCursorTest {

    @Test
    void readsBitFieldInSameByteMsbFirst() {
        // byte0 = 0x45 -> 高4位=0x4(version), 低4位=0x5(ihl)
        byte[] data = {0x45};
        BitCursor c = new BitCursor(data, 0);
        assertThat(c.readBits(4)).isEqualTo(0x4L);
        assertThat(c.readBits(4)).isEqualTo(0x5L);
        assertThat(c.bitOffset()).isEqualTo(8);
    }

    @Test
    void readsCrossByteBigEndian() {
        // 13-bit 字段从 byte0 bit0 起,跨越字节边界(byte0 全8位 + byte1 高5位)
        // byte0=0x09 (00001001), byte1=0x23 (00100011)
        // 13位 MSB-first = 00001001 00100 = 0000100100100 = 292
        byte[] data = {(byte) 0b00001_001, (byte) 0b00100011 /* 0x23 */};
        BitCursor c = new BitCursor(data, 0);
        long v = c.readBits(13);
        assertThat(c.bitOffset()).isEqualTo(13);
        // 高8位来自byte0(0x09), 低5位来自byte1高5位(0x23>>>3 = 00100 = 4)
        assertThat(v).isEqualTo((long) (data[0] & 0xFF) << 5 | ((data[1] & 0xFF) >>> 3));
    }

    @Test
    void writesBitFieldMsbFirst() {
        BitCursor c = new BitCursor(1); // 1 byte
        c.writeBits(0x4L, 4);
        c.writeBits(0x5L, 4);
        assertThat(c.bytes()).containsExactly(0x45);
    }

    @Test
    void writesCrossByteField() {
        BitCursor c = new BitCursor(2);
        c.writeBits(0x0123L, 13);
        byte[] out = c.bytes();
        // 0x0123 = 13位 = 00001_0010_0011, 大端铺进 16 位(高3位补0)
        // byte0 高8位 = 00001_001 = 0x09 ; byte1 = 低5位 00011 + 3位补0 = 0001_1000 = 0x18
        assertThat(out[0] & 0xFF).isEqualTo(0b00001_001);  // 0x09
        assertThat(out[1] & 0xFF).isEqualTo(0b00011_000);  // 0x18
    }

    @Test
    void readOffsetStartsAtByteBoundary() {
        byte[] data = {0x12, 0x34};
        BitCursor c = new BitCursor(data, 1); // 从第1字节起
        assertThat(c.readBits(8)).isEqualTo(0x34L);
    }
}
