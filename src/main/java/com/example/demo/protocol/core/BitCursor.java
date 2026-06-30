package com.example.demo.protocol.core;

/**
 * 位级读写游标。MSB 优先(字节内高位先填)、网络序大端(跨字节)、允许字段跨字节边界。
 */
public final class BitCursor {

    private final byte[] data;   // 读取源 / 写入目标
    private final int baseByte;  // 起始字节偏移
    private int bitPos;          // 相对 baseByte 的位偏移
    private final int totalBits; // 容量(仅写入用;读取不强制)

    /** 读模式:基于现有字节。 */
    public BitCursor(byte[] data, int startByteOffset) {
        this.data = data;
        this.baseByte = startByteOffset;
        this.bitPos = 0;
        this.totalBits = (data.length - startByteOffset) * 8;
    }

    /** 写模式:分配 byteCount 字节。 */
    public BitCursor(int byteCount) {
        this.data = new byte[byteCount];
        this.baseByte = 0;
        this.bitPos = 0;
        this.totalBits = byteCount * 8;
    }

    /** 从当前位偏移读 size 位(大端),并推进游标。 */
    public long readBits(int size) {
        if (size < 0 || size > 63) {
            throw new IllegalArgumentException("size must be 0..63, got " + size);
        }
        long value = 0;
        for (int i = 0; i < size; i++) {
            int absBit = baseByte * 8 + bitPos + i;
            int byteIdx = absBit / 8;
            int bitInByte = 7 - (absBit % 8); // MSB 优先
            value = (value << 1) | ((data[byteIdx] >> bitInByte) & 1);
        }
        bitPos += size;
        return value;
    }

    /** 从当前位偏移读 size 位为字节数组(BYTES/STRING/NESTED 用)。 */
    public byte[] readBytes(int size) {
        if (size % 8 != 0) {
            throw new IllegalArgumentException("byte read needs a multiple of 8 bits, got " + size);
        }
        int n = size / 8;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            int absBit = baseByte * 8 + bitPos + i * 8;
            int byteIdx = absBit / 8;
            out[i] = data[byteIdx];
        }
        bitPos += size;
        return out;
    }

    /** 在当前位偏移写 value 的低 size 位(大端),并推进游标。 */
    public void writeBits(long value, int size) {
        if (size < 0 || size > 63) {
            throw new IllegalArgumentException("size must be 0..63, got " + size);
        }
        for (int i = size - 1; i >= 0; i--) {
            int absBit = baseByte * 8 + bitPos + (size - 1 - i);
            int byteIdx = absBit / 8;
            int bitInByte = 7 - (absBit % 8);
            long bit = (value >> i) & 1L;
            if (bit == 1) {
                data[byteIdx] |= (byte) (1 << bitInByte);
            } else {
                data[byteIdx] &= (byte) ~(1 << bitInByte);
            }
        }
        bitPos += size;
    }

    /** 写入字节(BYTES/STRING/NESTED 用),size 必须是 8 的倍数。 */
    public void writeBytes(byte[] bytes) {
        if (bitPos % 8 != 0) {
            throw new IllegalStateException("writeBytes requires byte-aligned cursor, bitPos=" + bitPos);
        }
        int byteStart = baseByte + bitPos / 8;
        System.arraycopy(bytes, 0, data, byteStart, bytes.length);
        bitPos += bytes.length * 8;
    }

    public int bitOffset() {
        return bitPos;
    }

    /** 返回从当前游标位置(按字节对齐)起的剩余字节片段。游标必须字节对齐。 */
    public byte[] remainingFromCursor() {
        if (bitPos % 8 != 0) {
            throw new IllegalStateException("remainingFromCursor requires byte-aligned cursor, bitPos=" + bitPos);
        }
        int bytePos = baseByte + bitPos / 8;
        return java.util.Arrays.copyOfRange(data, bytePos, data.length);
    }

    /** 推进游标 n 位(不读取,仅移动)。 */
    public void skipBits(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("skipBits n must be >= 0, got " + n);
        }
        bitPos += n;
    }

    public byte[] bytes() {
        return data;
    }
}
