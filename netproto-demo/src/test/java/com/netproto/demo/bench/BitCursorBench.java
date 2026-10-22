package com.netproto.demo.bench;

import com.netproto.core.BitCursor;

/** BitCursor 新旧 readBits/writeBits 实现对照(新版已入 src;旧版逐位循环在此内联复刻)。 */
public class BitCursorBench {

    public static void main(String[] args) {
        for (int w = 0; w < 2; w++) {
            boolean useNew = w == 1;
            // writeBits
            for (int r = 0; r < 3; r++) timedWrite(useNew, 500);
            long[] res = new long[3];
            for (int r = 0; r < 3; r++) res[r] = timedWrite(useNew, 1000);
            System.out.printf("%s writeBits48: %,d ops/s%n", useNew ? "NEW" : "OLD", max(res));
            for (int r = 0; r < 3; r++) timedRead(useNew, 500);
            for (int r = 0; r < 3; r++) res[r] = timedRead(useNew, 1000);
            System.out.printf("%s readBits48 : %,d ops/s%n", useNew ? "NEW" : "OLD", max(res));
        }
    }

    static long max(long[] a) { long m = 0; for (long x : a) m = Math.max(m, x); return m; }

    static long timedWrite(boolean useNew, int ms) {
        BitCursor c = new BitCursor(1 << 20);
        long ops = 0, sink = 0;
        long t0 = System.nanoTime();
        long deadline = t0 + ms * 1_000_000L;
        while (System.nanoTime() < deadline) {
            for (int i = 0; i < 1000; i++) {
                if (useNew) c.writeBits(i, 48); else oldWriteBits(c, i, 48);
            }
            sink += c.bitOffset();
            if (c.bitOffset() > (1 << 20) * 8 - 100000) { c = new BitCursor(1 << 20); }
            ops += 1000;
        }
        if (sink == 42) System.out.print("");
        return (long) (ops * 1e9 / (System.nanoTime() - t0));
    }

    static long timedRead(boolean useNew, int ms) {
        byte[] data = new byte[1 << 20];
        BitCursor c = new BitCursor(data, 0);
        long ops = 0, sink = 0;
        long t0 = System.nanoTime();
        long deadline = t0 + ms * 1_000_000L;
        while (System.nanoTime() < deadline) {
            for (int i = 0; i < 1000; i++) {
                sink += useNew ? c.readBits(48) : oldReadBits(c, 48);
            }
            if (c.bitOffset() > (1 << 20) * 8 - 100000) { c = new BitCursor(data, 0); }
            ops += 1000;
        }
        if (sink == 42) System.out.print("");
        return (long) (ops * 1e9 / (System.nanoTime() - t0));
    }

    // ---- 旧实现复刻(逐位循环) ----
    static void oldWriteBits(BitCursor c, long value, int size) {
        for (int i = size - 1; i >= 0; i--) {
            long bit = (value >> i) & 1L;
            c.writeBits(bit, 1);
        }
    }

    static long oldReadBits(BitCursor c, int size) {
        long v = 0;
        for (int i = 0; i < size; i++) v = (v << 1) | c.readBits(1);
        return v;
    }
}
