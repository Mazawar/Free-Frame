package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.ChecksumField;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.Checksum;
import com.netproto.core.FieldType;
import com.netproto.stack.DecodedPacket;
import com.netproto.stack.ProtocolRegistry;
import com.netproto.stack.StackDecoder;
import com.netproto.stack.StackEncoder;
import lombok.Data;
import lombok.ToString;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 「帧尾 CRC」模式能力边界演示 —— body 之后还有校验字段怎么办。
 *
 * <p>结论(与本文件两个用例一一对应):
 * <ul>
 *   <li><b>自包含帧(孤岛)可以</b>:body 用 lengthField+lengthAdjust 驱动(非 @Payload),
 *       之后照常声明尾随字段(CRC/结束符)。DL/T 645(cs+16H)、本文件 {@link PdCrcFrame}
 *       都是此模式;CRC 由 {@code @ChecksumField} 编码期自动计算回填。</li>
 *   <li><b>带子协议分派的栈父层不可以</b>:引擎两条语义合起来堵死了——
 *       ① @Payload 无条件取「剩余全部字节」,后面再声明字段会读错位置;
 *       ② body 改用 lengthField 驱动后,headerBytes()=全部声明字段=整帧,
 *          子协议失去分派入口(decode 停在本层,encode 的内层注入也断了)。</li>
 * </ul>
 * 栈父层 + 尾部 CRC 的现实出路:收发两侧在引擎外做一层「追加/校验 CRC」
 * (socket 后端一行事),或走 L3 逃生舱手写整帧 codec 插回分派树。
 */
class PdCrcTrailerTest {

    /** 16B 头 + body + 2B CRC16 的自包含帧(body 由报文长度驱动,非 @Payload)。 */
    @Data
    @ToString
    @Protocol(id = "pd-crc", name = "配电帧(尾部CRC)")
    public static class PdCrcFrame implements Checksum {

        @ProtocolField(order = 1, size = 8, label = "版本号")
        private int version = 0x21;
        @ProtocolField(order = 2, size = 8, label = "信令类型")
        private int signalType = 1;
        @ProtocolField(order = 3, size = 32, label = "源地址")
        private int srcAddr = 1;
        @ProtocolField(order = 4, size = 32, label = "目标地址")
        private int dstAddr;
        @ProtocolField(order = 5, size = 16, label = "流水号")
        private int seqNo = 1;
        @ProtocolField(order = 6, size = 16, label = "认证令牌")
        private int token;
        /** 整帧长度(16 头 + body + 2 CRC)。组装时手工置(引擎不自动回填非 @Payload 长度)。 */
        @ProtocolField(order = 7, size = 16, label = "报文长度")
        private int frameLength;
        /** 信令体:报文长度驱动 = frameLength - 18(16B 头 + 2B CRC)。 */
        @ProtocolField(order = 8, type = FieldType.BYTES,
                lengthField = "frameLength", lengthAdjust = -18)
        private byte[] body = new byte[0];
        /** 尾部 CRC16(Modbus),编码期置 0 → 序列化 → 计算回填。 */
        @ProtocolField(order = 9, size = 16, label = "CRC")
        @ChecksumField
        private int crc;

        @Override
        public long compute(String field, byte[] serialized) {
            if (!"crc".equals(field)) {
                return -1;
            }
            // serialized 尾部 2B 是已置 0 的 crc 自身,计算范围排除之
            return crc16(serialized, serialized.length - 2);
        }
    }

    /** 试图挂在 pd-crc 下的子协议(实验用:证明此路不通)。 */
    @Data
    @ToString
    @Protocol(id = "pd-crc-reg", name = "注册(尾部CRC实验)")
    @BindOn(parent = "pd-crc", when = "signalType == 1")
    public static class PdCrcReg {
        @ProtocolField(order = 1, size = 8, label = "设备型号")
        private int model = 1;
        @ProtocolField(order = 2, size = 8, label = "组网方式")
        private int netMode;
        @ProtocolField(order = 3, size = 32, label = "注册时间")
        private long regTime;
    }

    private static ProtocolRegistry registry;
    private static StackEncoder encoder;
    private static StackDecoder decoder;

    @BeforeAll
    static void init() {
        registry = ProtocolRegistry.create(PdCrcFrame.class, PdCrcReg.class);
        registry.validateBindings();
        encoder = new StackEncoder(registry);
        decoder = new StackDecoder(registry, "pd-crc");
    }

    @Test
    @DisplayName("孤岛帧:头+body+尾CRC 完整往返,CRC 编码期自动回填且可复算")
    void islandFrameWithTrailingCrc() {
        PdCrcFrame f = new PdCrcFrame();
        byte[] body = new byte[]{0x01, 0x00, 0x5F, 0x30, 0x40, 0x00};      // 6B,与注册体一致
        f.setBody(body);
        f.setFrameLength(16 + body.length + 2);                     // 24

        byte[] frame = encoder.encode(List.of(f));                  // 单层编码
        assertEquals(24, frame.length);

        // CRC 已自动回填,且与独立复算一致(排除尾部 2B)
        int crcOnWire = ((frame[22] & 0xFF) << 8) | (frame[23] & 0xFF);
        assertEquals(crc16(frame, 22), crcOnWire);

        // 解码:body 精确读 frameLength-18=6 字节,CRC 照常解出,路径为叶子
        DecodedPacket p = decoder.decode(frame, "test", 0, 1);
        assertEquals("pd-crc", p.protocolPath());
        PdCrcFrame back = (PdCrcFrame) p.layers().get(0).packet();
        assertArrayEquals(body, back.getBody());
        assertEquals(crcOnWire, back.getCrc());
        assertEquals(24, back.getFrameLength());
    }

    @Test
    @DisplayName("栈父层+尾CRC:子协议分派入口被尾随字段吃掉(当前引擎边界,锁定行为)")
    void stackParentWithTrailingCrcLosesChildDispatch() {
        byte[] wire = hex("21 01 00 00 00 01 00 00 00 00 00 01 00 00 00 18"  // frameLength=24
                + " 01 00 5F 30 40 00"                                        // 注册体 6B
                + " AA 55");                                                   // 尾 CRC

        // body 读 24-18=6B、CRC 读 2B 都正确,但 headerBytes=整帧 24B → 子协议无从分派
        DecodedPacket p = decoder.decode(wire, "test", 0, 1);
        assertEquals(List.of("pd-crc"), p.layers().stream()
                .map(DecodedPacket.DecodedLayer::id).toList());   // pd-crc-reg 不会出现
    }

    @Test
    @DisplayName("栈分派模式:帧尾 CRC 对子协议解码无害(被层尾忽略,无需剥离)")
    void stackDispatchToleratesTrailingCrc() {
        // 真实业务形态:pd 公共头(@Payload body,子协议分派)+ 注册体 + 尾部 2B CRC
        // 用主协议 PdFrame/PdRegister 验证:decoder 收到含 CRC 的整帧
        // PdFrame 绑 udp,注册表须含其祖先链(ethernet/vlan/ipv4/ipv6/udp)
        ProtocolRegistry reg = ProtocolRegistry.create(
                com.netproto.protocols.builtin.EthernetFrame.class,
                com.netproto.protocols.builtin.VlanFrame.class,
                com.netproto.protocols.builtin.Ipv4Packet.class,
                com.netproto.protocols.builtin.Ipv6Packet.class,
                com.netproto.protocols.builtin.UdpSegment.class,
                PdFrame.class, PdRegister.class);
        reg.validateBindings();
        StackDecoder pdDecoder = new StackDecoder(reg, "pd");

        byte[] wire = hex("21 01 00 00 00 01 00 00 00 00 00 01 00 00 00 18"  // 头:frameLength=24(16+6+2)
                + " 01 00 5F 30 40 00"                                       // 注册体
                + " AA 55");                                                  // 尾部 CRC

        DecodedPacket p = pdDecoder.decode(wire, "test", 0, 1);
        // 子协议照常分派到底;body=剩余 8B(体+CRC)但注册只读自己 6B,CRC 字节被层尾忽略
        assertEquals("pd▸pd-reg", p.protocolPath());
        PdRegister regBack = (PdRegister) p.layers().get(1).packet();
        assertEquals(1, regBack.getModel());
        assertEquals(0x5F304000L, regBack.getRegTime());
    }

    // ---- CRC16/Modbus(poly 0xA001, init 0xFFFF, 低位在前;此处取高低位拼 16b 便于断言) ----

    static int crc16(byte[] data, int len) {
        int crc = 0xFFFF;
        for (int i = 0; i < len; i++) {
            crc ^= data[i] & 0xFF;
            for (int b = 0; b < 8; b++) {
                crc = (crc & 1) != 0 ? (crc >>> 1) ^ 0xA001 : crc >>> 1;
            }
        }
        return crc & 0xFFFF;
    }

    private static byte[] hex(String s) {
        String clean = s.replace(" ", "");
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
