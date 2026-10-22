package com.netproto.core;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 能力边界测试:结构表达族(真实协议里最常见的「怪结构」)。
 * <ul>
 *   <li>存在位图驱动条件字段(ISO 8583 / 部分电力规约)—— presentIf 位索引语法;</li>
 *   <li>一个字节内「标志位 + 7bit 计数」(IEC 60870-5 VSQ)—— 位拆字段,LIST 计数;</li>
 *   <li>递归嵌套(DER / MessagePack / MMS 递归 TLV)—— NESTED 吃剩余字节,数据驱动深度;</li>
 *   <li>二维结构(行×列矩阵,报表/参数表)—— LIST 套 LIST;</li>
 *   <li>16bit type + 16bit length 的宽头 TLV(TLS 扩展/SCTP 参数式)—— LIST_TLV 头固定 8/8,
 *       同质元素用「实体组合」表达;</li>
 *   <li>BCD 符号半字节(DL/T 645 数据 0x0C 正 / 0x0D 负)—— BCD 类型不支持,现状特征。</li>
 * </ul>
 */
class BoundaryStructureTest {

    // ---- 夹具 ----

    /**
     * 存在位图驱动条件字段(ISO 8583 式)。
     * 已修复:位索引 name[n] 按声明 size 解释(size=32 的 long 字段,[1]=最高位、[32]=最低位),
     * 不再按 Java 装箱宽度(long=64)错位计数。
     */
    @Data
    @Protocol(id = "b-bitmap")
    static class PresenceBitmapFrame {
        @ProtocolField(order = 1, size = 32, type = FieldType.UNSIGNED)
        private long bitmap;
        @ProtocolField(order = 2, size = 8, presentIf = "bitmap[1]==1")
        private int a;
        @ProtocolField(order = 3, size = 16, presentIf = "bitmap[17]==1")
        private int b;
        @ProtocolField(order = 4, size = 8, presentIf = "bitmap[32]==1")
        private int c;
    }

    @Data
    @Protocol(id = "b-vsq-ioa")
    static class Ioa {
        @ProtocolField(order = 1, size = 24, type = FieldType.UNSIGNED)
        private long address;
    }

    /** IEC 60870-5 式:1bit SQ + 7bit 计数同字节。 */
    @Data
    @Protocol(id = "b-vsq")
    static class VsqFrame {
        @ProtocolField(order = 1, size = 1)
        private int sq;
        @ProtocolField(order = 2, size = 7)
        private int count;
        @ProtocolField(order = 3, type = FieldType.LIST, countField = "count", elementClass = Ioa.class)
        private List<Ioa> ioas = new ArrayList<>();
    }

    /** 递归节点:len>0 则尾部嵌套同类型节点(每层至少 16bit,数据天然限深)。
     *  presentIf 全语法已支持(>、!=、&& 等;注册校验走 Expr 收集标识符)。 */
    @Data
    @Protocol(id = "b-recursive")
    static class RecursiveNode {
        @ProtocolField(order = 1, size = 8)
        private int tag;
        @ProtocolField(order = 2, size = 8)
        private int len;
        @ProtocolField(order = 3, presentIf = "len>0")
        private RecursiveNode child;
    }

    @Data
    @Protocol(id = "b-cell")
    static class Cell {
        @ProtocolField(order = 1, size = 16)
        private int v;
    }

    @Data
    @Protocol(id = "b-row")
    static class Row {
        @ProtocolField(order = 1, size = 8)
        private int count;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "count", elementClass = Cell.class)
        private List<Cell> cells = new ArrayList<>();
    }

    @Data
    @Protocol(id = "b-matrix")
    static class MatrixFrame {
        @ProtocolField(order = 1, size = 8)
        private int rowCount;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "rowCount", elementClass = Row.class)
        private List<Row> rows = new ArrayList<>();
    }

    @Data
    @Protocol(id = "b-tlv16elem")
    static class Tlv16Elem {
        @ProtocolField(order = 1, size = 16)
        private int type;
        @ProtocolField(order = 2, size = 16)
        private int len;
        @ProtocolField(order = 3, lengthField = "len", type = FieldType.BYTES)
        private byte[] value = new byte[0];
    }

    @Data
    @Protocol(id = "b-tlv16")
    static class Tlv16Frame {
        @ProtocolField(order = 1, type = FieldType.LIST, untilEnd = true, elementClass = Tlv16Elem.class)
        private List<Tlv16Elem> items = new ArrayList<>();
    }

    @Data
    @Protocol(id = "b-bcd-sign")
    static class BcdSignFrame {
        @ProtocolField(order = 1, size = 8, type = FieldType.BCD)
        private long v;
    }

    // ---- 测试 ----

    @Test
    void presenceBitmapDrivesConditionalFields() {
        ProtocolCodec<PresenceBitmapFrame> codec = new ProtocolCodec<>(PresenceBitmapFrame.class);
        PresenceBitmapFrame f = new PresenceBitmapFrame();
        f.setBitmap(0x80008000L);   // bit1 + bit17 → a、b 出现,c 不出现
        f.setA(0x5A);
        f.setB(0x1234);
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(7);   // 4B bitmap + 1B a + 2B b
        PresenceBitmapFrame back = codec.deserialize(wire);
        assertThat(back.getA()).isEqualTo(0x5A);
        assertThat(back.getB()).isEqualTo(0x1234);
        assertThat(back.getC()).isEqualTo(0);

        PresenceBitmapFrame none = new PresenceBitmapFrame();
        none.setBitmap(0L);
        assertThat(codec.serialize(none)).hasSize(4);
    }

    @Test
    void vsqBitSplitCountDrivesList() {
        ProtocolCodec<VsqFrame> codec = new ProtocolCodec<>(VsqFrame.class);
        VsqFrame f = new VsqFrame();
        f.setSq(1);
        f.setCount(3);
        Ioa a = new Ioa();
        a.setAddress(0x000001);
        Ioa b = new Ioa();
        b.setAddress(0x000002);
        Ioa c = new Ioa();
        c.setAddress(0x000003);
        f.setIoas(new ArrayList<>(List.of(a, b, c)));
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(1 + 9);   // SQ+count 同字节 + 3×3B
        assertThat(wire[0]).isEqualTo((byte) 0x83);   // SQ=1(最高位)+ count=3
        VsqFrame back = codec.deserialize(wire);
        assertThat(back.getSq()).isEqualTo(1);
        assertThat(back.getCount()).isEqualTo(3);
        assertThat(back.getIoas()).hasSize(3);
        assertThat(back.getIoas().get(2).getAddress()).isEqualTo(3);
    }

    /** 递归嵌套 4 层 round-trip;深度由数据驱动,机制上可用(无显式深度上限,见报告)。 */
    @Test
    void recursiveNestedNodeRoundTrip() {
        ProtocolCodec<RecursiveNode> codec = new ProtocolCodec<>(RecursiveNode.class);
        RecursiveNode n1 = new RecursiveNode();
        n1.setTag(1);
        n1.setLen(1);
        RecursiveNode n2 = new RecursiveNode();
        n2.setTag(2);
        n2.setLen(1);
        RecursiveNode n3 = new RecursiveNode();
        n3.setTag(3);
        n3.setLen(1);
        RecursiveNode n4 = new RecursiveNode();
        n4.setTag(4);
        n4.setLen(0);
        n3.setChild(n4);
        n2.setChild(n3);
        n1.setChild(n2);

        byte[] wire = codec.serialize(n1);
        assertThat(wire).hasSize(8);   // 4 层 × 2B

        RecursiveNode back = codec.deserialize(wire);
        assertThat(back.getTag()).isEqualTo(1);
        assertThat(back.getChild().getChild().getChild().getTag()).isEqualTo(4);
        assertThat(back.getChild().getChild().getChild().getChild()).isNull();
    }

    /** 畸形递归:len 恒 1 到字节耗尽 → 异常终止(深度受输入长度约束,不死循环)。 */
    @Test
    void malformedRecursiveTerminatesByInputExhaustion() {
        ProtocolCodec<RecursiveNode> codec = new ProtocolCodec<>(RecursiveNode.class);
        byte[] tight = {5, 1};   // 单层 len=1,无子层字节
        assertThrows(RuntimeException.class, () -> codec.deserialize(tight));
        byte[] deep = new byte[20];   // 10 层 "tag,len=1" 后耗尽 → 必须异常而非挂死
        for (int i = 0; i < deep.length; i++) {
            deep[i] = (byte) ((i % 2 == 1) ? 1 : (i / 2 + 1));
        }
        assertThrows(RuntimeException.class, () -> codec.deserialize(deep));
    }

    @Test
    void nestedListMatrixRoundTrip() {
        ProtocolCodec<MatrixFrame> codec = new ProtocolCodec<>(MatrixFrame.class);
        MatrixFrame f = new MatrixFrame();
        f.setRowCount(2);
        Row r1 = new Row();
        r1.setCount(3);
        for (int i = 0; i < 3; i++) {
            Cell c = new Cell();
            c.setV(0x100 + i);
            r1.getCells().add(c);
        }
        Row r2 = new Row();
        r2.setCount(1);
        Cell c = new Cell();
        c.setV(0x9999);
        r2.getCells().add(c);
        f.setRows(new ArrayList<>(List.of(r1, r2)));
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(1 + (1 + 6) + (1 + 2));
        MatrixFrame back = codec.deserialize(wire);
        assertThat(back.getRows()).hasSize(2);
        assertThat(back.getRows().get(0).getCells()).hasSize(3);
        assertThat(back.getRows().get(1).getCells().get(0).getV()).isEqualTo(0x9999);
    }

    /** 16/16 宽头 TLV:LIST_TLV 做不到(头固定 8/8),同质元素组合表达可用。 */
    @Test
    void wideHeaderTlvViaComposition() {
        ProtocolCodec<Tlv16Frame> codec = new ProtocolCodec<>(Tlv16Frame.class);
        Tlv16Frame f = new Tlv16Frame();
        Tlv16Elem e1 = new Tlv16Elem();
        e1.setType(0x0102);
        e1.setLen(0);
        Tlv16Elem e2 = new Tlv16Elem();
        e2.setType(0x0304);
        e2.setLen(3);
        e2.setValue(new byte[]{0x11, 0x22, 0x33});
        f.setItems(new ArrayList<>(List.of(e1, e2)));
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(
                0x01, 0x02, 0x00, 0x00,             // type16 + len16=0
                0x03, 0x04, 0x00, 0x03, 0x11, 0x22, 0x33);
        Tlv16Frame back = codec.deserialize(wire);
        assertThat(back.getItems()).hasSize(2);
        assertThat(back.getItems().get(1).getType()).isEqualTo(0x0304);
        assertThat(back.getItems().get(1).getValue()).containsExactly(0x11, 0x22, 0x33);
    }

    /** BCD 符号半字节:0x0D(负)解码干净拒绝;负数编码产出毒数据(解码必炸)—— 现状特征。 */
    @Test
    void bcdSignNibbleUnsupported() {
        ProtocolCodec<BcdSignFrame> codec = new ProtocolCodec<>(BcdSignFrame.class);
        // DL/T 645 数据区:数值 +0x33 混淆后,符号半字节 0x0C/0x0D 常见
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> codec.deserialize(new byte[]{0x0D}));
        assertThat(ex.getCause()).hasMessageContaining("invalid digit");

        BcdSignFrame f = new BcdSignFrame();
        f.setV(-12);
        byte[] poisoned = codec.serialize(f);   // 现状:负数静默产出非法 BCD
        assertThrows(RuntimeException.class, () -> codec.deserialize(poisoned));
    }

    /** presentIf 全语法(>/!=/&& 等)注册与求值均可(修复:注册校验走 Expr 收集标识符)。 */
    @Data
    @Protocol(id = "b-presentif-full")
    static class PresentIfFullFrame {
        @ProtocolField(order = 1, size = 8)
        private int ver;
        @ProtocolField(order = 2, size = 8, presentIf = "ver>1")
        private int extra;
        @ProtocolField(order = 3, size = 8, presentIf = "ver>=3 && extra>0")
        private int more;
    }

    @Test
    void presentIfFullGrammarWorks() {
        ProtocolCodec<PresentIfFullFrame> codec = new ProtocolCodec<>(PresentIfFullFrame.class);
        PresentIfFullFrame v3 = new PresentIfFullFrame();
        v3.setVer(3);
        v3.setExtra(0x55);
        v3.setMore(0xAA);
        byte[] wire = codec.serialize(v3);
        assertThat(wire).containsExactly(3, 0x55, 0xAA);
        assertThat(codec.deserialize(wire).getMore()).isEqualTo(0xAA);

        PresentIfFullFrame v1 = new PresentIfFullFrame();
        v1.setVer(1);
        assertThat(codec.serialize(v1)).containsExactly(1);   // extra/more 均缺席
    }

    /** presentIf 前向引用(引用更晚的字段)。 */
    @Data
    @Protocol(id = "b-presentif-fwd")
    static class PresentIfFwdFrame {
        @ProtocolField(order = 1, size = 8, presentIf = "later==1")
        private int early;
        @ProtocolField(order = 2, size = 8)
        private int later;
    }

    /** presentIf 前向引用(引用更晚的字段)注册期拒绝。 */
    @Test
    void presentIfForwardReferenceRejected() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new ProtocolCodec<>(PresentIfFwdFrame.class));
        assertThat(ex).hasMessageContaining("not earlier in order");
    }
}
