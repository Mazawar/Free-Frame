package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CodecBitFieldTest {

    @Data
    @ProtocolPacket(port = 7001)
    public static class BitFields {
        @ProtocolField(order = 1, size = 4)  private int version;
        @ProtocolField(order = 2, size = 4)  private int ihl;
        @ProtocolField(order = 3, size = 6)  private int dscp;
        @ProtocolField(order = 4, size = 2)  private int ecn;
        @ProtocolField(order = 5, size = 13) private int fragmentOffset;
        @ProtocolField(order = 6, size = 9)  private int tail; // 4+4+6+2+13+9 = 38 bit -> 5 bytes (round up)
    }

    @Test
    void roundTripsBitFieldsAcrossByteBoundaries() {
        ProtocolCodec<BitFields> codec = new ProtocolCodec<>(BitFields.class);
        BitFields original = new BitFields();
        original.setVersion(0x4);
        original.setIhl(0x5);
        original.setDscp(0x2A);
        original.setEcn(0x1);
        original.setFragmentOffset(0x0123);
        original.setTail(0x1FF); // 9 位全1

        byte[] out = codec.serialize(original);
        BitFields parsed = codec.deserialize(out);

        assertThat(parsed.getVersion()).isEqualTo(0x4);
        assertThat(parsed.getIhl()).isEqualTo(0x5);
        assertThat(parsed.getDscp()).isEqualTo(0x2A);
        assertThat(parsed.getEcn()).isEqualTo(0x1);
        assertThat(parsed.getFragmentOffset()).isEqualTo(0x0123);
        assertThat(parsed.getTail()).isEqualTo(0x1FF);
    }

    @Data
    @ProtocolPacket(port = 7002)
    public static class Outer {
        @ProtocolField(order = 1, size = 8)  private int mark;
        @ProtocolField(order = 2, type = FieldType.NESTED) private BitFields inner;
        @ProtocolField(order = 3, size = 8)  private int end;
    }

    @Test
    void roundTripsNestedEntity() {
        new ProtocolCodec<>(BitFields.class); // 触发内部 codec 构建
        ProtocolCodec<Outer> codec = new ProtocolCodec<>(Outer.class);

        Outer original = new Outer();
        original.setMark(0xAB);
        BitFields inner = new BitFields();
        inner.setVersion(0x4);
        inner.setIhl(0x5);
        inner.setDscp(0x2A);
        inner.setEcn(0x1);
        inner.setFragmentOffset(0x0123);
        inner.setTail(0x1FF);
        original.setInner(inner);
        original.setEnd(0xCD);

        byte[] out = codec.serialize(original);
        Outer parsed = codec.deserialize(out);

        assertThat(parsed.getMark()).isEqualTo(0xAB);
        assertThat(parsed.getEnd()).isEqualTo(0xCD);
        assertThat(parsed.getInner().getVersion()).isEqualTo(0x4);
        assertThat(parsed.getInner().getFragmentOffset()).isEqualTo(0x0123);
        assertThat(parsed.getInner().getTail()).isEqualTo(0x1FF);
    }
}
