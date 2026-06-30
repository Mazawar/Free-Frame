package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CodecConditionalTest {

    @Data
    @ProtocolPacket(port = 7005)
    public static class CondPacket {
        @ProtocolField(order = 1, size = 8) private int flag;
        @ProtocolField(order = 2, size = 8) private int always;
        @ProtocolField(order = 3, size = 8, presentIf = "flag==1") private int extra;
    }

    @Test
    void fieldPresentWhenConditionMet() {
        ProtocolCodec<CondPacket> codec = new ProtocolCodec<>(CondPacket.class);
        CondPacket original = new CondPacket();
        original.setFlag(1);
        original.setAlways(0xAA);
        original.setExtra(0xBB);

        byte[] out = codec.serialize(original);
        // flag=1 -> extra 出现 -> 3 字节
        assertThat(out).containsExactly(0x01, 0xAA, 0xBB);

        CondPacket parsed = codec.deserialize(out);
        assertThat(parsed.getFlag()).isEqualTo(1);
        assertThat(parsed.getAlways()).isEqualTo(0xAA);
        assertThat(parsed.getExtra()).isEqualTo(0xBB);
    }

    @Test
    void fieldAbsentWhenConditionNotMet() {
        ProtocolCodec<CondPacket> codec = new ProtocolCodec<>(CondPacket.class);
        CondPacket original = new CondPacket();
        original.setFlag(0);
        original.setAlways(0xAA);
        original.setExtra(0); // 不出现,值无所谓

        byte[] out = codec.serialize(original);
        // flag=0 -> extra 不出现 -> 2 字节
        assertThat(out).containsExactly(0x00, 0xAA);

        CondPacket parsed = codec.deserialize(out);
        assertThat(parsed.getFlag()).isEqualTo(0);
        assertThat(parsed.getAlways()).isEqualTo(0xAA);
        // extra 字段反序列化后保持 Java 默认值 0
        assertThat(parsed.getExtra()).isEqualTo(0);
    }
}
