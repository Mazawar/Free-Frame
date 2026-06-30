package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 回归测试:确认旧协议 MyProtocol 在引擎升级(位游标+类型+NESTED+长度引用+条件)后,
 * 不改一行代码依然能正确 round-trip。这是向后兼容的硬承诺。
 */
class MyProtocolRegressionTest {

    @Test
    void myProtocolRoundTripsUnchanged() {
        ProtocolCodec<MyProtocol> codec = new ProtocolCodec<>(MyProtocol.class);

        MyProtocol original = new MyProtocol();
        original.setVersion((byte) 1);
        original.setType((byte) 2);
        original.setReserved((short) 0);
        original.setSequenceId(12345);
        original.setPayloadData(new byte[]{0x01, 0x02, 0x03, 0x04});

        byte[] out = codec.serialize(original);
        // 结构:1(version)+1(type)+2(reserved)+4(sequenceId) 头 + 4 payload = 12 字节
        assertThat(out).hasSize(12);

        MyProtocol parsed = codec.deserialize(out);
        assertThat(parsed.getVersion()).isEqualTo((byte) 1);
        assertThat(parsed.getType()).isEqualTo((byte) 2);
        assertThat(parsed.getReserved()).isEqualTo((short) 0);
        assertThat(parsed.getSequenceId()).isEqualTo(12345);
        assertThat(parsed.getPayloadData()).containsExactly(0x01, 0x02, 0x03, 0x04);
    }
}
