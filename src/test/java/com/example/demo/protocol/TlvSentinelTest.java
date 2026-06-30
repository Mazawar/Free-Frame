package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.dhcp.DhcpMsgType;
import com.example.demo.protocol.dhcp.DhcpOptions;
import com.example.demo.protocol.dhcp.Router;
import com.example.demo.protocol.dhcp.SubnetMask;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TlvSentinelTest {

    @Test
    void sentinelStopsParsing() {
        new ProtocolCodec<>(SubnetMask.class);
        new ProtocolCodec<>(Router.class);
        new ProtocolCodec<>(DhcpMsgType.class);
        ProtocolCodec<DhcpOptions> codec = new ProtocolCodec<>(DhcpOptions.class);

        // SubnetMask + FF(立即 sentinel)→ 只有 1 个元素
        byte[] data = {
                0x01, 0x04, (byte) 0xC0, (byte) 0xA8, 0x01, 0x01,
                (byte) 0xFF
        };
        DhcpOptions parsed = codec.deserialize(data);
        assertThat(parsed.getOptions()).hasSize(1);
        assertThat(parsed.getOptions().get(0)).isInstanceOf(SubnetMask.class);

        // round-trip:序列化回去应含 sentinel
        byte[] reserialized = codec.serialize(parsed);
        assertThat(reserialized[reserialized.length - 1]).isEqualTo((byte) 0xFF);
    }

    @Test
    void emptyTlvWithOnlySentinel() {
        new ProtocolCodec<>(SubnetMask.class);
        ProtocolCodec<DhcpOptions> codec = new ProtocolCodec<>(DhcpOptions.class);

        // 仅 FF → 空列表
        DhcpOptions parsed = codec.deserialize(new byte[]{(byte) 0xFF});
        assertThat(parsed.getOptions()).isEmpty();

        // 空列表序列化 → 仅 FF
        byte[] out = codec.serialize(new DhcpOptions());
        assertThat(out).containsExactly((byte) 0xFF);
    }
}
