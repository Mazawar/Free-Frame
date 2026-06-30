package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.dhcp.DhcpMsgType;
import com.example.demo.protocol.dhcp.DhcpOptions;
import com.example.demo.protocol.dhcp.Router;
import com.example.demo.protocol.dhcp.SubnetMask;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TlvUnknownTypeTest {

    @Test
    void unknownTypeIsSkipped() {
        new ProtocolCodec<>(SubnetMask.class);
        new ProtocolCodec<>(Router.class);
        new ProtocolCodec<>(DhcpMsgType.class);
        ProtocolCodec<DhcpOptions> codec = new ProtocolCodec<>(DhcpOptions.class);

        // 手构字节:SubnetMask(01 04 C0A80101) + 未知 type 99(63 01 AB) + Router(03 04 C0A801FE) + FF
        byte[] data = {
                0x01, 0x04, (byte) 0xC0, (byte) 0xA8, 0x01, 0x01,   // SubnetMask 192.168.1.1
                0x63, 0x01, (byte) 0xAB,                            // type=99(未知) len=1 value=AB → 跳过
                0x03, 0x04, (byte) 0xC0, (byte) 0xA8, 0x01, (byte) 0xFE,  // Router
                (byte) 0xFF                                         // End
        };

        DhcpOptions parsed = codec.deserialize(data);
        // 未知 type 99 被跳过,只剩 SubnetMask + Router
        assertThat(parsed.getOptions()).hasSize(2);
        assertThat(parsed.getOptions().get(0)).isInstanceOf(SubnetMask.class);
        assertThat(parsed.getOptions().get(1)).isInstanceOf(Router.class);
    }
}
