package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.dhcp.DhcpMsgType;
import com.example.demo.protocol.dhcp.DhcpOptions;
import com.example.demo.protocol.dhcp.Router;
import com.example.demo.protocol.dhcp.SubnetMask;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TlvBasicTest {

    @Test
    void roundTripsKnownTlvTypes() {
        new ProtocolCodec<>(SubnetMask.class);
        new ProtocolCodec<>(Router.class);
        new ProtocolCodec<>(DhcpMsgType.class);
        ProtocolCodec<DhcpOptions> codec = new ProtocolCodec<>(DhcpOptions.class);

        DhcpOptions opts = new DhcpOptions();
        SubnetMask sm = new SubnetMask();
        sm.setMask(0xC0A80101);       // 192.168.1.1
        Router r = new Router();
        r.setAddress(0xC0A801FE);      // 192.168.1.254
        DhcpMsgType mt = new DhcpMsgType();
        mt.setType(2);                  // OFFER
        opts.getOptions().add(sm);
        opts.getOptions().add(r);
        opts.getOptions().add(mt);

        byte[] out = codec.serialize(opts);
        assertThat(out).containsExactly(
                0x01, 0x04, (byte) 0xC0, (byte) 0xA8, 0x01, 0x01,
                0x03, 0x04, (byte) 0xC0, (byte) 0xA8, 0x01, (byte) 0xFE,
                0x35, 0x01, 0x02,
                (byte) 0xFF);

        DhcpOptions parsed = codec.deserialize(out);
        assertThat(parsed.getOptions()).hasSize(3);
        assertThat(parsed.getOptions().get(0)).isInstanceOf(SubnetMask.class);
        assertThat(((SubnetMask) parsed.getOptions().get(0)).getMask()).isEqualTo(0xC0A80101);
        assertThat(parsed.getOptions().get(1)).isInstanceOf(Router.class);
        assertThat(((Router) parsed.getOptions().get(1)).getAddress()).isEqualTo(0xC0A801FE);
        assertThat(parsed.getOptions().get(2)).isInstanceOf(DhcpMsgType.class);
        assertThat(((DhcpMsgType) parsed.getOptions().get(2)).getType()).isEqualTo(2);
    }
}
