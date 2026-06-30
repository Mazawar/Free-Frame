package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ChecksumAlgorithmTest {

    /**
     * 用一个最简 IPv4 头(20字节)验证:序列化后校验和字段被引擎填上正确值。
     * 全 0 输入(除 version/ihl)→ 校验和 = 反码求和(version/ihl 字节 = 0x45)。
     */
    @Test
    void checksumFieldIsComputedOnSerialize() {
        ProtocolCodec<Ipv4HeaderWithChecksum> codec = new ProtocolCodec<>(Ipv4HeaderWithChecksum.class);

        Ipv4HeaderWithChecksum h = new Ipv4HeaderWithChecksum();
        h.setVersion(4);
        h.setIhl(5);
        h.setTos(0);
        h.setTotalLength(20);
        h.setIdentification(0);
        h.setFlags(0);
        h.setFragmentOffset(0);
        h.setTtl(0);
        h.setProtocol(0);
        h.setHeaderChecksum(0);   // 占位,引擎会重算
        h.setSourceIp(0);
        h.setDestinationIp(0);

        byte[] out = codec.serialize(h);
        // 校验和字段在字节偏移 10-11(IPv4 头第 11-12 字节,0-indexed 10-11)
        int computed = ((out[10] & 0xFF) << 8) | (out[11] & 0xFF);
        // 手算:全头除校验和外只有 0x45 00 00 14(其余0),反码求和
        // 0x4500 + 0x0014 = 0x4514;取反 = 0xBAEB
        assertThat(computed).isEqualTo(0xBAEB);
    }
}
