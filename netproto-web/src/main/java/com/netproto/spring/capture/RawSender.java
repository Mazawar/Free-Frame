package com.netproto.spring.capture;

import com.netproto.stack.StackEncoder;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * 原始以太网发包:pcap4j sendPacket 直接注入 L2 帧(非 UDP/TCP socket)。
 * <p>
 * 边界(诚实声明):Windows 需要 Npcap + 管理员权限;raw TCP 无内核栈握手,
 * 仅适合演示/测试;帧尾 FCS 不生成(通常由驱动负责)。
 */
public class RawSender {

    private static final Logger log = LoggerFactory.getLogger(RawSender.class);

    private final StackEncoder encoder;

    public RawSender(StackEncoder encoder) {
        this.encoder = encoder;
    }

    /** 组装协议层(外层→内层)并注入。 */
    public int send(String iface, List<?> layers) throws PcapNativeException, NotOpenException {
        byte[] frame = encoder.encode(layers);
        return sendRaw(iface, frame);
    }

    /** 直接注入原始帧,返回发送字节数。 */
    public int sendRaw(String iface, byte[] frame) throws PcapNativeException, NotOpenException {
        try (PcapHandle handle = NetIfaces.find(iface).openLive(
                65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 1000)) {
            handle.sendPacket(frame);
            log.info("sent {} bytes raw frame on {}", frame.length, iface);
            return frame.length;
        }
    }
}
