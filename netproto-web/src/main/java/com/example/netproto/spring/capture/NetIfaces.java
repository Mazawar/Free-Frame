package com.example.netproto.spring.capture;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.List;

/** 网卡查找/列表小工具(CaptureEngine/RawSender/Web 共用)。 */
public final class NetIfaces {

    private NetIfaces() {}

    public static List<PcapNetworkInterface> list() throws PcapNativeException {
        return Pcaps.findAllDevs();
    }

    public static PcapNetworkInterface find(String name) throws PcapNativeException {
        for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
            if (nif.getName().equals(name)) {
                return nif;
            }
        }
        throw new IllegalArgumentException("network interface not found: " + name);
    }
}
