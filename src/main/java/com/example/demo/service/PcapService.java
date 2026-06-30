package com.example.demo.service;

import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.core.ProtocolRegistry;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

@Slf4j
@Service
public class PcapService {

    private final AtomicBoolean capturing = new AtomicBoolean(false);
    private PcapHandle handle;
    private Thread captureThread;
    private final List<String> capturedPackets = new ArrayList<>();

    public List<PcapNetworkInterface> listNetworkInterfaces() throws Exception {
        return Pcaps.findAllDevs();
    }

    public void startCapture(String ifaceName, int maxPackets) throws Exception {
        if (capturing.get()) {
            throw new IllegalStateException("Capture is already running");
        }

        PcapNetworkInterface nif = findInterface(ifaceName);
        if (nif == null) {
            throw new IllegalArgumentException("Network interface not found: " + ifaceName);
        }

        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 10;

        handle = nif.openLive(snapLen, mode, timeout);
        capturedPackets.clear();
        capturing.set(true);

        captureThread = new Thread(() -> {
            try {
                PacketListener listener = packet -> {
                    if (packet != null) {
                        String info = parsePacket(packet);
                        synchronized (capturedPackets) {
                            capturedPackets.add(info);
                        }
                        log.info("Captured packet: {}", info);
                    }
                };

                if (maxPackets > 0) {
                    handle.loop(maxPackets, listener);
                } else {
                    handle.loop(-1, listener);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (PcapNativeException | NotOpenException e) {
                log.error("Capture error", e);
            } finally {
                capturing.set(false);
            }
        });

        captureThread.start();
        log.info("Started capture on interface: {}", ifaceName);
    }

    public void stopCapture() throws NotOpenException {
        if (!capturing.get()) {
            return;
        }
        capturing.set(false);
        if (handle != null && handle.isOpen()) {
            handle.breakLoop();
            handle.close();
        }
        if (captureThread != null) {
            captureThread.interrupt();
            try {
                captureThread.join(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        log.info("Stopped capture. Total packets captured: {}", capturedPackets.size());
    }

    public List<String> getCapturedPackets() {
        synchronized (capturedPackets) {
            return new ArrayList<>(capturedPackets);
        }
    }

    public boolean isCapturing() {
        return capturing.get();
    }

    private String parsePacket(Packet packet) {
        if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            int dstPort = udp.getHeader().getDstPort().valueAsInt();
            int srcPort = udp.getHeader().getSrcPort().valueAsInt();
            Packet udpPayload = udp.getPayload();

            if (udpPayload != null && ProtocolRegistry.hasCodec(dstPort)) {
                return tryParseCustom(udpPayload.getRawData(), dstPort);
            }
            if (udpPayload != null && ProtocolRegistry.hasCodec(srcPort)) {
                return tryParseCustom(udpPayload.getRawData(), srcPort);
            }
        }
        return packet.toString();
    }

    private String tryParseCustom(byte[] rawData, int port) {
        ProtocolCodec<?> codec = ProtocolRegistry.getCodec(port);
        try {
            Object obj = codec.deserialize(rawData);
            return "[CUSTOM:" + port + "] " + obj.toString();
        } catch (Exception e) {
            log.debug("Failed to parse custom protocol on port {}", port, e);
            return "[RAW on port " + port + "] " + new String(rawData);
        }
    }

    private PcapNetworkInterface findInterface(String name) throws Exception {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        for (PcapNetworkInterface nif : interfaces) {
            if (nif.getName().equals(name)) {
                return nif;
            }
        }
        return null;
    }
}
