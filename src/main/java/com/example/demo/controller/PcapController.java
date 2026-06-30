package com.example.demo.controller;

import com.example.demo.service.PcapService;
import lombok.RequiredArgsConstructor;
import org.pcap4j.core.PcapNetworkInterface;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/pcap")
@RequiredArgsConstructor
public class PcapController {

    private final PcapService pcapService;

    @GetMapping("/interfaces")
    public Map<String, Object> listInterfaces() {
        Map<String, Object> result = new HashMap<>();
        try {
            List<PcapNetworkInterface> interfaces = pcapService.listNetworkInterfaces();
            List<Map<String, String>> ifaceList = interfaces.stream().map(nif -> {
                Map<String, String> m = new HashMap<>();
                m.put("name", nif.getName());
                m.put("description", nif.getDescription());
                return m;
            }).toList();
            result.put("interfaces", ifaceList);
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        return result;
    }

    @PostMapping("/capture/start")
    public Map<String, Object> startCapture(@RequestParam String interfaceName,
                                            @RequestParam(defaultValue = "100") int maxPackets) {
        Map<String, Object> result = new HashMap<>();
        try {
            pcapService.startCapture(interfaceName, maxPackets);
            result.put("status", "started");
            result.put("interface", interfaceName);
            result.put("maxPackets", maxPackets);
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        return result;
    }

    @PostMapping("/capture/stop")
    public Map<String, Object> stopCapture() {
        Map<String, Object> result = new HashMap<>();
        try {
            pcapService.stopCapture();
            result.put("status", "stopped");
            result.put("capturedPackets", pcapService.getCapturedPackets().size());
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        return result;
    }

    @GetMapping("/capture/status")
    public Map<String, Object> captureStatus() {
        Map<String, Object> result = new HashMap<>();
        result.put("capturing", pcapService.isCapturing());
        result.put("packetCount", pcapService.getCapturedPackets().size());
        return result;
    }

    @GetMapping("/capture/packets")
    public Map<String, Object> getCapturedPackets() {
        Map<String, Object> result = new HashMap<>();
        result.put("packets", pcapService.getCapturedPackets());
        return result;
    }
}
