package com.netproto.demo.web;

import com.netproto.demo.protocol.realworld.RealWorldSamples;
import com.netproto.spring.capture.CaptureEngine;
import com.netproto.stack.StackEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 真实协议样例注入端点:组装 Modbus TCP / S7comm / MQTT / Kafka 的完整以太网帧
 * 并注入解析管线,页面无需真实流量即可看到解析效果。
 * DL/T 645 与 ISO 8583 为串口/裸流孤岛协议(无以太网帧形态),不在注入之列。
 */
@RestController
@RequestMapping("/api/demo")
public class DemoSampleController {

    private final CaptureEngine capture;
    private final RealWorldSamples samples;

    public DemoSampleController(CaptureEngine capture, StackEncoder encoder) {
        this.capture = capture;
        this.samples = new RealWorldSamples(encoder);
    }

    /** 注入全部 6 帧真实协议样例,返回各帧长度。 */
    @PostMapping("/samples")
    public Map<String, Object> injectSamples() {
        Map<String, Integer> frames = new LinkedHashMap<>();
        frames.put("modbus-read-resp", samples.modbusReadResp().length);
        frames.put("modbus-write-multi", samples.modbusWriteMulti().length);
        frames.put("s7-read-job", samples.s7ReadJob().length);
        frames.put("s7-ack-data", samples.s7AckData().length);
        frames.put("mqtt-connect", samples.mqttConnect().length);
        frames.put("kafka-metadata", samples.kafkaMetadata().length);

        capture.inject("demo", samples.modbusReadResp());
        capture.inject("demo", samples.modbusWriteMulti());
        capture.inject("demo", samples.s7ReadJob());
        capture.inject("demo", samples.s7AckData());
        capture.inject("demo", samples.mqttConnect());
        capture.inject("demo", samples.kafkaMetadata());

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "injected");
        out.put("frames", frames);
        return out;
    }
}
