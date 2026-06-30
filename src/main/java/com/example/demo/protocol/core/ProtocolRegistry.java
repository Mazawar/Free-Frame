package com.example.demo.protocol.core;

import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.annotation.ProtocolTransport;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class ProtocolRegistry {

    private static final Map<Integer, ProtocolCodec<?>> codecs = new ConcurrentHashMap<>();

    private ProtocolRegistry() {}

    public static <T> void register(Class<T> clazz) {
        ProtocolPacket ann = clazz.getAnnotation(ProtocolPacket.class);
        if (ann == null) {
            throw new IllegalArgumentException(clazz.getName() + " is not annotated with @ProtocolPacket");
        }
        codecs.put(ann.port(), new ProtocolCodec<>(clazz));
    }

    @SuppressWarnings("unchecked")
    public static <T> ProtocolCodec<T> getCodec(int port) {
        return (ProtocolCodec<T>) codecs.get(port);
    }

    public static boolean hasCodec(int port) {
        return codecs.containsKey(port);
    }
}
