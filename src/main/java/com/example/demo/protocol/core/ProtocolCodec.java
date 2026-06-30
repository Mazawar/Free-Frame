package com.example.demo.protocol.core;

import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.Packet;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public final class ProtocolCodec<T> {

    private final Class<T> clazz;
    private final List<FieldInfo> fixedFields;
    private final FieldInfo payloadField;
    private final int headerSize;

    public ProtocolCodec(Class<T> clazz) {
        this.clazz = clazz;
        List<FieldInfo> fixed = new ArrayList<>();
        FieldInfo payload = null;

        for (Field f : clazz.getDeclaredFields()) {
            if (f.isAnnotationPresent(com.example.demo.protocol.annotation.Payload.class)) {
                payload = new FieldInfo(f, -1, -1, true);
            } else if (f.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolField.class)) {
                com.example.demo.protocol.annotation.ProtocolField ann = f.getAnnotation(com.example.demo.protocol.annotation.ProtocolField.class);
                fixed.add(new FieldInfo(f, ann.order(), ann.size(), false));
            }
        }

        fixed.sort(Comparator.comparingInt(f -> f.order));

        if (fixed.stream().mapToInt(f -> f.size).sum() % 8 != 0) {
            throw new IllegalArgumentException("Fixed field sizes must sum to a whole number of bytes in " + clazz.getName());
        }

        this.fixedFields = fixed;
        this.payloadField = payload;
        this.headerSize = fixed.stream().mapToInt(f -> f.size).sum() / 8;
    }

    public int headerSize() {
        return headerSize;
    }

    public T deserialize(byte[] rawData) {
        return deserialize(rawData, 0, rawData.length);
    }

    public T deserialize(byte[] rawData, int offset, int length) {
        try {
            T obj = clazz.getDeclaredConstructor().newInstance();
            int pos = offset;

            for (FieldInfo fi : fixedFields) {
                fi.field.setAccessible(true);
                int byteSize = fi.size / 8;
                long val = readBytes(rawData, pos, byteSize);
                fi.field.set(obj, convertToFieldType(fi.field.getType(), val, byteSize));
                pos += byteSize;
            }

            if (payloadField != null && length > headerSize) {
                payloadField.field.setAccessible(true);
                byte[] payloadData = Arrays.copyOfRange(rawData, offset + headerSize, offset + length);
                payloadField.field.set(obj, payloadData);
            }

            return obj;
        } catch (Exception e) {
            throw new RuntimeException("Failed to deserialize " + clazz.getName(), e);
        }
    }

    public byte[] serialize(T obj) {
        try {
            int totalSize = headerSize;
            if (payloadField != null) {
                payloadField.field.setAccessible(true);
                byte[] payloadData = (byte[]) payloadField.field.get(obj);
                totalSize += payloadData != null ? payloadData.length : 0;
            }

            ByteBuffer buf = ByteBuffer.allocate(totalSize).order(ByteOrder.BIG_ENDIAN);

            for (FieldInfo fi : fixedFields) {
                fi.field.setAccessible(true);
                Object value = fi.field.get(obj);
                int byteSize = fi.size / 8;
                long val = convertFromFieldType(fi.field.getType(), value);
                writeBytes(buf, val, byteSize);
            }

            if (payloadField != null) {
                payloadField.field.setAccessible(true);
                byte[] payloadData = (byte[]) payloadField.field.get(obj);
                if (payloadData != null) {
                    buf.put(payloadData);
                }
            }

            return buf.array();
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize " + clazz.getName(), e);
        }
    }

    public Packet toPacket(byte[] rawData, int offset, int length) {
        org.pcap4j.util.ByteArrays.validateBounds(rawData, offset, length);
        T obj = deserialize(rawData, offset, length);
        return new AutoPacket(rawData, offset, length, obj);
    }

    public Packet toPacket(T obj) {
        byte[] rawData = serialize(obj);
        return new AutoPacket(rawData, 0, rawData.length, obj);
    }

    public T fromPacket(Packet packet) {
        byte[] rawData = packet.getRawData();
        return deserialize(rawData);
    }

    private static long readBytes(byte[] data, int offset, int size) {
        long val = 0;
        for (int i = 0; i < size; i++) {
            val = (val << 8) | (data[offset + i] & 0xFF);
        }
        return val;
    }

    private static void writeBytes(ByteBuffer buf, long val, int size) {
        for (int i = size - 1; i >= 0; i--) {
            buf.put((byte) ((val >> (i * 8)) & 0xFF));
        }
    }

    private static Object convertToFieldType(Class<?> type, long val, int byteSize) {
        if (type == byte.class || type == Byte.class) return (byte) val;
        if (type == short.class || type == Short.class) return (short) val;
        if (type == int.class || type == Integer.class) return (int) val;
        if (type == long.class || type == Long.class) return val;
        return val;
    }

    private static long convertFromFieldType(Class<?> type, Object value) {
        if (value == null) return 0;
        if (value instanceof Number n) return n.longValue();
        return 0;
    }

    private record FieldInfo(Field field, int order, int size, boolean isPayload) {}

    private final class AutoPacket extends AbstractPacket {

        private static final long serialVersionUID = 1L;

        private final byte[] rawData;
        private final AutoHeader autoHeader;
        private final Packet payload;

        AutoPacket(byte[] rawData, int offset, int length, T obj) {
            this.rawData = Arrays.copyOfRange(rawData, offset, offset + length);
            this.autoHeader = new AutoHeader(this.rawData, obj);
            this.payload = null;
        }

        @Override
        public AutoHeader getHeader() {
            return autoHeader;
        }

        @Override
        public Packet getPayload() {
            return payload;
        }

        @Override
        public AutoBuilder getBuilder() {
            return new AutoBuilder();
        }

        @Override
        public int length() {
            return rawData.length;
        }

        @Override
        public String toString() {
            return "[AutoPacket " + clazz.getSimpleName() + " " + autoHeader + "]";
        }

        @Override
        public byte[] getRawData() {
            return rawData.clone();
        }
    }

    private final class AutoHeader extends AbstractPacket.AbstractHeader {

        private static final long serialVersionUID = 1L;
        private final byte[] rawData;
        private final T obj;

        AutoHeader(byte[] rawData, T obj) {
            this.rawData = rawData;
            this.obj = obj;
        }

        @Override
        public int length() {
            return rawData.length;
        }

        @Override
        public byte[] getRawData() {
            return rawData.clone();
        }

        @Override
        public List<byte[]> getRawFields() {
            List<byte[]> fields = new ArrayList<>();
            int pos = 0;
            for (FieldInfo fi : fixedFields) {
                int byteSize = fi.size / 8;
                byte[] fieldBytes = new byte[byteSize];
                System.arraycopy(rawData, pos, fieldBytes, 0, byteSize);
                fields.add(fieldBytes);
                pos += byteSize;
            }
            if (payloadField != null && rawData.length > headerSize) {
                fields.add(Arrays.copyOfRange(rawData, headerSize, rawData.length));
            }
            return fields;
        }

        @Override
        public String toString() {
            return obj != null ? obj.toString() : Arrays.toString(rawData);
        }
    }

    public final class AutoBuilder extends AbstractPacket.AbstractBuilder {

        private T obj;

        AutoBuilder() {
            try {
                this.obj = clazz.getDeclaredConstructor().newInstance();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public AutoBuilder withObject(T obj) {
            this.obj = obj;
            return this;
        }

        @Override
        public AutoPacket build() {
            byte[] data = serialize(obj);
            return new AutoPacket(data, 0, data.length, obj);
        }
    }
}
