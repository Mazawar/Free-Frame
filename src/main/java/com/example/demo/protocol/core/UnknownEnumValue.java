package com.example.demo.protocol.core;

/**
 * 未知枚举值的兜底占位:反序列化遇 enum 未覆盖的整数时使用。
 * 实现 ProtocolEnum,序列化返回存的原始 int,信息零丢失。
 */
public final class UnknownEnumValue implements ProtocolEnum {

    private final int rawValue;
    private final Class<? extends Enum<?>> enumType;

    public UnknownEnumValue(int rawValue, Class<? extends Enum<?>> enumType) {
        this.rawValue = rawValue;
        this.enumType = enumType;
    }

    @Override
    public int value() {
        return rawValue;
    }

    public Class<? extends Enum<?>> enumType() {
        return enumType;
    }

    @Override
    public String toString() {
        return "Unknown(" + enumType.getSimpleName() + "=" + rawValue + ")";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof UnknownEnumValue that)) return false;
        return rawValue == that.rawValue && enumType.equals(that.enumType);
    }

    @Override
    public int hashCode() {
        return rawValue * 31 + enumType.hashCode();
    }
}
