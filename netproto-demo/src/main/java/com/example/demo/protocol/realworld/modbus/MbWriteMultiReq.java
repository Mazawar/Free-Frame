package com.example.demo.protocol.realworld.modbus;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * Modbus 功能码 16(0x10):写多个寄存器请求。
 * 这里 quantity 的单位就是「寄存器个数」→ countField 直接正确驱动
 * (与 fc3 响应的 byteCount 单位对比,见矩阵)。
 */
@Data
@ToString
@Protocol(id = "modbus-write-multi", name = "Modbus 写多寄存器请求")
@BindOn(parent = "modbus", when = "functionCode == 16")
public class MbWriteMultiReq {

    @ProtocolField(order = 1, size = 16)
    private int startAddress;

    /** 寄存器数量(单位=元素个数)。 */
    @ProtocolField(order = 2, size = 16)
    private int quantity;

    /** 字节数 = quantity × 2(展示用)。 */
    @ProtocolField(order = 3, size = 8)
    private int byteCount;

    @ProtocolField(order = 4, type = FieldType.LIST,
            countField = "quantity", elementClass = MbRegister.class)
    private List<MbRegister> registers = new ArrayList<>();

    public static MbWriteMultiReq of(int startAddress, int... values) {
        MbWriteMultiReq r = new MbWriteMultiReq();
        r.setStartAddress(startAddress);
        r.setQuantity(values.length);
        r.setByteCount(values.length * 2);
        for (int v : values) {
            r.getRegisters().add(MbRegister.of(v));
        }
        return r;
    }
}
