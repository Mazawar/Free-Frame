package com.netproto.demo.protocol.realworld.modbus;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.CountUnit;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * Modbus 功能码 03:读保持寄存器响应 —— 定长 16bit 寄存器循环。
 * byteCount 单位是「字节」(寄存器数×2):用 countUnit=BYTES 声明后直接驱动循环,
 * 且组装期按元素字节数自动回填(无需手工设置)。
 */
@Data
@ToString
@Protocol(id = "modbus-read-resp", name = "Modbus 读保持寄存器响应", group = "Modbus")
@BindOn(parent = "modbus", when = "functionCode == 3")
public class MbReadHoldingResp {

    /** 数据字节数 = 寄存器数 × 2(组装期自动)。 */
    @ProtocolField(order = 1, size = 8)
    private int byteCount;

    @ProtocolField(order = 2, type = FieldType.LIST,
            countField = "byteCount", countUnit = CountUnit.BYTES,
            elementClass = MbRegister.class)
    private List<MbRegister> registers = new ArrayList<>();

    public static MbReadHoldingResp of(int... values) {
        MbReadHoldingResp r = new MbReadHoldingResp();
        for (int v : values) {
            r.getRegisters().add(MbRegister.of(v));
        }
        return r;   // byteCount 由引擎回填
    }
}
