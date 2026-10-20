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
 * Modbus 功能码 03:读保持寄存器响应 —— 定长 16bit 寄存器循环。
 * <p>
 * 注:byteCount 单位是「字节」(寄存器数×2),而引擎 countField 数「元素个数」,
 * 二者无倍率换算(真实缺口,见验证矩阵)——这里用 untilEnd 变通:data 是 PDU
 * 末段,读到帧尾等价;byteCount 保留仅作解析展示。
 */
@Data
@ToString
@Protocol(id = "modbus-read-resp", name = "Modbus 读保持寄存器响应")
@BindOn(parent = "modbus", when = "functionCode == 3")
public class MbReadHoldingResp {

    /** 数据字节数 = 寄存器数 × 2。 */
    @ProtocolField(order = 1, size = 8)
    private int byteCount;

    @ProtocolField(order = 2, type = FieldType.LIST,
            elementClass = MbRegister.class, untilEnd = true)
    private List<MbRegister> registers = new ArrayList<>();

    public static MbReadHoldingResp of(int... values) {
        MbReadHoldingResp r = new MbReadHoldingResp();
        r.setByteCount(values.length * 2);
        for (int v : values) {
            r.getRegisters().add(MbRegister.of(v));
        }
        return r;
    }
}
