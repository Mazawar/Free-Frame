package com.netproto.demo.protocol.realworld.modbus;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** Modbus 寄存器(16bit,大端)。 */
@Data
@ToString
@Protocol(id = "modbus-register", name = "Modbus 寄存器", group = "Modbus")
public class MbRegister {

    @ProtocolField(order = 1, size = 16)
    private int value;

    public static MbRegister of(int v) {
        MbRegister r = new MbRegister();
        r.setValue(v);
        return r;
    }
}
