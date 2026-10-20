package com.example.demo.protocol.realworld.s7;

import com.example.netproto.annotation.Endian;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * S7 Any-Type Item(定长 12 字节):[0x12,0x0A,0x10,传输大小语法] + 长度 + DB 号 + 区号 + 地址。
 * 地址是「字节地址×8 的 3 字节小端」——endian=LITTLE,引擎按语义值读写。
 */
@Data
@ToString
@Protocol(id = "s7-item", name = "S7 Item", group = "S7comm")
public class S7Item {

    @ProtocolField(order = 1, size = 8)
    private int variableSpec = 0x12;

    /** Item 头剩余长度 = 10。 */
    @ProtocolField(order = 2, size = 8)
    private int lengthOfRead = 0x0A;

    /** 0x10 = Any-Type。 */
    @ProtocolField(order = 3, size = 8)
    private int syntaxId = 0x10;

    /** 传输大小语法:2=字节 4=字。 */
    @ProtocolField(order = 4, size = 8)
    private int transportSize = 0x02;

    /** 读取长度(按 transportSize 单位)。 */
    @ProtocolField(order = 5, size = 16)
    private int length;

    @ProtocolField(order = 6, size = 16)
    private int dbNumber;

    /** 0x84=DB 区 0x82=输出 0x83=输入。 */
    @ProtocolField(order = 7, size = 8)
    private int area;

    /** 3 字节地址(字节地址×8,线上小端;endian=LITTLE 由引擎处理字节序)。 */
    @ProtocolField(order = 8, size = 24, endian = Endian.LITTLE)
    private int address;

    public static S7Item db(int dbNumber, int startByte, int byteCount) {
        S7Item i = new S7Item();
        i.setLength(byteCount);
        i.setDbNumber(dbNumber);
        i.setArea(0x84);
        i.setAddress(startByte * 8);   // 直接存语义值,序列化/解析自动小端
        return i;
    }
}
