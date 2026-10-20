package com.example.demo.protocol.realworld.s7;

import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * S7 Any-Type Item(定长 12 字节):[0x12,0x0A,0x10,传输大小语法] + 长度 + DB 号 + 区号 + 地址。
 * 地址是「字节地址×8 的 3 字节小端」——引擎大端位序下直接按 3 字节原始值展示(见矩阵注记)。
 */
@Data
@ToString
@Protocol(id = "s7-item", name = "S7 Item")
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

    /** 3 字节地址(字节地址×8,原始大端读;真实工具按小端×8 解,见矩阵)。 */
    @ProtocolField(order = 8, size = 24)
    private int address;

    public static S7Item db(int dbNumber, int startByte, int byteCount) {
        S7Item i = new S7Item();
        i.setLength(byteCount);
        i.setDbNumber(dbNumber);
        i.setArea(0x84);
        // 线上格式 = 字节地址×8 的 3 字节小端;引擎整数字段为大端 → 存反转值,
        // 使序列化字节与真实 S7 一致(小端整数支持见验证矩阵缺口)。
        int a = startByte * 8;
        i.setAddress(((a & 0xFF) << 16) | (a & 0xFF00) | ((a >> 16) & 0xFF));
        return i;
    }
}
