package com.example.netproto.protocols.tcp;

import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.annotation.Protocol;
import lombok.Data;
import lombok.ToString;

import java.util.EnumSet;
import java.util.Set;

/**
 * TCP flags 字段(简化):用 Set<TcpFlag> 表达。
 * 实际 TCP flags 占 9 位(含保留位/NS/CWR/ECE),此处用 8 位示例;
 * 保留位(mask 未覆盖)反序列化时忽略。
 */
@Data
@ToString
@Protocol(id = "tcp-header-flags")
public class TcpHeaderFlags {

    @ProtocolField(order = 1, size = 8, flagClass = TcpFlag.class)
    private Set<TcpFlag> flags = EnumSet.noneOf(TcpFlag.class);
}
