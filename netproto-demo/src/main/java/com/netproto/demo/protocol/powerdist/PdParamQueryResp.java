package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * 0x14 参数查询响应(平台 → 终端)。
 * 信令体 = 参数个数(1B) + 参数个数 × 条目(3B:编号+值) + 校验和(2B)。
 * 演示点:countField 计数驱动 LIST,列表之后还有定长尾随字段(校验和)。
 */
@Data
@ToString
@Protocol(id = "pd-param-query-resp", name = "参数查询响应", group = "参数配置")
@BindOn(parent = "pd", when = "signalType == 0x14")
public class PdParamQueryResp {

    @ProtocolField(order = 1, size = 8, label = "参数个数")
    private int paramCount = 2;

    @ProtocolField(order = 2, type = FieldType.LIST,
            elementClass = PdParamItem.class, countField = "paramCount")
    private List<PdParamItem> params = new ArrayList<>(List.of(
            PdParamItem.of(1, 0x3C), PdParamItem.of(2, 0x190)));

    /** 尾随校验和(源协议为固定 55AA 占位,非计算字段)。 */
    @ProtocolField(order = 3, size = 16, label = "校验和")
    private int checksum = 0x55AA;
}
