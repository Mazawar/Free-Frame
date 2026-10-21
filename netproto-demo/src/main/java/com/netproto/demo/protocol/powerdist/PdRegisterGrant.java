package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 0x02 注册许可(平台 → 终端):分配 2B 认证令牌(公共头令牌位),后续帧头自动携带。
 * 信令体 = 注册结果(1B) + 令牌有效期(4B);流水号/令牌本身在公共头内回显。
 */
@Data
@ToString
@Protocol(id = "pd-reg-grant", name = "注册许可", group = "智能配电")
@BindOn(parent = "pd", when = "signalType == 0x02")
public class PdRegisterGrant {

    /** 00 成功 / 01 失败 / 02 令牌无效 / 03 未注册。 */
    @ProtocolField(order = 1, size = 8, label = "注册结果")
    private int result;

    /** 秒,默认 3600(0x0E10)。 */
    @ProtocolField(order = 2, size = 32, label = "令牌有效期")
    private int ttl = 0x0E10;
}
