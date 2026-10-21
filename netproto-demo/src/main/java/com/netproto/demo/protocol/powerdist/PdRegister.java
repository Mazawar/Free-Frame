package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 0x01 开机注册(终端 → 平台):上电第一步,令牌位全 0。
 * 信令体 = 设备型号(1B) + 组网方式(1B) + 注册时间(4B)。
 */
@Data
@ToString
@Protocol(id = "pd-reg", name = "开机注册", group = "接入管理")
@BindOn(parent = "pd", when = "signalType == 0x01")
public class PdRegister {

    /** 01 标准DTU / 02 增强网关 / 03 微型采集终端。 */
    @ProtocolField(order = 1, size = 8, label = "设备型号")
    private int model = 1;

    /** 00 以太网 / 01 蜂窝网络 / 02 专线接入。 */
    @ProtocolField(order = 2, size = 8, label = "组网方式")
    private int netMode;

    /** Unix 秒。 */
    @ProtocolField(order = 3, size = 32, label = "注册时间")
    private long regTime = 0x5F304000L;
}
