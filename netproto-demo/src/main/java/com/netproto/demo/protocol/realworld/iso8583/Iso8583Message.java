package com.netproto.demo.protocol.realworld.iso8583;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * ISO 8583(银行卡报文互换标准,金融 POS/收单核心)——孤岛协议,定长子集。
 * <pre>
 *  | MTI(4B ASCII) | Primary Bitmap(8B=64bit) | 按 bit 出现的条件字段... |
 *    bit n = 1 → 第 n 号字段存在
 * </pre>
 * 位图驱动条件字段使用一等语法 {@code bitmap[n] == 1}(Expr 位索引,从最高有效位起数,
 * 与 8583 bit 编号一致)——不再需要把位图拆成 64 个 1bit 字段。
 * <p>
 * 子集字段:3 处理码 / 4 金额 / 7 传输时间 / 11 STAN / 41 终端 / 42 商户。
 * 变长域(LLVAR/LLLVAR 的 ASCII/BCD 长度前缀)与 BCD 数值不在本子集 —— 见验证矩阵。
 */
@Data
@ToString
@Protocol(id = "iso8583", name = "ISO 8583 银行卡报文")
public class Iso8583Message {

    /** 消息类型标识,如 "0100"(授权请求)/"0210"(授权响应)。 */
    @ProtocolField(order = 1, type = FieldType.STRING, size = 32)
    private String mti = "0100";

    /** 主位图:bit n(MSB 起数)= 第 n 号字段存在。 */
    @ProtocolField(order = 2, size = 64, type = FieldType.UNSIGNED)
    private long bitmap;

    // ---- 条件字段(bitmap[n] == 1 才出现) ----

    /** F2 主账号 PAN:LLVAR(两位 ASCII 长度 + ≤19 位数字)。 */
    @ProtocolField(order = 3, type = FieldType.STRING, size = 16, presentIf = "bitmap[2] == 1")
    private String panLen = "00";

    @ProtocolField(order = 4, type = FieldType.STRING,
            lengthField = "panLen", lengthAscii = true, presentIf = "bitmap[2] == 1")
    private String pan = "";

    /** F3 处理码,6B 数字。 */
    @ProtocolField(order = 5, type = FieldType.STRING, size = 48, presentIf = "bitmap[3] == 1")
    private String processingCode = "";

    /** F4 交易金额,12B 数字(分)。 */
    @ProtocolField(order = 6, type = FieldType.STRING, size = 96, presentIf = "bitmap[4] == 1")
    private String amount = "";

    /** F7 传输时间,10B MMDDhhmmss。 */
    @ProtocolField(order = 7, type = FieldType.STRING, size = 80, presentIf = "bitmap[7] == 1")
    private String transmission = "";

    /** F11 系统跟踪审计号,6B。 */
    @ProtocolField(order = 8, type = FieldType.STRING, size = 48, presentIf = "bitmap[11] == 1")
    private String stan = "";

    /** F41 终端标识,8B。 */
    @ProtocolField(order = 9, type = FieldType.STRING, size = 64, presentIf = "bitmap[41] == 1")
    private String terminalId = "";

    /** F42 商户标识,15B。 */
    @ProtocolField(order = 10, type = FieldType.STRING, size = 120, presentIf = "bitmap[42] == 1")
    private String merchantId = "";

    // ---- 组装便捷:置位并填值 ----

    private void setBit(int n) {
        this.bitmap |= 1L << (64 - n);
    }

    public void setField2(String pan) {
        setBit(2);
        this.pan = pan;
        this.panLen = String.format("%02d", pan.length());   // LLVAR 两位 ASCII 长度
    }

    public void setField3(String v) {
        setBit(3);
        this.processingCode = v;
    }

    public void setField4(String v) {
        setBit(4);
        this.amount = v;
    }

    public void setField7(String v) {
        setBit(7);
        this.transmission = v;
    }

    public void setField11(String v) {
        setBit(11);
        this.stan = v;
    }

    public void setField41(String v) {
        setBit(41);
        this.terminalId = v;
    }

    public void setField42(String v) {
        setBit(42);
        this.merchantId = v;
    }
}
