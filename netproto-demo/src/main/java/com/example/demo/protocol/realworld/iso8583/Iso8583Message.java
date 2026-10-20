package com.example.demo.protocol.realworld.iso8583;

import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * ISO 8583(银行卡报文互换标准,金融 POS/收单核心)——孤岛协议,定长子集。
 * <pre>
 *  | MTI(4B ASCII) | Primary Bitmap(8B=64bit) | 按 bit 出现的条件字段... |
 *    bit n = 1 → 第 n 号字段存在 —— 「位图驱动条件字段」的教科书形态
 * </pre>
 * 纯注解方案:把 64bit 位图拆成 64 个 1bit 字段(bmp1..bmp64,引擎按位连续排列),
 * 条件字段 presentIf="bmpN == 1"。机制可行但 64 行位字段很啰嗦 —— 位图一等支持
 * (如 presentIf="bitmap[3] == 1")列为改进项(见验证矩阵)。
 * <p>
 * 子集字段:3 处理码 / 4 金额 / 7 传输时间 / 11 STAN / 41 终端 / 42 商户。
 * 变长域(LLVAR/LLLVAR 的 ASCII/BCD 长度前缀)与 BCD 数值不在本子集 —— 矩阵缺口。
 */
@Data
@ToString
@Protocol(id = "iso8583", name = "ISO 8583 银行卡报文")
public class Iso8583Message {

    /** 消息类型标识,如 "0100"(授权请求)/"0210"(授权响应)。 */
    @ProtocolField(order = 1, type = FieldType.STRING, size = 32)
    private String mti = "0100";

    // ---- Primary bitmap:64 个 1bit 字段,order 2..65 连续排列 = 8 字节 ----
    @ProtocolField(order = 2, size = 1) private int bmp1;
    @ProtocolField(order = 3, size = 1) private int bmp2;
    @ProtocolField(order = 4, size = 1) private int bmp3;
    @ProtocolField(order = 5, size = 1) private int bmp4;
    @ProtocolField(order = 6, size = 1) private int bmp5;
    @ProtocolField(order = 7, size = 1) private int bmp6;
    @ProtocolField(order = 8, size = 1) private int bmp7;
    @ProtocolField(order = 9, size = 1) private int bmp8;
    @ProtocolField(order = 10, size = 1) private int bmp9;
    @ProtocolField(order = 11, size = 1) private int bmp10;
    @ProtocolField(order = 12, size = 1) private int bmp11;
    @ProtocolField(order = 13, size = 1) private int bmp12;
    @ProtocolField(order = 14, size = 1) private int bmp13;
    @ProtocolField(order = 15, size = 1) private int bmp14;
    @ProtocolField(order = 16, size = 1) private int bmp15;
    @ProtocolField(order = 17, size = 1) private int bmp16;
    @ProtocolField(order = 18, size = 1) private int bmp17;
    @ProtocolField(order = 19, size = 1) private int bmp18;
    @ProtocolField(order = 20, size = 1) private int bmp19;
    @ProtocolField(order = 21, size = 1) private int bmp20;
    @ProtocolField(order = 22, size = 1) private int bmp21;
    @ProtocolField(order = 23, size = 1) private int bmp22;
    @ProtocolField(order = 24, size = 1) private int bmp23;
    @ProtocolField(order = 25, size = 1) private int bmp24;
    @ProtocolField(order = 26, size = 1) private int bmp25;
    @ProtocolField(order = 27, size = 1) private int bmp26;
    @ProtocolField(order = 28, size = 1) private int bmp27;
    @ProtocolField(order = 29, size = 1) private int bmp28;
    @ProtocolField(order = 30, size = 1) private int bmp29;
    @ProtocolField(order = 31, size = 1) private int bmp30;
    @ProtocolField(order = 32, size = 1) private int bmp31;
    @ProtocolField(order = 33, size = 1) private int bmp32;
    @ProtocolField(order = 34, size = 1) private int bmp33;
    @ProtocolField(order = 35, size = 1) private int bmp34;
    @ProtocolField(order = 36, size = 1) private int bmp35;
    @ProtocolField(order = 37, size = 1) private int bmp36;
    @ProtocolField(order = 38, size = 1) private int bmp37;
    @ProtocolField(order = 39, size = 1) private int bmp38;
    @ProtocolField(order = 40, size = 1) private int bmp39;
    @ProtocolField(order = 41, size = 1) private int bmp40;
    @ProtocolField(order = 42, size = 1) private int bmp41;
    @ProtocolField(order = 43, size = 1) private int bmp42;
    @ProtocolField(order = 44, size = 1) private int bmp43;
    @ProtocolField(order = 45, size = 1) private int bmp44;
    @ProtocolField(order = 46, size = 1) private int bmp45;
    @ProtocolField(order = 47, size = 1) private int bmp46;
    @ProtocolField(order = 48, size = 1) private int bmp47;
    @ProtocolField(order = 49, size = 1) private int bmp48;
    @ProtocolField(order = 50, size = 1) private int bmp49;
    @ProtocolField(order = 51, size = 1) private int bmp50;
    @ProtocolField(order = 52, size = 1) private int bmp51;
    @ProtocolField(order = 53, size = 1) private int bmp52;
    @ProtocolField(order = 54, size = 1) private int bmp53;
    @ProtocolField(order = 55, size = 1) private int bmp54;
    @ProtocolField(order = 56, size = 1) private int bmp55;
    @ProtocolField(order = 57, size = 1) private int bmp56;
    @ProtocolField(order = 58, size = 1) private int bmp57;
    @ProtocolField(order = 59, size = 1) private int bmp58;
    @ProtocolField(order = 60, size = 1) private int bmp59;
    @ProtocolField(order = 61, size = 1) private int bmp60;
    @ProtocolField(order = 62, size = 1) private int bmp61;
    @ProtocolField(order = 63, size = 1) private int bmp62;
    @ProtocolField(order = 64, size = 1) private int bmp63;
    @ProtocolField(order = 65, size = 1) private int bmp64;

    // ---- 条件字段(bit=1 才出现) ----

    /** F3 处理码,6B 数字。 */
    @ProtocolField(order = 66, type = FieldType.STRING, size = 48, presentIf = "bmp3 == 1")
    private String processingCode = "";

    /** F4 交易金额,12B 数字(分)。 */
    @ProtocolField(order = 67, type = FieldType.STRING, size = 96, presentIf = "bmp4 == 1")
    private String amount = "";

    /** F7 传输时间,10B MMDDhhmmss。 */
    @ProtocolField(order = 68, type = FieldType.STRING, size = 80, presentIf = "bmp7 == 1")
    private String transmission = "";

    /** F11 系统跟踪审计号,6B。 */
    @ProtocolField(order = 69, type = FieldType.STRING, size = 48, presentIf = "bmp11 == 1")
    private String stan = "";

    /** F41 终端标识,8B。 */
    @ProtocolField(order = 70, type = FieldType.STRING, size = 64, presentIf = "bmp41 == 1")
    private String terminalId = "";

    /** F42 商户标识,15B。 */
    @ProtocolField(order = 71, type = FieldType.STRING, size = 120, presentIf = "bmp42 == 1")
    private String merchantId = "";

    /** 组装便捷:置位并填值。 */
    public void setField3(String v) {
        this.bmp3 = 1;
        this.processingCode = v;
    }

    public void setField4(String v) {
        this.bmp4 = 1;
        this.amount = v;
    }

    public void setField11(String v) {
        this.bmp11 = 1;
        this.stan = v;
    }

    public void setField41(String v) {
        this.bmp41 = 1;
        this.terminalId = v;
    }

    public void setField42(String v) {
        this.bmp42 = 1;
        this.merchantId = v;
    }
}
