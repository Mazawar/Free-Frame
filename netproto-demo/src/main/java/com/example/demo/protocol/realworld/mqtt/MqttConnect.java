package com.example.demo.protocol.realworld.mqtt;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.nio.charset.StandardCharsets;

/**
 * MQTT CONNECT 报文(type=1):协议名 + 级别 + 标志位拆分 + keepAlive + clientId
 * + 按 connectFlags 位出现的可选 will/用户名/密码。
 * <p>
 * 验证点:connectFlags 单字节 1+1+2+1+1+1 位拆分,username/password/will 组
 * 用 presentIf 条件出现 —— 「标志位驱动条件字段」纯注解形态。
 */
@Data
@ToString
@Protocol(id = "mqtt-connect", name = "MQTT CONNECT", group = "MQTT")
@BindOn(parent = "mqtt", when = "type == 1")
public class MqttConnect {

    @ProtocolField(order = 1, size = 16)
    private int protoNameLen;

    @ProtocolField(order = 2, type = FieldType.STRING, lengthField = "protoNameLen")
    private String protoName = "MQTT";

    /** 协议级别 4 = 3.1.1。 */
    @ProtocolField(order = 3, size = 8)
    private int level = 4;

    // connectFlags: D7 username D6 password D5 will-retain D4-D3 will-QoS D2 will-flag D1 reserved D0 clean-session
    @ProtocolField(order = 4, size = 1)
    private int usernameFlag;

    @ProtocolField(order = 5, size = 1)
    private int passwordFlag;

    @ProtocolField(order = 6, size = 1)
    private int willRetain;

    @ProtocolField(order = 7, size = 2)
    private int willQos;

    @ProtocolField(order = 8, size = 1)
    private int willFlag;

    @ProtocolField(order = 9, size = 1)
    private int reserved;

    @ProtocolField(order = 10, size = 1)
    private int cleanSession;

    @ProtocolField(order = 11, size = 16)
    private int keepAlive = 60;

    @ProtocolField(order = 12, size = 16)
    private int clientIdLen;

    @ProtocolField(order = 13, type = FieldType.STRING, lengthField = "clientIdLen")
    private String clientId = "";

    /** will 主题(willFlag=1 才出现)。 */
    @ProtocolField(order = 14, size = 16, presentIf = "willFlag == 1")
    private int willTopicLen;

    @ProtocolField(order = 15, type = FieldType.STRING,
            lengthField = "willTopicLen", presentIf = "willFlag == 1")
    private String willTopic = "";

    /** will 消息。 */
    @ProtocolField(order = 16, size = 16, presentIf = "willFlag == 1")
    private int willMsgLen;

    @ProtocolField(order = 17, type = FieldType.BYTES,
            lengthField = "willMsgLen", presentIf = "willFlag == 1")
    private byte[] willMsg = new byte[0];

    /** 用户名。 */
    @ProtocolField(order = 18, size = 16, presentIf = "usernameFlag == 1")
    private int usernameLen;

    @ProtocolField(order = 19, type = FieldType.STRING,
            lengthField = "usernameLen", presentIf = "usernameFlag == 1")
    private String username = "";

    /** 密码。 */
    @ProtocolField(order = 20, size = 16, presentIf = "passwordFlag == 1")
    private int passwordLen;

    @ProtocolField(order = 21, type = FieldType.STRING,
            lengthField = "passwordLen", presentIf = "passwordFlag == 1")
    private String password = "";

    public static MqttConnect of(String clientId, String username, String password, boolean clean) {
        MqttConnect c = new MqttConnect();
        c.setProtoNameLen(4);
        c.setCleanSession(clean ? 1 : 0);
        c.setClientId(clientId);
        c.setClientIdLen(clientId.getBytes(StandardCharsets.UTF_8).length);
        if (username != null) {
            c.setUsernameFlag(1);
            c.setUsername(username);
            c.setUsernameLen(username.getBytes(StandardCharsets.UTF_8).length);
        }
        if (password != null) {
            c.setPasswordFlag(1);
            c.setPassword(password);
            c.setPasswordLen(password.getBytes(StandardCharsets.UTF_8).length);
        }
        return c;
    }
}
