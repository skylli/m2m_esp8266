# M2M for esp8266 
m2m 协议 esp8266 的实现。

# 描述
该 Wifi 模块的品类应该由内部 flash 字段标记。

# 设备id

    类型 + 厂家 + 品牌 + 品类 + 产品  + mac
    类型： 4 byete ： 0 为设备， 1 为APP端，2 为服务端
    厂家： 1 byete： 默认为 0
    品类： 1 byte 为led 灯饰类， 2 为智能家具类
    产品： 4 byte
    产品 mac：  6 byte 

# todo
1. 设备 id 应该是  wifi类型 + 品类标识 +  mac 地址， 其中 wifi 类型固定不变， 品类为 flash 中特定字段。
2. 短按 3s 重写 flash 配置数据 如品类，默认秘钥， 清楚 ssid 密码，并重启进入 smartconfig 模式， 再度短按时则直接 ap 模式，需要等待 ssid 和 秘钥包， 连接上路由后指示灯灭并根据不同的产品发送不同指令 提示 连接变化。
3. flash 还需要保存固件更新的 url，并根据接收到的指令触发更新。

