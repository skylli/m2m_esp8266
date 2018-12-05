#  Firmware 要求

    - wifi 模式有四种： sta 会获取 smt 保存的 ssid 链接路由， sta_smt  wifi工作在 sta 模式下，且上电进入 smartconfig 模式， ap  wifi 工作于ap 模式下， sta_pw wifi工作于 sta 模式并使用 ap 设置 ssid 链接路由。
    - 上电时， 从 flash 中读取加密的秘钥，服务器host的 ip 和 port， 以及wifi的模式( sta 或者 ap)。
    - 指示灯应该指示四种种状态， 断网，联网中， 连接上路由但是没有连接上服务器， 连接上服务器。
    - 长按进入恢复出厂， flash 中的加密秘钥， host 的 ip 和 port 均被重置， wifi 模式设置为  sta_smt。
    - 在 sta_smt 模式下长按时 进入 ap 模式，  客户端只需要发送一条指令无论wifi是 ap 和sta 模式下设置 ssid 和 password 重置路由配置并重启wifi。
    
