# HisSword
内网渗透工具、支持sock等代理模式和端口转发模式

client:
    客户端支持直连和反向链接

    HisSword -a 127.0.0.1 -p 8888 -r=1

server:
    服务端支持直连和反向链接，支持端口转发和流量代理
    
    HisServer -a 127.0.0.1 -p 1080 -A 127.0.0.1 -P 8888 -r=1 -proxy=1


