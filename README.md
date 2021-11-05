# proxy


## TODO:
1. int checkserver(char *hostname)

修改blocked_server设置方式

2. int checkclient(in_addr_t cli_ipaddr)

修改allowed_ip 设置方式

3. remote connect failed等返回客户端提示信息


## 测试：

1. 启动apache2:

`sudo /etc/init.d/apache2 start`

2. 配置代理:

```
export http_proxy='127.0.0.1:port'
export https_proxy='127.0.0.1:port'
```
   
3. 运行proxy

`proxy -p port`

此处的Port与配置代理中的Port一致   

4. 使用curl测试:

` curl ip:port`

此处的Port为apache运行的端口，默认为80

观察到proxy输出:
```asm
client port: xxxxx, client addr : xxxxx
server port: xxxxx, client addr : xxxxx
```

5. 为http连接指定用户名和密码

`curl -u 'username:password' ip:port`

在http报文中会出现Authorization域

6. 通过代理访问其他服务器:
```asm
curl -u 'bob:1234' -x 127.0.0.1:8080 www.baidu.com
```
-x 指定代理服务器地址，实际上就是防火墙所在的主机和端口