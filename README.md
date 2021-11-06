# proxy

## 编译
```
mkdir rules
touch ip content hostname
make clean && make
```

## 配置规则
* Add target
* Modify target
* Delete target seq   
* List target
* Quit

target 包括 Content, Host, IP

seq 为 List中指定的序号

IP的输入规则:
`` ip username password``
若无需用户验证，则用None代替username和password

## 测试：

使用curl
```asm
curl -x serveraddr:port desthost    //通过serveraddr上的指定代理访问目标服务器
curl -u username:passwd -x serveraddr:port desthost  //使用Authorization用户验证
```

* List IP
![img.png](img/1.jpg)

* List Host
  ![img.png](img/2.jpg)
  
* List Content

  ![img.png](img/3.jpg)

* Delete Content

  ![img.png](img/4.jpg)

* Add IP
  ![img.png](img/5.jpg)

* Host

  ![img.png](img/7.jpg)
  
* Content

  ![img.png](img/9.jpg)
  
* 正常

  ![img.png](img/10.jpg)
  