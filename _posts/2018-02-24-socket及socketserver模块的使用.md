---
layout:     post
title:      python---网络编程
subtitle:   socket和socketserver模块介绍
date:       2018-2-24
author:     CRC
header-img: img/post-bg-universe.jpg
catalog: true
tags:
    - Python Socket
---

# 1、socket介绍
## 概念
  socket通常也称作"套接字"，是一种计算机网络数据结构，相当于一个通信端点。在任何类型的通信开始之前，网络应用程序必须创建套接字。可以将它们比作电话插孔，没有它将无法进行通信。
  如果一个套接字像一个电话插孔--允许通信的一些基础设施，那么主机名和端口号就像是区号和电话号码的组合。
## Socket Families(地址簇)

socket.AF_UNIX | unix  本机进程间通信 
---------------|--------------------
socket.AF_INET　| IPV4
socket.AF_INET6 | IPV6

## Socket Types
socket.SOCK_STREAM | for tcp
-------------------|----------------
socket.SOCK_DGRAM  | for udp 
socket.SOCK_RAW   | 原始套接字，普通的套接字无法处理ICMP、IGMP等网络报文，而SOCK_RAW可以；其次，SOCK_RAW也可以处理特殊的IPv4报文；此外，利用原始套接字，可以通过IP_HDRINCL套接字选项由用户构造IP头。
socket.SOCK_RDM  | 是一种可靠的UDP形式，即保证交付数据报但不保证顺序。SOCK_RAM用来提供对原始协议的低级访问，在需要执行某些特殊操作时使用，如发送ICMP报文。SOCK_RAM通常仅限于高级用户或管理员运行的程序使用。
socket.SOCK_SEQPACKET | 废弃了

# 2、socket参数介绍
* socket.socket（socket_family, socket_type,protocol=0
    > 其中，socket_family是AF_UNIX或AF_INET（如前所述），socket_type是SOCK_STREAM或SOCK_DGRAM(也如前所述）。protocol通常省略，默认为0。
    > 所以，为了创建TCP/IP套接字，可以用下面的方式调用socket.socket()。
    > tcpSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    > 同样，为了创建UDP/IP套接字，需要执行以下语句。
    > udpSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

* socket.socketpair([family[, type[, proto]]])
* socket.create_connection(address[, timeout[, source_address]])
* socket.getaddrinfo(host, port, family=0, type=0, proto=0, flags=0)
     > 获取要连接的对端主机地址 必会
* s.bind(address)
    > 将套接字绑定到地址。address地址的格式取决于地址族。在AF_INET下，以元组（host,port）的形式表示地址。
* sk.listen(backlog)`
    > 开始监听传入连接。backlog指定在拒绝连接之前，可以挂起的最大连接数量。
    > backlog等于5，表示内核已经接到了连接请求，但服务器还没有调用accept进行处理的连接个数最大为5
    > 这个值不能无限大，因为要在内核中维护连接队列
* sk.setlocking(bool)
    > 是否阻塞（默认True），如果设置False，那么accept和recv时一旦无数据，则报错。
* sk.accecp()
    > 接受连接并返回（conn,address）,其中conn是新的套接字对象，可以用来接收和发送数据。address是连接客户端的地址。
    > 接收TCP 客户的连接（阻塞式）等待连接的到来
* sk.connect(address) 必会
    > 连接到address处的套接字。一般，address的格式为元组（hostname,port）,如果连接出错，返回socket.error错误。
* sk.connect_ex(address)
    > 同上，只不过会有返回值，连接成功时返回 0 ，连接失败时候返回编码，例如：10061
* sk.close() 必会
    > 关闭套接字
* sk.recv(bufsize[,flag]) 必会
    > 接受套接字的数据。数据以字符串形式返回，bufsize指定最多可以接收的数量。flag提供有关消息的其他信息，通常可以忽略。
* sk.recvfrom(bufsize[.flag])
    > 与recv()类似，但返回值是（data,address）。其中data是包含接收数据的字符串，address是发送数据的套接字地址。
* sk.send(string[,flag]) 必会
    > 将string中的数据发送到连接的套接字。返回值是要发送的字节数量，该数量可能小于string的字节大小。即：可能未将指定内容全部发送。
* sk.sendall(string[,flag]) 必会
    > 将string中的数据发送到连接的套接字，但在返回之前会尝试发送所有数据。成功返回None，失败则抛出异常。内部通过递归调用send，将所有内容发送出去。
* sk.sendto(string[,flag],address)
    > 将数据发送到套接字，address是形式为（ipaddr，port）的元组，指定远程地址。返回值是发送的字节数。该函数主要用于UDP协议。
* sk.settimeout(timeout) 必会
    > 设置套接字操作的超时期，timeout是一个浮点数，单位是秒。值为None表示没有超时期。一般，超时期应该在刚创建套接字时设置，因为它们可能用于连接（如 client 连接最多等待5s ）
* sk.getpeername()  必会
    > 返回连接套接字的远程地址。返回值通常是元组（ipaddr,port）。
* sk.getsockname() 
    > 返回套接字自己的地址。通常是一个元组(ipaddr,port)
* sk.fileno()
    > 套接字的文件描述符
* socket.sendfile(file, offset=0, count=None)
    > 发送文件 ，但目前多数情况下并无什么卵用。
---------------------------------------------------------------------------------------------------------------------------------------
    
# 3、socket实例
  前面讲了那么多，到底怎么用呢？
  
socketserver.py
```
import socket

server = socket.socket() #获得socket实例

server.bind(("localhost",9998)) #绑定ip port
server.listen()  #开始监听
print("等待客户端的连接...")
conn,addr = server.accept() #接受并建立与客户端的连接,程序在此处开始阻塞,只到有客户端连接进来...
print("新连接:",addr )

data = conn.recv(1024)
print("收到消息:",data)


server.close()

```
socketclient.py
```
import socket

client = socket.socket()

client.connect(("localhost",9998))

client.send(b"hey")

client.close()

SocketClient.py
```
上面的代码的有一个问题， 就是SocketServer.py运行起来后， 接收了一次客户端的data就退出了。。。， 但实际场景中，一个连接建立起来后，可能要进行多次往返的通信。
![](https://github.com/erstarry/erstarry.github.io/blob/master/img/socket%E9%80%9A%E4%BF%A1.png)

多次的数据交互怎么实现？

socketserver端支持交互
```
import socket

server = socket.socket() #获得socket实例

server.bind(("localhost",9998)) #绑定ip port
server.listen()  #开始监听
print("等待客户端的连接...")
conn,addr = server.accept() #接受并建立与客户端的连接,程序在此处开始阻塞,只到有客户端连接进来...
print("新连接:",addr )
while True:

    data = conn.recv(1024)

    print("收到消息:",data)
    conn.send(data.upper())

server.close()

```
socketclient端支持交互
```
import socket

client = socket.socket()

client.connect(("localhost",9998))

while True:
    msg = input(">>:").strip()
    if len(msg) == 0:continue
    client.send( msg.encode("utf-8") )

    data = client.recv(1024)
    print("来自服务器:",data)

client.close()

```
实现了多次交互， 棒棒的， 但你会发现一个小问题， 就是客户端一断开，服务器端就进入了死循环，为啥呢？

看客户端断开时服务器端的输出
```
等待客户端的连接...
新连接: ('127.0.0.1', 62722)
收到消息: b'hey'
收到消息: b'you'
收到消息: b''  #客户端一断开，服务器端就收不到数据了，但是不会报错，就进入了死循环模式。。。
收到消息: b''
收到消息: b''
收到消息: b''
收到消息: b''
```
知道了原因就好解决了，只需要加个判断服务器接到的数据是否为空就好了，为空就代表断了。。。
加了判断客户端是否断开的代码
```
import socket

server = socket.socket() #获得socket实例

server.bind(("localhost",9998)) #绑定ip port
server.listen()  #开始监听
print("等待客户端的连接...")
conn,addr = server.accept() #接受并建立与客户端的连接,程序在此处开始阻塞,只到有客户端连接进来...
print("新连接:",addr )
while True:

    data = conn.recv(1024)
    if not data:
        print("客户端断开了...")
        break
    print("收到消息:",data)
    conn.send(data.upper())

server.close()

```
# 4、socket实现多连接处理
  上面的代码虽然实现了服务端与客户端的多次交互，但是你会发现，如果客户端断开了， 服务器端也会跟着立刻断开，因为服务器只有一个while 循环，客户端一断开，服务端收不到数据 ，就会直接break跳出循环，然后程序就退出了，这显然不是我们想要的结果 ，我们想要的是，客户端如果断开了，我们这个服务端还可以为下一个客户端服务，在这里如何实现呢？
  
* conn,addr = server.accept() #接受并建立与客户端的连接,程序在此处开始阻塞,只到有客户端连接进来...
    > 我们知道上面这句话负责等待并接收新连接，对于上面那个程序，其实在while break之后，只要让程序再次回到上面这句代码这，就可以让服务端继续接下一个客户啦。 
```
import socket
 
server = socket.socket() #获得socket实例
 
server.bind(("localhost",9998)) #绑定ip port
server.listen()  #开始监听
 
while True: #第一层loop
    print("等待客户端的连接...")
    conn,addr = server.accept() #接受并建立与客户端的连接,程序在此处开始阻塞,只到有客户端连接进来...
    print("新连接:",addr )
    while True:
 
        data = conn.recv(1024)
        if not data:
            print("客户端断开了...")
            break #这里断开就会再次回到第一次外层的loop
        print("收到消息:",data)
        conn.send(data.upper())
 
server.close()
```
# 5、通过socket实现简单的ssh
  光只是简单的发消息、收消息没意思，干点正事，可以做一个极简版的ssh，就是客户端连接上服务器后，让服务器执行命令，并返回结果给客户端。
socket ssh服务端
```
import socket
import os,subprocess
server = socket.socket()	#获得socket实例
server.bind(("localhost",9998))	#绑定ip，port
server.listen()	#开始监听
while True:
    print("等待新连接：")
    conn,addr = server.accept()	#接受并建立与客户端的连接,程序在此处开始阻塞,只到有客户端连接进来...
    print("new conn:",addr)
    while True:
        print("等待新指令")
        data = conn.recv(1024)
        if not data:
            print("客户端断开了...")
            break
        print("执行命令:",data)
        cmd_res = os.popen(data.decode()).read()    #py3 里socket发送的只有bytes,os.popen又只能接受str,所以要decode一下
        #res = subprocess.Popen(data,shell=True,stdout=subprocess.PIPE).stdout.read() #跟上面那条命令的效果是一样的
        print("before send",len(cmd_res))
        if len(cmd_res)==0:
            cmd_res = "cmd has no output..."
        conn.send(str(len(cmd_res.encode())).encode("utf-8"))   #发送数据之前,先告诉客户端要发多少数据给它
        ask_client = conn.recv(1024)
        print(ask_client)
        conn.send(cmd_res.encode("utf-8"))
        print("send done")
server.close

```
socket ssh客户端
```
import socket
client = socket.socket()
client.connect(("localhost",9998))
while True:
    cmd = input(">>:").strip()
    if len(cmd) == 0:
        continue
    client.send(cmd.encode("utf-8"))
    cmd_res_size = client.recv(1024)    #接受命令结果的长度
    print("命令结果大小:",cmd_res_size)
    to_server = client.send("everything is ok,starting send...".encode())
    received_size = 0	#已接收到的数据
    received_data = b''
    
    while received_size < int(cmd_res_size.decode()):
        data = client.recv(1024)
        received_size += len(data)
        received_data += data
    else:
        print("cmd res receive done...",received_size)
        print(received_data.decode())
client.close()
```
![https://github.com/erstarry/erstarry.github.io/blob/master/img/socket%20ssh.png]

# 6、socketserver模块
  The socketserver module simplifies the task of writing network servers.
1. socket模块不能实现多并发    
2. socketserver是对socket的再封装
创建一个socketserver分以下几步：
    First, you must create a request handler（处理类） class by subclassing the BaseRequestHandler class and overriding（覆盖） its handle() method; this method will process incoming requests. 　　
    你必须自己创建一个请求处理类，并且这个类要继承BaseRequestHandler,并且还有重写父亲类里的handle()【跟客户端所有的交互都是在handle（）里完成的】

    Second, you must instantiate（实例化） one of the server classes, passing it the server’s address and the request handler class.
    你必须实例化TCPServer ，并且传递server ip 和 你上面创建的请求处理类 给这个TCPServer

    Then call the handle_request() or serve_forever() method of the server object to process one or many requests.
    server.handle_request() #只处理一个请求
    server.serve_forever() #处理多个一个请求，永远执行

    Finally, call server_close() to close the socket.
socketserve的基本使用

Linux 服务端代码
```
#!/usr/bin/env python
# coding=utf-8
import socketserver
class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            self.data = self.request.recv(1024).strip()
            print("{} wrote".format(self.client_address[0]))
            print(self.data)
            if not self.data:   #客户端断开了
                print(self.client_address,"断开了")
                break
            self.request.send(self.data.upper())
if __name__ == "__main__":
    HOST,PORT = "0.0.0.0",9999
    server = socketserver.TCPServer((HOST,PORT),MyTCPHandler)
    server.serve_forever()
    
    server_close()

```
linux 客户端代码
```
#!/usr/bin/env python
# coding=utf-8
import socket
client = socket.socket()
client.connect(('192.168.213.144',9999))
while True:
    msg = input(">>:").strip()
    if len(msg) == 0:continue
    client.send(msg.encode("utf-8"))
    data = client.recv(1024)
    print("recv:",data.decode())
client.close()

```
上面这个例子你会发现，依然不能实现多并发，哈哈，在server端做一下更改就可以了
把
`server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)` 改成
`server = socketserver.ThreadingTCPServer((HOST, PORT), MyTCPHandler)`
