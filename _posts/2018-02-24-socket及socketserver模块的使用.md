---
layout:     post
title:      ������
subtitle:   socket��socketserverģ�����
date:       2018-2-24
author:     CRC
header-img: img/post-bg-universe.jpg
catalog: true
tags:
    - Python Socket
---

#1��socket����
#����
socketͨ��Ҳ����"�׽���"����һ�ּ�����������ݽṹ���൱��һ��ͨ�Ŷ˵㡣���κ����͵�ͨ�ſ�ʼ֮ǰ������Ӧ�ó�����봴���׽��֡����Խ����Ǳ����绰��ף�û�������޷�����ͨ�š�
���һ���׽�����һ���绰���--����ͨ�ŵ�һЩ������ʩ����ô�������Ͷ˿ںž��������ź͵绰�������ϡ�
```
Socket Families(��ַ��)

socket.AF_UNIX unix�������̼�ͨ�� 

socket.AF_INET��IPV4��

socket.AF_INET6  IPV6
```
```
Socket Types

socket.SOCK_STREAM  #for tcp

socket.SOCK_DGRAM   #for udp 

socket.SOCK_RAW     #ԭʼ�׽��֣���ͨ���׽����޷�����ICMP��IGMP�����籨�ģ���SOCK_RAW���ԣ���Σ�SOCK_RAWҲ���Դ��������IPv4���ģ����⣬����ԭʼ�׽��֣�����ͨ��IP_HDRINCL�׽���ѡ�����û�����IPͷ��

socket.SOCK_RDM  #��һ�ֿɿ���UDP��ʽ������֤�������ݱ�������֤˳��SOCK_RAM�����ṩ��ԭʼЭ��ĵͼ����ʣ�����Ҫִ��ĳЩ�������ʱʹ�ã��緢��ICMP���ġ�SOCK_RAMͨ�������ڸ߼��û������Ա���еĳ���ʹ�á�

socket.SOCK_SEQPACKET #������
```

#2��socket��������
socket.socket��socket_family, socket_type,protocol=0��
���У�socket_family��AF_UNIX��AF_INET����ǰ��������socket_type��SOCK_STREAM��SOCK_DGRAM(Ҳ��ǰ��������protocolͨ��ʡ�ԣ�Ĭ��Ϊ0��
���ԣ�Ϊ�˴���TCP/IP�׽��֣�����������ķ�ʽ����socket.socket()��
	tcpSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
ͬ����Ϊ�˴���UDP/IP�׽��֣���Ҫִ��������䡣
	udpSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

socket.socketpair([family[, type[, proto]]])

socket.create_connection(address[, timeout[, source_address]])

socket.getaddrinfo(host, port, family=0, type=0, proto=0, flags=0) #��ȡҪ���ӵĶԶ�������ַ �ػ�

sk.bind(adress)
��s.bind(address) ���׽��ְ󶨵���ַ��address��ַ�ĸ�ʽȡ���ڵ�ַ�塣��AF_INET�£���Ԫ�飨host,port������ʽ��ʾ��ַ��
sk.listen(backlog)
����ʼ�����������ӡ�backlogָ���ھܾ�����֮ǰ�����Թ�����������������

      backlog����5����ʾ�ں��Ѿ��ӵ����������󣬵���������û�е���accept���д�������Ӹ������Ϊ5
      ���ֵ�������޴���ΪҪ���ں���ά�����Ӷ���
sk.setlocking(bool)
���Ƿ�������Ĭ��True�����������False����ôaccept��recvʱһ�������ݣ��򱨴�
sk.accecp()
���������Ӳ����أ�conn,address��,����conn���µ��׽��ֶ��󣬿����������պͷ������ݡ�address�����ӿͻ��˵ĵ�ַ��

��������TCP �ͻ������ӣ�����ʽ���ȴ����ӵĵ���
sk.connect(address) �ػ�

�������ӵ�address�����׽��֡�һ�㣬address�ĸ�ʽΪԪ�飨hostname,port��,������ӳ�������socket.error����

sk.connect_ex(address)

����ͬ�ϣ�ֻ�������з���ֵ�����ӳɹ�ʱ���� 0 ������ʧ��ʱ�򷵻ر��룬���磺10061

sk.close() �ػ�

�����ر��׽���

sk.recv(bufsize[,flag]) �ػ�

���������׽��ֵ����ݡ��������ַ�����ʽ���أ�bufsizeָ�������Խ��յ�������flag�ṩ�й���Ϣ��������Ϣ��ͨ�����Ժ��ԡ�

sk.recvfrom(bufsize[.flag])

������recv()���ƣ�������ֵ�ǣ�data,address��������data�ǰ����������ݵ��ַ�����address�Ƿ������ݵ��׽��ֵ�ַ��

sk.send(string[,flag]) �ػ�

������string�е����ݷ��͵����ӵ��׽��֡�����ֵ��Ҫ���͵��ֽ�����������������С��string���ֽڴ�С����������δ��ָ������ȫ�����͡�

sk.sendall(string[,flag]) �ػ�

������string�е����ݷ��͵����ӵ��׽��֣����ڷ���֮ǰ�᳢�Է����������ݡ��ɹ�����None��ʧ�����׳��쳣��

      �ڲ�ͨ���ݹ����send�����������ݷ��ͳ�ȥ��

sk.sendto(string[,flag],address)

���������ݷ��͵��׽��֣�address����ʽΪ��ipaddr��port����Ԫ�飬ָ��Զ�̵�ַ������ֵ�Ƿ��͵��ֽ������ú�����Ҫ����UDPЭ�顣

sk.settimeout(timeout) �ػ�

���������׽��ֲ����ĳ�ʱ�ڣ�timeout��һ������������λ���롣ֵΪNone��ʾû�г�ʱ�ڡ�һ�㣬��ʱ��Ӧ���ڸմ����׽���ʱ���ã���Ϊ���ǿ����������ӵĲ������� client �������ȴ�5s ��

sk.getpeername()  �ػ�

�������������׽��ֵ�Զ�̵�ַ������ֵͨ����Ԫ�飨ipaddr,port����

sk.getsockname() 

���������׽����Լ��ĵ�ַ��ͨ����һ��Ԫ��(ipaddr,port)

sk.fileno() 

�����׽��ֵ��ļ�������

socket.sendfile(file, offset=0, count=None)

     �����ļ� ����Ŀǰ��������²���ʲô���á�
     
#3��socketʵ��
ǰ�潲����ô�࣬������ô���أ�
socketserver.py
```
import socket

server = socket.socket() #���socketʵ��

server.bind(("localhost",9998)) #��ip port
server.listen()  #��ʼ����
print("�ȴ��ͻ��˵�����...")
conn,addr = server.accept() #���ܲ�������ͻ��˵�����,�����ڴ˴���ʼ����,ֻ���пͻ������ӽ���...
print("������:",addr )

data = conn.recv(1024)
print("�յ���Ϣ:",data)


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
����Ĵ������һ�����⣬ ����SocketServer.py���������� ������һ�οͻ��˵�data���˳��ˡ������� ��ʵ�ʳ����У�һ�����ӽ��������󣬿���Ҫ���ж��������ͨ�š�
![]()
��ε����ݽ�����ôʵ�֣�
socketserver��֧�ֽ���
```
import socket

server = socket.socket() #���socketʵ��

server.bind(("localhost",9998)) #��ip port
server.listen()  #��ʼ����
print("�ȴ��ͻ��˵�����...")
conn,addr = server.accept() #���ܲ�������ͻ��˵�����,�����ڴ˴���ʼ����,ֻ���пͻ������ӽ���...
print("������:",addr )
while True:

    data = conn.recv(1024)

    print("�յ���Ϣ:",data)
    conn.send(data.upper())

server.close()

```
socketclient��֧�ֽ���
```
import socket

client = socket.socket()

client.connect(("localhost",9998))

while True:
    msg = input(">>:").strip()
    if len(msg) == 0:continue
    client.send( msg.encode("utf-8") )

    data = client.recv(1024)
    print("���Է�����:",data)

client.close()

```
ʵ���˶�ν����� �����ģ� ����ᷢ��һ��С���⣬ ���ǿͻ���һ�Ͽ����������˾ͽ�������ѭ����Ϊɶ�أ�

���ͻ��˶Ͽ�ʱ�������˵����
```
�ȴ��ͻ��˵�����...
������: ('127.0.0.1', 62722)
�յ���Ϣ: b'hey'
�յ���Ϣ: b'you'
�յ���Ϣ: b''  #�ͻ���һ�Ͽ����������˾��ղ��������ˣ����ǲ��ᱨ���ͽ�������ѭ��ģʽ������
�յ���Ϣ: b''
�յ���Ϣ: b''
�յ���Ϣ: b''
�յ���Ϣ: b''
```
֪����ԭ��ͺý���ˣ�ֻ��Ҫ�Ӹ��жϷ������ӵ��������Ƿ�Ϊ�վͺ��ˣ�Ϊ�վʹ�����ˡ�����
�����жϿͻ����Ƿ�Ͽ��Ĵ���
```
import socket

server = socket.socket() #���socketʵ��

server.bind(("localhost",9998)) #��ip port
server.listen()  #��ʼ����
print("�ȴ��ͻ��˵�����...")
conn,addr = server.accept() #���ܲ�������ͻ��˵�����,�����ڴ˴���ʼ����,ֻ���пͻ������ӽ���...
print("������:",addr )
while True:

    data = conn.recv(1024)
    if not data:
        print("�ͻ��˶Ͽ���...")
        break
    print("�յ���Ϣ:",data)
    conn.send(data.upper())

server.close()

```
#4��socketʵ�ֶ����Ӵ���
����Ĵ�����Ȼʵ���˷������ͻ��˵Ķ�ν�����������ᷢ�֣�����ͻ��˶Ͽ��ˣ� ��������Ҳ��������̶Ͽ�����Ϊ������ֻ��һ��while ѭ�����ͻ���һ�Ͽ���������ղ������� ���ͻ�ֱ��break����ѭ����Ȼ�������˳��ˣ�����Ȼ����������Ҫ�Ľ�� ��������Ҫ���ǣ��ͻ�������Ͽ��ˣ������������˻�����Ϊ��һ���ͻ��˷������������ʵ���أ�
- `conn,addr = server.accept()` ���ܲ�������ͻ��˵�����,�����ڴ˴���ʼ����,ֻ���пͻ������ӽ���...
����֪��������仰����ȴ������������ӣ����������Ǹ�������ʵ��while break֮��ֻҪ�ó����ٴλص������������⣬�Ϳ����÷���˼�������һ���ͻ����� 
```
import socket
 
server = socket.socket() #���socketʵ��
 
server.bind(("localhost",9998)) #��ip port
server.listen()  #��ʼ����
 
while True: #��һ��loop
    print("�ȴ��ͻ��˵�����...")
    conn,addr = server.accept() #���ܲ�������ͻ��˵�����,�����ڴ˴���ʼ����,ֻ���пͻ������ӽ���...
    print("������:",addr )
    while True:
 
        data = conn.recv(1024)
        if not data:
            print("�ͻ��˶Ͽ���...")
            break #����Ͽ��ͻ��ٴλص���һ������loop
        print("�յ���Ϣ:",data)
        conn.send(data.upper())
 
server.close()
```
#ͨ��socketʵ�ּ򵥵�ssh
��ֻ�Ǽ򵥵ķ���Ϣ������Ϣû��˼���ɵ����£�������һ��������ssh�����ǿͻ��������Ϸ��������÷�����ִ����������ؽ�����ͻ��ˡ�
socket ssh�����
```
#!/usr/bin/env python
# coding=utf-8
import socket
import os,subprocess
server = socket.socket()	#���socketʵ��
server.bind(("localhost",9998))	#��ip��port
server.listen()	#��ʼ����
while True:
    print("�ȴ������ӣ�")
    conn,addr = server.accept()	#���ܲ�������ͻ��˵�����,�����ڴ˴���ʼ����,ֻ���пͻ������ӽ���...
    print("new conn:",addr)
    while True:
        print("�ȴ���ָ��")
        data = conn.recv(1024)
        if not data:
            print("�ͻ��˶Ͽ���...")
            break
        print("ִ������:",data)
        cmd_res = os.popen(data.decode()).read()    #py3 ��socket���͵�ֻ��bytes,os.popen��ֻ�ܽ���str,����Ҫdecodeһ��
        #res = subprocess.Popen(data,shell=True,stdout=subprocess.PIPE).stdout.read() #���������������Ч����һ����
        print("before send",len(cmd_res))
        if len(cmd_res)==0:
            cmd_res = "cmd has no output..."
        conn.send(str(len(cmd_res.encode())).encode("utf-8"))   #��������֮ǰ,�ȸ��߿ͻ���Ҫ���������ݸ���
        ask_client = conn.recv(1024)
        print(ask_client)
        conn.send(cmd_res.encode("utf-8"))
        print("send done")
server.close

```
socket ssh�ͻ���
```
#!/usr/bin/env python
# coding=utf-8
import socket
client = socket.socket()
client.connect(("localhost",9998))
while True:
    cmd = input(">>:").strip()
    if len(cmd) == 0:
        continue
    client.send(cmd.encode("utf-8"))
    cmd_res_size = client.recv(1024)    #�����������ĳ���
    print("��������С:",cmd_res_size)
    to_server = client.send("everything is ok,starting send...".encode())
    received_size = 0	#�ѽ��յ�������
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
![]
###socketserverģ��
The socketserver module simplifies the task of writing network servers.
1��socketģ�鲻��ʵ�ֶಢ��    
2��socketserver�Ƕ�socket���ٷ�װ
����һ��socketserver�����¼�����
    First, you must create a request handler�������ࣩ class by subclassing the BaseRequestHandler class and overriding�����ǣ� its handle() method; this method will process incoming requests. ����
    ������Լ�����һ���������࣬���������Ҫ�̳�BaseRequestHandler,���һ�����д���������handle()�����ͻ������еĽ���������handle��������ɵġ�

    Second, you must instantiate��ʵ������ one of the server classes, passing it the server��s address and the request handler class.
    �����ʵ����TCPServer �����Ҵ���server ip �� �����洴������������ �����TCPServer

    Then call the handle_request() or serve_forever() method of the server object to process one or many requests.
    server.handle_request() #ֻ����һ������
    server.serve_forever() #������һ��������Զִ��

    Finally, call server_close() to close the socket.
socketserve�Ļ���ʹ��
Linux ����˴���
```

```
linux �ͻ��˴���
```
```
�������������ᷢ�֣���Ȼ����ʵ�ֶಢ������������server����һ�¸��ľͿ�����
��
- `server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)` �ĳ�
- `server = socketserver.ThreadingTCPServer((HOST, PORT), MyTCPHandler)`