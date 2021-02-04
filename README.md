# 内网扫描监测 v1 tcpdump版

### 环境准备

##### 1、centos7操作系统
##### 2、配置多个ip，两种用途：
>服务器添加多块网卡，可以同时监测多个网络
>单网卡配置多个ip，增加被黑客扫描的几率
>我这里配置了一块网卡 ens160，上面配置了四个IP地址 10.12.28.99、10.12.29.99、10.12.30.99、10.12.31.99

##### 3、加固sshd服务，防止服务器被黑客黑掉
>配置完监控后，直接关闭sshd服务。后续维护的时候，可以临时开启sshd服务，或者在服务器本地进行操作
>N种方法：禁用root登录、设置强密码、强制使用密钥登录、修改sshd监听端口号，限制访问IP等
>我这里使用的方法是：强制使用密钥登录+修改sshd监控端口为22774

##### 4、关闭防火墙运行黑客扫描本机的端口；关闭除sshd以外的其他所有可以监听tcp端口的服务，防止黑客扫描成功黑掉服务器；最后执行命令检查服务器对外监听的端口只有sshd，方便我们连上来进行管理
```bash
[root@net-monitor ~]# systemctl stop firewalld.service
[root@net-monitor ~]# systemctl disable firewalld.service
[root@net-monitor ~]# systemctl stop iptables.service
[root@net-monitor ~]# systemctl disable iptables.service
[root@net-monitor ~]# systemctl stop rpcbind.service
[root@net-monitor ~]# systemctl stop rpcbind.socket
[root@net-monitor ~]# systemctl disable rpcbind.socket
[root@net-monitor ~]# systemctl disable rpcbind.service
[root@net-monitor ~]# ss -tunl | grep '^tcp' | awk '{print$5}' | grep \* 
*:22774
```


### 操作步骤

##### 1、创建存放抓包文件的目录，这里在/tmp目录下创建一个专门的目录，系统会自动清理较早的文件

``` bash
[root@net-monitor ~]# mkdir -p /tmp/tcpdump
```
##### 2、设置开机自动抓包，tcpdump只抓到四个监控IP的tcp-syn包，每分钟在/tmp目录下保存一个文件

``` bash
[root@net-monitor ~]# echo 'nohup tcpdump -i any \(tcp[tcpflags] = tcp-syn\) and dst host \(10.12.28.99 or 10.12.29.99 or 10.12.30.99 or 10.12.31.99\) -s 0 -U -G 60  -w /tmp/tcpdump/%Y_%m%d_%H%M.cap &>/dev/null &' >> /etc/rc.local
```
##### 3、手工执行一下上面的命令，就不用重启系统了
```bash
[root@net-monitor ~]# nohup tcpdump -i any \(tcp[tcpflags] = tcp-syn\) and dst host \(10.12.28.99 or 10.12.29.99 or 10.12.30.99 or 10.12.31.99\) -s 0 -U -G 60  -w /tmp/tcpdump/%Y_%m%d_%H%M.cap &>/dev/null &
```


>在后台执行命令xxxx，即使退出登录也不会影响xxxx命令的运行，并且记录nohup日志
>nuhop xxxx &>/dev/null &

>在服务器的所有接口上抓包，不包括lo（127.0.0.1）接口
>-i any

>只抓tcp协议的syn包
>\(tcp[tcpflags] = tcp-syn\)

>抓取目标地址是本机四个IP地址的包
>dst host \(10.12.28.99 or 10.12.29.99 or 10.12.30.99 or 10.12.31.99\)

>抓取完成的数据包，默认只抓取68字节
>-s 0

>将抓到的包直接写入文件
>-U

>每60s生成一个文件，注意文件名要用变量，否则最多只能保存最近一分钟的数据包
>-G 60 

>设置保存抓包文件的位置，配合 -G命令，这里使用了时间变量：/tmp/tcpdump/2021_0201_1745.cap
>-w /tmp/tcpdump/%Y_%m%d_%H%M.cap

##### 4、为rc.local文件添加执行权限
``` bash
[root@net-monitor ~]# chmod +x /etc/rc.d/rc.local
```
##### 5、创建脚本目录，存放分析扫描的脚本文件
```bash
[root@net-monitor ~]# mkdir -p /opt/shells
```
##### 6、编辑脚本文件 /opt/shells/net-monitor.sh
```bash
#!/bin/bash

#  设置IP白名单，多个IP使用 | 隔开
WHITE_LIST='10.12.28.253|172.22.140.44'

#  设置报警阈值
WARN_NUM=4

#  计划任务每分钟自动读取两分钟前的那个抓包文件，分析异常IP，触发阈值自动邮件报警，并提供证据
/usr/sbin/tcpdump \
    -r /tmp/tcpdump/$(date -d '2 mins ago' "+%Y_%m%d_%H%M").cap \
    -nn \
    2>/dev/null \
        | grep -Ev "$WHITE_LIST" \
        | awk '{print $3}' \
        | awk -F \. '{print $1"."$2"."$3"."$4}' \
        | sort -n | uniq -c | sort -nr \
        | while read COUNT IP
          do
            if [ $COUNT -ge $WARN_NUM ] 
            then        
                /usr/sbin/tcpdump \
                    -r /tmp/tcpdump/$(date -d '2 mins ago' "+%Y_%m%d_%H%M").cap \
                    -nn \               
                    2>/dev/null \       
                        | grep $IP \            
                        | head -10 \            
                        | mail -r net-monitor@mail.com \
                               -s "异常IP: $IP 一分钟内扫描监控服务器 $COUNT 次" \
                               -a /tmp/tcpdump/$(date -d '2 mins ago' "+%Y_%m%d_%H%M").cap \
                               -c CC@mail.com \
                               network-manager@mail.com  
            else        
                exit            
            fi          
          done 
```
>因为 \ 后面加 #注释 会影响脚本运行，所以单独写了一份注释版的
```bash
#!/bin/bash

#  设置IP白名单，多个IP使用 | 隔开
WHITE_LIST='10.12.28.253|172.22.140.44'

#  设置报警阈值
WARN_NUM=4

#  计划任务每分钟自动读取两分钟前的那个抓包文件，分析异常IP，触发阈值自动邮件报警，并提供证据

/usr/sbin/tcpdump \                               # tcpdump命令的绝对位置，使用相对路径计划任务会找不到该命令
    -r /tmp/tcpdump/$(date -d '2 mins ago' "+%Y_%m%d_%H%M").cap \ # 分析两分钟前的那个抓包文件，上一分钟的不行，原因留个悬念
    -nn \                                               # 直接显示IP和端口号
    2>/dev/null \                                    # 不打印错误信息
        | grep -Ev "$WHITE_LIST" \               # 过滤白名单中的IP
        | awk '{print $3}' \                          # 取源IP
        | awk -F \. '{print $1"."$2"."$3"."$4}' \ # 去掉源端口，方便后面去重统计次数
        | sort -n | uniq -c | sort -nr \            # IP去重后，按出现次数降序排列，第一列是出现次数，第二列是IP地址
        | while read COUNT IP                    # while循环读取每个IP及出现次数
          do
            if [ $COUNT -ge $WARN_NUM ]   # 如果IP出现次数大于等于报警阈值，进行邮件报警
            then        
                /usr/sbin/tcpdump \               # 重新分析两分钟前的那个抓包文件
                    -r /tmp/tcpdump/$(date -d '2 mins ago' "+%Y_%m%d_%H%M").cap \
                    -nn \               
                    2>/dev/null \       
                        | grep $IP \                                                                                      # 只看该异常IP的信息
                        | head -10 \                                                                                     # 节选前10行证据，放到邮件正文
                        | mail -r net-monitor@mail.com \                                                         # 设置邮件的发件人
                               -s "异常IP: $IP 一分钟内扫描监控服务器 $COUNT 次" \                          # 设置邮件主题
                               -a /tmp/tcpdump/$(date -d '2 mins ago' "+%Y_%m%d_%H%M").cap \  # 将本次分析的抓包文件，作为完成的证据添加到邮件的附件中
                               -c CC@mail.com \                                                                     # 设置抄送邮箱
                               network-manager@mail.com                                                       # 设置主送邮箱
            else        
                exit                                     # 如果IP出现的次数小于报警阈值，直接退出脚本，不在对后面出现次数更少的IP进行处理
            fi          
          done 
```
##### 7、添加计划任务，每分钟执行一次脚本
```bash
[root@net-monitor ~]# crontab -e
* * * * * sh /opt/shells/net-monitor.sh
```
##### 8、完成后的效果，如图
![568e23104a58dae171e2907f8bc0c968.png](en-resource://database/8344:1)

##### 9、附1：实时抓包命令
```bash
[root@net-monitor ~]# tcpdump -i any \(tcp[tcpflags] = tcp-syn\) and dst host \(10.12.28.99 or 10.12.29.99 or 10.12.30.99 or 10.12.31.99\) -nn
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
23:29:39.150287 IP 10.12.28.8.46905 > 10.12.28.99.22: Flags [S], seq 1789993435, win 14600, options [mss 1460,sackOK,TS val 4251068229 ecr 0,nop,wscale 7], length 0
```
##### 10、附2：手工分析历史抓包文件
```bash
[root@net-monitor ~]# for i in `ls /tmp/tcpdump/*.cap` ; do echo "------ $i -----" ; tcpdump -r $i -nn 2>/dev/null| awk '{print $3}' | awk -F . '{print $1"."$2"."$3"."$4}' | sort -n | uniq -c | sort -n ; done
------ /tmp/tcpdump/2021_0201_2212.cap -----
------ /tmp/tcpdump/2021_0201_2218.cap -----
      1 10.12.28.253
------ /tmp/tcpdump/2021_0201_2219.cap -----
      1 10.12.28.253
------ /tmp/tcpdump/2021_0201_2220.cap -----
      1 10.12.28.253
------ /tmp/tcpdump/2021_0201_2241.cap -----
     19 10.12.28.8
------ /tmp/tcpdump/2021_0201_2329.cap -----
      1 10.12.28.8
```
##### 11、附3：[tcpdump官方手册](http://www.tcpdump.org/manpages/tcpdump.1.html)
