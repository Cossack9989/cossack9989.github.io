---
layout: post
title:  "A glance at Hikvision ISUP SDK"
date:   2021-11-11 12:00:00 +0800
categories: vuln
---

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/Hikvision-Logo-scaled.jpeg)

好久不更新博客，恰好最近拿到一批编号`CNNVD-202111-636/637/638/639`，`CVE-2021-42260`，寻思着不如来分享一下这次审计2b sdk的经历

ISUP SDK对各位来说可能比较陌生，这是一款海康威视发布的to B的SDK，主要用于内网综合安防平台的搭建，集成了EAlarm（设备报警管理）、ESS（数据存储）、ECMS（平台管理）、EStream（因为业务并未涉及，所以这个服务咕了Orz）四个服务

## Structure of ISUP SDK Package

```
.
├── doc
│   ├── ISUPSDK（通用）_开发指南.PDF
│   ├── Open Source Software Licenses-HCEHome.txt
│   └── Open Source Software Licenses_playctrl_linux.txt
├── incCn
│   ├── AudioIntercom.h
│   ├── HCISUPAlarm.h
│   ├── HCISUPCMS.h
│   ├── HCISUPIPS.h
│   ├── HCISUPPublic.h
│   ├── HCISUPSS.h
│   ├── HCISUPStream.h
│   └── plaympeg4.h
└── lib
    ├── HCAapSDKCom
    │   ├── libSystemTransform.so
    │   └── libiconv2.so
    ├── libHCISUPAlarm.so
    ├── libHCISUPCMS.so
    ├── libHCISUPSS.so
    ├── libHCISUPStream.so
    ├── libHCNetUtils.so
    ├── libNPQos.so
    ├── libcrypto.so
    ├── libcrypto.so.1.0.0
    ├── libhpr.so
    ├── libsqlite3.so
    ├── libssl.so
    ├── libssl.so.1.0.0
    └── libz.so
```

## Preliminary analysis

根据开发指南，可以快速定位到，核心功能的实现集中在

- libHCISUPAlarm.so 实现设备异常报警相关API
- libHCISUPCMS.so 实现设备管理平台相关API
- libHCISUPSS.so 实现设备文件传输服务相关API
- libHCISUPStream.so 没看

发现报文类似SOAP，是类HTTP+XML，例子如下
![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/hikvision-isup-sdk-structure.png)
根据上述信息，可以确定多个漏洞挖掘方向：

- SDK的报文解析
- 自研实现(比如Headers字段)
- 外部依赖实现(比如XML)
- ISUP协议状态机
- … …

## Hunting by 头铁逆向

头铁逆向就完事儿了

通过Headers关键字来确定报文解系的代码定位，先后定位了`<Version/>`字段解析、`Content-Length`字段解析、`filename=`字段解析等4处漏洞。

### NET_EHOME_ALARM_LISTEN_PARAM Stack-Overflow

**威胁程度**：高危，若EAlarm服务设置byProtocolType为TCP，则攻击者可发送恶意payload导致EAlarm异常crash甚至RCE

**调用链**

`vtable for NETEHome::CAlarmListenTCP` 

=> `CAlarmListenTCP::ProcessRecvData` 

=> `CAlarmListenTCP::ProcessAlarmData` 

=> `CAlarmListenTCP::PushAlarmDataToCache` 

=> `CAlarmListenTCP::PushHTTPAlarmDataToCache`

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ealarm1.png)

=> `CAlarmListenTCP::ProcessHttpHeadData`

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ealarm2.png)

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ealarm3.png)

通过定位`Content-Length:`与`\r\n`前后缀，取出`Content-Length`字段并填入栈上大小为0x20的缓冲区中，极易造成栈上数据污染导致的crash；该缓冲区距离返回地址仅0x40，精心构造的`Content-Length`字段可覆盖返回地址从而进行ROP来RCE

### NET_StartListenProxy Stack-Overflow

**威胁程度**：高危，若ECMS服务开启http proxy，则攻击者可发送恶意payload导致ECMS异常crash甚至RCE

**调用链**

`NET_ECMS_StartListenProxy` 

=> `CHTTPProxyMgr::StartListen` 

=> `libHCISUPCMS.so + 0x43AB0 (TRANSHTTPCONFIG)` 

=> `CHTTPProxyMgr::ProcessDataCB` 

=> `libHCISUPCMS.so + 0x43742` 

=> `CHTTPProxyMgr::FindHTTPTotalLen`

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ecms1.png)

=> `CHTTPProxyMgr::GetHeaderValueInt`

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ecms2.png)

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ecms3.png)

通过定位`Content-Length:`与`\r\n`前后缀，取出`Content-Length`字段并填入栈上大小为0x48的缓冲区中，极易造成栈上数据污染导致的crash；该缓冲区距离返回地址仅0x60，精心构造的`Content-Length`字段可覆盖返回地址从而进行ROP来RCE

## NET_StartListen Stack-Overflow

**威胁程度**：严重，攻击者可发送恶意payload导致ECMS异常crash甚至RCE

**调用链**

`NET_ECMS_StartListen` 

=> `CListenServer::StartServer` 

=> `libHCISUPCMS.so + 0x52F86` 

=> `CListenServer::ProcessCallBackData` 

=> `Utils_ParseHCEHomeHead`

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ecms4.png)

=> `ConvertStringToVersion`

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ecms4.png)

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ecms6.png)

通过定位`<Version>`与`</Version>`前后缀，取出`Version`字段并填入栈上大小为0x20的缓冲区中，极易造成栈上数据污染导致的crash；该缓冲区距离返回地址仅0x60，精心构造的`Version`字段可覆盖返回地址从而进行ROP来RCE

## NET_EHOME_SERVER_INFO Stack-Overflow

**威胁程度**：中危，若ESS服务设置dwPicServerType为VRB，则攻击者可发送恶意payload导致ESS异常crash

**调用链**

`vtable for NETEHome::CProtocolProcVRB` 

=> `CProtocolProcVRB::Proc`

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ess1.png)

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ess2.png)

=> `CBusinessProc::SaveFile`

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ess3.png)

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/ess4.png)

将长度上限为0x1ff的`filename`拷贝入长度0x100的栈上缓冲区，将会导致一系列对象与成员指针被覆盖，从而诱发非法地址访问。该漏洞并不排除构造恶意对象导致RCE的情况。



## Hunting by AFL

逆向之后通过github搜索error log字符串发现用到了TinyXML（注意并不是TinyXML2，是十年前就再也不更新的TinyXML），同时还惊喜地发现SDK将TinyXML静态编译进去的时候，没关DEBUG，导致`__alert_fail`极易导致服务crash。这里我们先假定在关闭DEBUG的情况下做fuzz

随后搓harness——

```
#include "tinyxml.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>


int main(int argc, char*argv[]){

    if(argc < 2){
        printf("args error\n");
        return 0;
    }

    int fd = open(argv[1], O_RDWR | O_APPEND);
    if(!fd){
        printf("open failed\n");
        return -1;
    }

    int bytes = 1024 * 1024;
    char *buffer = (char*)malloc(bytes);

    int n = read(fd, buffer, bytes-1);
    printf("read %d bytes\n", n);


    TiXmlDocument doc;
    doc.Parse(buffer);


    close(fd);
    free(buffer);
    return 0;
}
```

afl-fuzz, run!

![](https://raw.githubusercontent.com/Cossack9989/cossack9989.github.io/main/_images/tinyxml_loop.png)

然后就跑项目主页报漏洞了 https://sourceforge.net/p/tinyxml/bugs/141/

## Attacking Model

这个攻击建模还是相对简单的。

- 控制大型企业/工厂的内网的某一台安防设备（比如物理入侵门禁机/摄像头/传感器）
- 劫持当前Victim的流量，篡改其对综合安防平台的响应报文
- 入侵综合安防平台，下发恶意指令，群控安防设备

## The end

等以后有空了再挖一挖状态机的漏洞