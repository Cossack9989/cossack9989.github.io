---
layout: post
title:  "Research on SIP (record 1)"
date:   2022-04-25 0:00:00 +0800
categories: vuln
---

前段时间逆Linkus和VOS很自闭，所以来找找开源的茬。fuzz了一些SIP开源协议栈，收割了七个漏洞，涂作消遣，把自认为稍有些价值的洞po出来mark下

## PJSIP

### [Inf-Loop @ PJXML](https://github.com/pjsip/pjproject/security/advisories/GHSA-5x45-qp78-g4p4)

- 编号
  - GHSA-5x45-qp78-g4p4
  - CVE-2022-24763
- 攻击面：PJSIP协议栈中所有基于XML的交互，例如
  - 基于SIP的[`isComposing`/`isTyping`](https://datatracker.ietf.org/doc/html/draft-schulzrinne-simple-iscomposing-00)短信报文
  - 基于SIP的[`PIDF`/`XPIDF`](https://datatracker.ietf.org/doc/html/rfc5263)订阅报文
- 漏洞成因：解析`<![CDATA[???]]>`时，当XML无`]]>`，scan loop中扫描位置无移动

### [Heap-Bof @ PJDNS](https://github.com/pjsip/pjproject/security/advisories/GHSA-p6g5-v97c-w5q4)

- 编号
  - GHSA-p6g5-v97c-w5q4
  - CVE-2022-24793
- 攻击面：SIP URL包含域名时，通过PJDNS解析域名，此时可借鉴DNS投毒的攻击手法，向PJDNS发包，触发漏洞
- 漏洞成因：DNS Packet缺少对Packet End的检查，导致堆溢出
- 备注：完整利用应该需要堆风水，复测过程中发现case触发crash概率大概在1/8

## Sofia-SIP

### [OOB @ SofiaSDP](https://github.com/freeswitch/sofia-sip/security/advisories/GHSA-8w5j-6g2j-pxcp)

- 编号
  - GHSA-8w5j-6g2j-pxcp
- 攻击面：SIP携带恶意构造的SDP报文，即可触发（离谱）
- 漏洞成因：解析SDP Key后未检查剩余字符串长度，导致解析SDP Value越界

## Plan in weeks

- SIP中各类Session的实现
- Qualcomm SIP（感谢字节钞能力！）

