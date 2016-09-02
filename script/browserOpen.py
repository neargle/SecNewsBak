# -*- coding: utf-8 -*-
# @Author: Nearg1e -- 2016-09-02 09:09:18 --0v0--

import webbrowser
from urllib import quote

base_search_url = 'https://www.google.com.hk/search?newwindow=1&safe=strict&q=site%3Aju.outofmemory.cn+{text}&oq=site%3Aju.outofmemory.cn+{text}&gs_l=serp.3...39571821.39572425.0.39572572.2.2.0.0.0.0.0.0..0.0....0...1c.4.64.serp..2.0.0.0XJKkDVdkw4'

search_text = [
"攻击洋葱路由(Tor)匿名服务的一些综述",
"Hacking ipcam like Harold in POI",
"比葫芦娃还可怕的百度全系APP SDK漏洞 - WormHole虫洞漏洞分析报告",
"WMI Attacks",
"攻击洋葱路由(Tor)匿名服务的一些综述",
"SQL注入速查表（上）.html",
"Hacking ipcam like Harold in POI",
"海豚浏览器与水星浏览器远程代码执行漏洞详解",
"WMI Backdoor",
"比葫芦娃还可怕的百度全系APP SDK漏洞 - WormHole虫洞漏洞分析报告",
"那些年做过的ctf之加密篇",
"从一个锁主页木马里挖出的惊天“暗杀黑名单”",
"C&C控制服务的设计和侦测方法综述",
"Python安全编码指南",
"翻墙路由器的原理与实现",
"Ruby on Rails 动态渲染远程代码执行漏洞 (CVE-2016-0752)(翻译)",
"Do Evil Things with gopher://",
"Struts2 S033与最新S037详细分析",
"SQL注入关联分析",
"玩转Metasploit之Automated Persistent Backdoor",
"Uber渗透案例：我们是如何发现你是谁，你在哪，你要打车去哪！",
"玩转Metasploit之Automated Persistent Backdoor",
"Docker安全那些事 ",
"Use bitsadmin to maintain persistence and bypass Autoruns ",
"CTF中那些脑洞大开的编码和加密 ",
"Jenkins RCE 2(CVE-2016-0788)分析及利用",
"小议安卓定位伪造-实战足不出户畅玩pokemon go",
"三个白帽挑战赛之[续集]火币网2W大挑战Writeup"
]

for text in search_text:
    text = quote(text)
    print base_search_url.format(text=text)
    webbrowser.open_new_tab(base_search_url.format(text=text))
