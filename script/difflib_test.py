# -*- coding: utf-8 -*-
# @Author: Nearg1e -- 2016-09-01 14:42:49 --0v0--

import difflib
import os

drops_arti_list = [
"SQL注入速查表（上）",
"WMI Attacks",
"攻击洋葱路由(Tor)匿名服务的一些综述",
"SQL注入速查表（下）与Oracle注入速查表",
"Hacking ipcam like Harold in POI",
"海豚浏览器与水星浏览器远程代码执行漏洞详解",
"WMI Backdoor",
"手把手教你当微信运动第一名 – 利用Android Hook进行微信运动作弊",
"WMI Defense",
"Tomcat安全配置",
"利用Weblogic进行入侵的一些总结",
"工控安全入门分析",
"利用被入侵的路由器获取网络流量",
"利用白名单绕过360实例",
"浅析大规模DDOS防御架构-应对T级攻防",
"XCode编译器里有鬼 – XCodeGhost样本分析",
"借用UAC完成的提权思路分享",
"TcpDump使用手册",
"被人遗忘的Memcached内存注射",
"利用被入侵的路由器迈入内网",
"Android sqlite load_extension漏洞解析",
"CTF主办方指南之对抗搅屎棍",
"域渗透的金之钥匙",
"比葫芦娃还可怕的百度全系APP SDK漏洞 - WormHole虫洞漏洞分析报告",
"那些年做过的ctf之加密篇",
"从一个锁主页木马里挖出的惊天“暗杀黑名单”",
"C&C控制服务的设计和侦测方法综述",
"Python安全编码指南",
"翻墙路由器的原理与实现",
"几期『三个白帽』小竞赛的writeup",
"拆分密码",
"变种XSS：持久控制",
"使用32位64位交叉编码混淆来打败静态和动态分析工具",
"給初學者的DLL Side Loading的UAC繞過",
"Joomla远程代码执行漏洞分析",
"网络小黑揭秘系列之黑色SEO初探",
"一步一步学ROP之Android ARM 32位篇",
"Linux入侵检测基础",
"Android WebView File域攻击杂谈",
"小议Linux安全防护(一)",
"Powershell 提权框架-Powerup",
"Android Linker学习笔记",
"MD5碰撞的演化之路",
"Android应用安全开发之源码安全",
"Ruby on Rails 动态渲染远程代码执行漏洞 (CVE-2016-0752)(翻译)",
"中间人攻击 -- Cookie喷发",
"域渗透——Security Support Provider",
"LUA脚本虚拟机逃逸技术分析",
"我的通行你的证",
"在不需要知道密码的情况下 Hacking MSSQL",
"代码审计入门总结",
"Linux服务器应急事件溯源报告",
"Head First FILE Stream Pointer Overflow",
"从 WTForm 的 URLXSS 谈开源组件的安全性",
"网络小黑揭秘系列之黑产江湖黑吃黑—中国菜刀的隐形把手",
"简单验证码识别及工具编写思路",
"中国菜刀仿冒官网三百万箱子爆菊记",
"Rails Security (上) ",
"富文本存储型XSS的模糊测试之道",
"主机被入侵分析过程报告",
"Exploring SSTI in Flask/Jinja2 | WooYun知识库",
"0ctf writeup",
"一个支付宝木马的分析溯源之旅",
"QQ模拟登录实现后篇",
"渗透技巧——通过cmd上传文件的N种方法",
"通过ELF动态装载构造ROP链 （ Return-to-dl-resolve）",
"Mysql报错注入原理分析(count()、rand()、group by)",
"利用反射型XSS二次注入绕过CSP form-action限制",
"渗透Hacking Team过程",
"“信任“之殇――安全软件的“白名单”将放大恶意威胁",
"百脑虫之hook技术",
"内网渗透中转发工具总结",
"TCP安全测试指南-魔兽3找联机0day",
"CVE-2016-3714 - ImageMagick 命令执行分析",
"CVE-2016-1897/8 - FFMpeg漏洞分析",
"漫谈流量劫持",
"新姿势之Docker Remote API未授权访问漏洞分析和利用",
"利用CouchDB未授权访问漏洞执行任意系统命令",
"利用环境变量LD_PRELOAD来绕过php disable_function执行系统命令",
"CTF中比较好玩的stego",
"linux下tomcat安全配置",
"MySQL和PostgreSQL数据库安全配置",
"内网渗透思路探索之新思路的探索与验证",
"小窥TeslaCrypt密钥设计",
"Do Evil Things with gopher://",
"三个白帽条条大路通罗马系列2之二进制题分析",
"Android安全开发之Provider组件安全",
"漏洞检测的那些事儿 ",
"QQ浏览器隐私泄露报告",
"三个白帽之从pwn me调试到Linux攻防学习",
"渗透中寻找突破口的那些事",
"Struts2 S033与最新S037详细分析",
"DB2在渗透中的应用",
"Python urllib HTTP头注入漏洞 (中文翻译)",
"SQL注入关联分析",
"Anti-debugging Skills in APK",
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

filelist = []

def ingore_text(x):
    return ' _ WooYun知识库.html'


def diff_age(newstr = '', oldstr = ''):
    req = difflib.SequenceMatcher(None, newstr, oldstr)
    return req.ratio()


def get_drops_file_list():
    path = os.path.realpath('C:\Users\RedMagic\Desktop\wooyun_articles\drops')
    filelist = os.listdir(path)
    return filelist


def dict2str(dict = {}):
    return 'filename:'+dict['filename']+'\n'+'diff_age:'+str(dict['diff_age'])+'\n'+'title:'+dict['title']+'\n\n\n'


if __name__ == '__main__':
    max_age_list = []
    filelist = filelist
    for title in drops_arti_list:
        max_age_dict = {}
        diff_age_list = []
        for filename in filelist:
            diff_age_dict = {}
            current_diff_age = diff_age(title.decode('utf-8'), filename[:-5].decode('utf-8'))
            diff_age_dict['filename'] = filename
            diff_age_dict['diff_age'] = current_diff_age
            diff_age_list.append(diff_age_dict)
        print max([x['diff_age'] for x in diff_age_list])
        max_age_dict = max(diff_age_list, key=lambda x:x['diff_age'])
        max_age_dict['title'] = title
        # max_age_list.append(max_age_dict)
        open('result.txt', 'a').write(dict2str(max_age_dict))
