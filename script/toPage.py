# -*- coding: utf-8 -*-
# @Author: Nearg1e -- 2016-09-02 10:10:41 --0v0--

# -*- coding: utf-8 -*-
# @Author: Nearg1e -- 2016-09-01 20:15:13 --0v0--

import os
import difflib
import shutil

titleList = [
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

arti_url_dict = {
'SQL注入速查表（上）': r'http://drops.wooyun.org/tips/7840',
'WMI Attacks': r'http://drops.wooyun.org/tips/8189',
'攻击洋葱路由(Tor)匿名服务的一些综述': r'http://drops.wooyun.org/papers/8265',
'SQL注入速查表（下）与Oracle注入速查表': r'http://drops.wooyun.org/tips/8242',
'Hacking ipcam like Harold in POI': r'http://drops.wooyun.org/papers/8298',
'海豚浏览器与水星浏览器远程代码执行漏洞详解': r'http://drops.wooyun.org/mobile/8293',
'WMI Backdoor': r'http://drops.wooyun.org/tips/8260',
'手把手教你当微信运动第一名 – 利用Android Hook进行微信运动作弊': r'http://drops.wooyun.org/tips/8416',
'WMI Defense': r'http://drops.wooyun.org/tips/8290',
'Tomcat安全配置': r'http://drops.wooyun.org/%E8%BF%90%E7%BB%B4%E5%AE%89%E5%85%A8/8519',
'利用Weblogic进行入侵的一些总结': r'http://drops.wooyun.org/tips/8321',
'工控安全入门分析': r'http://drops.wooyun.org/tips/8594',
'利用被入侵的路由器获取网络流量': r'http://drops.wooyun.org/tips/8641',
'利用白名单绕过360实例': r'http://drops.wooyun.org/tips/8701',
'浅析大规模DDOS防御架构-应对T级攻防': r'http://drops.wooyun.org/tips/8872',
'XCode编译器里有鬼 – XCodeGhost样本分析': r'http://drops.wooyun.org/news/8864',
'借用UAC完成的提权思路分享': r'http://drops.wooyun.org/tips/8989',
'TcpDump使用手册': r'http://drops.wooyun.org/运维安全/8885',
'被人遗忘的Memcached内存注射': r'http://drops.wooyun.org/web/8987',
'利用被入侵的路由器迈入内网': r'http://drops.wooyun.org/tips/9121',
'Android sqlite load_extension漏洞解析': r'http://drops.wooyun.org/mobile/9247',
'CTF主办方指南之对抗搅屎棍': r'http://drops.wooyun.org/tips/9405',
'域渗透的金之钥匙': r'http://drops.wooyun.org/tips/9591',
'比葫芦娃还可怕的百度全系APP SDK漏洞 - WormHole虫洞漏洞分析报告': r'http://drops.wooyun.org/papers/10061',
'那些年做过的ctf之加密篇': r'http://drops.wooyun.org/tips/10002',
'从一个锁主页木马里挖出的惊天“暗杀黑名单”': r'http://drops.wooyun.org/papers/10243',
'C&C控制服务的设计和侦测方法综述': r'http://drops.wooyun.org/tips/10232',
'Python安全编码指南': r'http://drops.wooyun.org/tips/10383',
'翻墙路由器的原理与实现': r'http://drops.wooyun.org/papers/10177',
'几期『三个白帽』小竞赛的writeup': r'http://drops.wooyun.org/tips/10564',
'拆分密码': r'http://drops.wooyun.org/tips/10641',
'变种XSS：持久控制': r'http://drops.wooyun.org/web/10798',
'使用32位64位交叉编码混淆来打败静态和动态分析工具': r'http://drops.wooyun.org/papers/11032',
'給初學者的DLL Side Loading的UAC繞過': r'http://drops.wooyun.org/tips/10912',
'Joomla远程代码执行漏洞分析': r'http://drops.wooyun.org/papers/11330',
'网络小黑揭秘系列之黑色SEO初探': r'http://drops.wooyun.org/papers/11448',
'一步一步学ROP之Android ARM 32位篇': r'http://drops.wooyun.org/papers/11390',
'Linux入侵检测基础': r'http://drops.wooyun.org/%E8%BF%90%E7%BB%B4%E5%AE%89%E5%85%A8/11106',
'Android WebView File域攻击杂谈': r'http://drops.wooyun.org/mobile/11263',
'小议Linux安全防护(一)': r'http://drops.wooyun.org/%e8%bf%90%e7%bb%b4%e5%ae%89%e5%85%a8/11801',
'Powershell 提权框架-Powerup': r'http://drops.wooyun.org/tips/11989',
'Android Linker学习笔记': r'http://drops.wooyun.org/tips/12122',
'MD5碰撞的演化之路': r'http://drops.wooyun.org/papers/12396',
'Android应用安全开发之源码安全': r'http://drops.wooyun.org/mobile/12172',
'Ruby on Rails 动态渲染远程代码执行漏洞 (CVE-2016-0752)(翻译)': r'http://drops.wooyun.org/papers/12519',
'中间人攻击 -- Cookie喷发': r'http://drops.wooyun.org/papers/12645',
'域渗透——Security Support Provider': r'http://drops.wooyun.org/tips/12518',
'LUA脚本虚拟机逃逸技术分析': r'http://drops.wooyun.org/tips/12677',
'我的通行你的证': r'http://drops.wooyun.org/web/12695',
'在不需要知道密码的情况下 Hacking MSSQL': r'http://drops.wooyun.org/tips/12749',
'代码审计入门总结': r'http://drops.wooyun.org/tips/12751',
'Linux服务器应急事件溯源报告': r'http://drops.wooyun.org/tips/12972',
'Head First FILE Stream Pointer Overflow': r'http://drops.wooyun.org/binary/12740',
'从 WTForm 的 URLXSS 谈开源组件的安全性': r'http://drops.wooyun.org/papers/13058',
'网络小黑揭秘系列之黑产江湖黑吃黑—中国菜刀的隐形把手': r'http://drops.wooyun.org/papers/13128',
'简单验证码识别及工具编写思路': r'http://drops.wooyun.org/tips/13043',
'中国菜刀仿冒官网三百万箱子爆菊记': r'http://drops.wooyun.org/news/13471',
'Rails Security (上) ': r'http://drops.wooyun.org/web/12750',
'富文本存储型XSS的模糊测试之道': r'http://drops.wooyun.org/web/13124',
'主机被入侵分析过程报告': r'http://drops.wooyun.org/tips/13647',
'Exploring SSTI in Flask/Jinja2 | WooYun知识库': r'http://drops.wooyun.org/tips/13683',
'0ctf writeup': r'http://drops.wooyun.org/tips/13791',
'一个支付宝木马的分析溯源之旅': r'http://drops.wooyun.org/papers/14103',
'QQ模拟登录实现后篇': r'http://drops.wooyun.org/tips/14042',
'渗透技巧——通过cmd上传文件的N种方法': r'http://drops.wooyun.org/tips/14101',
'通过ELF动态装载构造ROP链 （ Return-to-dl-resolve）': r'http://drops.wooyun.org/binary/14360',
'Mysql报错注入原理分析(count()、rand()、group by)': r'http://drops.wooyun.org/tips/14312',
'利用反射型XSS二次注入绕过CSP form-action限制': r'http://drops.wooyun.org/tips/14686',
'渗透Hacking Team过程': r'http://drops.wooyun.org/pentesting/15117',
'“信任“之殇――安全软件的“白名单”将放大恶意威胁': r'http://drops.wooyun.org/tips/15249',
'百脑虫之hook技术': r'http://drops.wooyun.org/mobile/15308',
'内网渗透中转发工具总结': r'http://drops.wooyun.org/tools/15000',
'TCP安全测试指南-魔兽3找联机0day': r'http://drops.wooyun.org/papers/15557',
'CVE-2016-3714 - ImageMagick 命令执行分析': r'http://drops.wooyun.org/papers/15589',
'CVE-2016-1897/8 - FFMpeg漏洞分析': r'http://drops.wooyun.org/papers/15598',
'漫谈流量劫持': r'http://drops.wooyun.org/tips/15826',
'新姿势之Docker Remote API未授权访问漏洞分析和利用': r'http://drops.wooyun.org/papers/15892',
'利用CouchDB未授权访问漏洞执行任意系统命令': r'http://drops.wooyun.org/papers/16030',
'利用环境变量LD_PRELOAD来绕过php disable_function执行系统命令': r'http://drops.wooyun.org/tips/16054',
'CTF中比较好玩的stego': r'http://drops.wooyun.org/tips/16041',
'linux下tomcat安全配置': r'http://drops.wooyun.org/%E8%BF%90%E7%BB%B4%E5%AE%89%E5%85%A8/15888',
'MySQL和PostgreSQL数据库安全配置': r'http://drops.wooyun.org/%e8%bf%90%e7%bb%b4%e5%ae%89%e5%85%a8/16067',
'内网渗透思路探索之新思路的探索与验证': r'http://drops.wooyun.org/tips/16116',
'小窥TeslaCrypt密钥设计': r'http://drops.wooyun.org/tips/16060',
'Do Evil Things with gopher://': r'http://drops.wooyun.org/tips/16357',
'三个白帽条条大路通罗马系列2之二进制题分析': r'http://drops.wooyun.org/papers/16380',
'Android安全开发之Provider组件安全': r'http://drops.wooyun.org/mobile/16382',
'漏洞检测的那些事儿 ': r'http://drops.wooyun.org/tips/16431',
'QQ浏览器隐私泄露报告': r'http://drops.wooyun.org/papers/14532',
'三个白帽之从pwn me调试到Linux攻防学习': r'http://drops.wooyun.org/binary/16700',
'渗透中寻找突破口的那些事': r'http://drops.wooyun.org/tips/2915',
'Struts2 S033与最新S037详细分析': r'http://drops.wooyun.org/papers/16875',
'DB2在渗透中的应用': r'http://drops.wooyun.org/tips/16673',
'Python urllib HTTP头注入漏洞 (中文翻译)': r'http://drops.wooyun.org/papers/16905',
'SQL注入关联分析': r'http://drops.wooyun.org/web/16972',
'Anti-debugging Skills in APK': r'http://drops.wooyun.org/mobile/16969',
'玩转Metasploit之Automated Persistent Backdoor': r'http://drops.wooyun.org/tips/16908',
'Uber渗透案例：我们是如何发现你是谁，你在哪，你要打车去哪！': r'http://drops.wooyun.org/tips/17228',
'玩转Metasploit之Automated Persistent Backdoor': r'http://drops.wooyun.org/tips/16908',
'Docker安全那些事 ': r'http://drops.wooyun.org/tips/17416',
'Use bitsadmin to maintain persistence and bypass Autoruns ': r'http://drops.wooyun.org/tips/15692',
'CTF中那些脑洞大开的编码和加密 ': r'http://drops.wooyun.org/tips/17609',
'Jenkins RCE 2(CVE-2016-0788)分析及利用': r'http://drops.wooyun.org/papers/17716',
'小议安卓定位伪造-实战足不出户畅玩pokemon go': r'http://drops.wooyun.org/tips/17840',
'三个白帽挑战赛之[续集]火币网2W大挑战Writeup': r'http://drops.wooyun.org/tips/17839'
}

filelist = [
'“信任“之殇――安全软件的“白名单”将放大恶意威胁.html',
'0ctf writeup.html',
'Android Linker学习笔记.html',
'Android sqlite load_extension漏洞解析.html',
'Android WebView File域攻击杂谈.html',
'Android安全开发之Provider组件安全.html',
'Android应用安全开发之源码安全.html',
'Anti-debugging Skills in APK.html',
'C&amp;C控制服务的设计和侦测方法综述 .html',
'CTF中比较好玩的stego.html',
'CTF中那些脑洞大开的编码和加密 .html',
'CTF主办方指南之对抗搅屎棍.html',
'CVE-2016-1897.8 - FFMpeg漏洞分析.html',
'CVE-2016-3714 - ImageMagick 命令执行分析.html',
'DB2在渗透中的应用.html',
'Do Evil Things with gopher .html',
'Docker安全那些事 .html',
'Exploring SSTI in Flask.Jinja2.html',
'Hacking ipcam like Harold in POI .html',
'Head First FILE Stream Pointer Overflow.html',
'Jenkins RCE 2(CVE.html',
'Joomla远程代码执行漏洞分析.html',
'Linux服务器应急事件溯源报告.html',
'Linux入侵检测基础.html',
'linux下tomcat安全配置.html',
'LUA脚本虚拟机逃逸技术分析.html',
'MD5碰撞的演化之路.html',
'Mysql报错注入原理分析(count()、rand()、group by).html',
'MySQL和PostgreSQL数据库安全配置.html',
'Powershell 提权框架-Powerup.html',
'Python urllib HTTP头注入漏洞.html',
'Python安全编码指南 .html',
'QQ浏览器隐私泄露报告.html',
'QQ模拟登录实现后篇.html',
'Rails Security (上).html',
'Ruby on Rails 动态渲染远程代码执行漏洞 (CVE.html',
'SQL注入关联分析 .html',
'SQL注入速查表（上） .html',
'SQL注入速查表（上）.html',
'Struts2 S033与最新S037详细分析 .html',
'TcpDump使用手册.html',
'TCP安全测试指南-魔兽3找联机0day.html',
'Tomcat安全配置.html',
'toPgae.py',
'Uber渗透案例：我们是如何发现你是谁，你在哪，你要打车去哪！ .html',
'Use bitsadmin to maintain persistence and bypass A .html',
'WMI Attacks .html',
'WMI Backdoor .html',
'WMI Defense.html',
'Xcode编译器里有鬼 – XcodeGhost样本分析.html',
'百脑虫之hook技术.html',
'被人遗忘的Memcached内存注射.html',
'比葫芦娃还可怕的百度全系APP SDK漏洞 .html',
'变种XSS：持久控制.html',
'拆分密码.html',
'从 WTForm 的 URLXSS 谈开源组件的安全性.html',
'从一个锁主页木马里挖出的惊天“暗杀黑名单” .html',
'代码审计入门总结.html',
'翻墙路由器的原理与实现 .html',
'富文本存储型XSS的模糊测试之道.html',
'給初學者的DLL Side Loading的UAC繞過.html',
'工控安全入门分析.html',
'攻击洋葱路由(Tor)匿名服务的一些综述 .html',
'海豚浏览器与水星浏览器远程代码执行漏洞详解 .html',
'几期『三个白帽』小竞赛的writeup.html',
'简单验证码识别及工具编写思路.html',
'借用UAC完成的提权思路分享.html',
'利用CouchDB未授权访问漏洞执行任意系统命令.html',
'利用Weblogic进行入侵的一些总结.html',
'利用白名单绕过360实例.html',
'利用被入侵的路由器获取网络流量.html',
'利用被入侵的路由器迈入内网.html',
'利用反射型XSS二次注入绕过CSP form-action限制.html',
'利用环境变量LD_PRELOAD来绕过php disable_function执行系统命令.html',
'漏洞检测的那些事儿.html',
'漫谈流量劫持.html',
'那些年做过的ctf之加密篇 .html',
'内网渗透思路探索    之新思路的探索与验证.html',
'内网渗透中转发工具总结.html',
'浅析大规模DDOS防御架构-应对T级攻防.html',
'三个白帽挑战赛之[续集]火币网2W大挑战Writeup .html',
'三个白帽条条大路通罗马系列2之二进制题分析.html',
'三个白帽之从pwn me调试到Linux攻防学习.html',
'渗透Hacking Team过程.html',
'渗透技巧——通过cmd上传文件的N种方法.html',
'渗透中寻找突破口的那些事.html',
'使用32位64位交叉编码混淆来打败静态和动态分析工具.html',
'手把手教你当微信运动第一名 – 利用Android Hook进行微信运动作弊.html',
'通过ELF动态装载构造ROP链 （ Return-to-dl-resolve）.html',
'玩转Metasploit之Automated Persistent Backdoor .html',
'网络小黑揭秘系列之黑产江湖黑吃黑—中国菜刀的隐形把手.html',
'网络小黑揭秘系列之黑色SEO初探.html',
'我的通行你的证.html',
'小窥TeslaCrypt密钥设计.html',
'小议Linux安全防护(一).html',
'小议安卓定位伪造.html',
'新姿势之Docker Remote API未授权访问漏洞分析和利用.html',
'一步一步学ROP之Android ARM 32位篇.html',
'一个支付宝木马的分析溯源之旅.html',
'域渗透——Security Support Provider.html',
'域渗透的金之钥匙.html',
'在不需要知道密码的情况下 Hacking MSSQL.html',
'中国菜刀仿冒官网三百万箱子爆菊记.html',
'中间人攻击 -- Cookie喷发.html',
'主机被入侵分析过程报告.html'
]

def diff_age(newstr = '', oldstr = ''):
    req = difflib.SequenceMatcher(None, newstr, oldstr)
    return req.ratio()



def copy_file(origin='', target=''):
    path = os.path.dirname(target)
    if not os.path.exists(path):
        mkdir_p(path)
    shutil.copyfile(origin, target)


def mkdir_p(path):
    import errno
    try:
        os.makedirs(path)
    except OSError as exc: # Python >2.5 (except OSError, exc: for Python <2.5)
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise


def dict2str(dict = {}):
    return dict['filename']+' : '+str(dict['url'])+' : '+dict['title']+'\n\n'


if __name__ == '__main__':
    max_age_list = []
    i = 0
    for title in titleList:
        i = i+1
        print i
        print 'url:  '+arti_url_dict[title]
        max_age_dict = {}
        diff_age_list = []
        for filename in filelist:
            diff_age_dict = {}
            current_diff_age = diff_age(title.decode('utf-8'), filename[:-5].decode('utf-8'))
            diff_age_dict['filename'] = filename
            diff_age_dict['diff_age'] = current_diff_age
            diff_age_list.append(diff_age_dict)
        max_age_dict = max(diff_age_list, key=lambda x:x['diff_age'])
        max_age_dict['title'] = title
        max_age_dict['url'] = arti_url_dict[title]
        # import pdb;pdb.set_trace()
        if max_age_dict['diff_age'] > 0.8:
            copy_file(
                max_age_dict['filename'].decode('utf-8'),
                os.path.realpath('E:\ProgramWorkSpace\SecNewsBak\drops\\'+max_age_dict['filename'].decode('utf-8'))
                )
            stri = dict2str(max_age_dict)
            print '*************'
            open('result.txt', 'a').write(stri)
        else:
            print arti_url_dict[title]
            print str(max_age_dict['diff_age'])
