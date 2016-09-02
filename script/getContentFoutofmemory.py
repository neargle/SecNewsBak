# -*- coding: utf-8 -*-
# @Author: Nearg1e -- 2016-09-01 21:53:42 --0v0--

import requests
import re

urllist = [
"http://ju.outofmemory.cn/entry/203198"
]

html_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <meta charset="utf-8">
</head>
<body>
<h1>{title}</h1>
{content}
</body>
</html>
'''

def gethtmlfoom(url=''):
    re_str = r'.*return true;\n.*}\n<\/script>([\s\S]+)<div class="like">\n\s+<a href'
    re_title = r'<title>(.*)</title>'
    req = requests.get(url, timeout=10)
    con = req.content
    content = re.findall(re_str, con)[0]
    title = re.findall(re_title, con)[0]
    content = html_template.format(title=title, content=content)
    for newstr in ['\\', '//', ':', '*', '?', '"', '<', '>', '|']:
        title = title.replace(newstr, '')
    print url
    open('getfromnet/'+title.split('-')[0].decode('utf-8')+'.html', 'w').write(content)

if __name__ == '__main__':
    for url in urllist:
        gethtmlfoom(url)
