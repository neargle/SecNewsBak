# -*- coding: utf-8 -*-
# @Author: Nearg1e -- 2016-09-02 16:37:28 --0v0--

import requests
import re
import os
import shutil

# http://static.wooyun.org//drops/20151216/2015121615312451451170.png
# re_png_path = '/drops/20151216/2015121615312451451170.png'
re_img_path = '(http\:\/\/static.wooyun.org\/{1,2}[A-Za-z0-9]+\/\d+\/[A-Za-z0-9]+\.[a-z]{3})'

def dlimg(imgurl='', filepath=''):
    response = requests.get(imgurl, stream=True)
    path = os.path.dirname(filepath)
    if not os.path.exists(path):
        mkdir_p(path)
    with open(filepath, 'wb') as out_file:
        shutil.copyfileobj(response.raw, out_file)
    del response

def mkdir_p(path):
    import errno
    try:
        os.makedirs(path)
    except OSError as exc: # Python >2.5 (except OSError, exc: for Python <2.5)
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

def copy_file(origin=None, target=None):
    shutil.copyfile(origin, target)

def getimglist(htmltext=''):
    img_url_list = re.findall(re_img_path, htmltext)
    return img_url_list

def getimgpath(url=''):
    re_path = 'http\:\/\/static.wooyun.org\/{1,2}([A-Za-z0-9]+\/\d+\/[A-Za-z0-9]+\.[a-z]{3})'
    print re.findall(re_path, url)[0]
    return re.findall(re_path, url)[0]

if __name__ == '__main__':
    path = os.path.realpath('E:\ProgramWorkSpace\SecNewsBak\drops')
    imgpath = os.path.realpath('E:\ProgramWorkSpace\SecNewsBak\image')
    for file in os.listdir(path):
        filename = os.path.join(path, file)
        with open(filename, 'r') as filebuf:
            html = filebuf.read()
            img_url_list = getimglist(html)
            for url in img_url_list:
                print url
                dlimg(imgurl=url, filepath=os.path.join(imgpath, getimgpath(url)))