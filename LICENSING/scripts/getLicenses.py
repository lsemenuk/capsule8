#!/usr/bin/env python3
import urllib.request
import time
import os
import sys
import re

def multiReplace(url, dic):
    reg = re.compile('|'.join(map(re.escape, dic.keys())))
    return reg.sub(lambda match: dic[match.group(0)], url)

def main():
    if(len(sys.argv) != 3):
        sys.exit("Error: Please enter the path to the csv file containing the URL's and then the file containing the project names: ./getLicenses <path-to-file> <path-to-project-names>")

    #read urls
    f = open(sys.argv[1], 'r')
    urls = []
    for line in f.readlines():
        urls.append(line.strip())

    #read libs 
    f = open(sys.argv[2], 'r')
    libs = []
    for line in f.readlines():
        libs.append(line.strip())

    #Check to see if lists are equal size
    if(len(urls) != len(libs)):
        sys.exit("The length of the urls is not equal to the length of the corresponding libs")

    #Dict to get correct urls
    replace = {'https://github.com':'https://raw.githubusercontent.com', '/blob':''}
    basePath = os.getcwd() + '/'

    #convert urls to their raw counterparts, create appropriate dir, and download license
    for i in range(len(urls)):
        path = basePath + libs[i]
        if(os.path.exists(path) != True):
            print(path + ":" + urls[i])
            os.mkdir(path)
            urllib.request.urlretrieve(multiReplace(urls[i], replace), path + '/LICENSE')
            time.sleep(.25)
   
if __name__ == '__main__':
    main()
