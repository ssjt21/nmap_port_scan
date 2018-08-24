# -*- coding: utf-8 -*-

"""
@author:随时静听
@file: nmapScan.py
@time: 2018/08/23
@email:wang_di@topsec.com.cn
"""
from IPy import IP
import glob
from multiprocessing import   Process,Pool
import nmap
import os

def getAll(filepath):
    file_lst=glob.glob1(filepath,'*.txt')
    ip_lst=[]

    for filename in file_lst:
        print '\033[1;31m %s \033[0m' % filename
        with open(filename,'r') as f:
            for ip in f.readlines():
                ip=ip.strip()
                try:
                    ip_=IP(ip)
                    for ip in ip_:
                        # print ip
                        ip_lst.append(ip)
                except:
                    with open('failed.log','a+') as f:
                        f.write(ip+'\n')
    return  ip_lst



# -sV -p- -T4 -Pn -n --min-parallelism 512 --min-hostgroup 64
def portScan(ip,command='-sV -p- -T4 -Pn -n  '):
    ip=str(ip)
    filenanme=REPORTPAHT+'/'+ip+'.xml'
    if os.path.exists(filenanme):
        print 'exists'
        return

    nm=nmap.PortScanner()
    nm.scan(ip,arguments=command)
    with open(filenanme,'w') as f:
        f.write(nm.get_nmap_last_output())
    print nm.command_line()

# portScan('192.168.1.1')

# def reportExcel(datalst,title=TI):


if __name__ == '__main__':
    import sys
    if len(sys.argv)<3:
        print '[!] Usage: nmapScan.py ipfiledir [reportxmldir]'
        print '[!] Demo: nmapScan.py  ip_path  RESULT_XML_DIR'
    else:

        REPORTPAHT=sys.argv[2]
        REPORTPAHT= 'report' if not REPORTPAHT else REPORTPAHT
        IPPATH=sys.argv[1]
        if not os.path.exists(IPPATH):
            print "[!] '%s' path does not exists!" % IPPATH
            exit(1)
    if not os.path.exists(REPORTPAHT):
        os.mkdir(REPORTPAHT)
    p_lst=[]
    pool= Pool()
    for ip in getAll(IPPATH):
        pool.apply_async(portScan,(ip,))

    pool.close()
    pool.join()

    print "complete！"
    pass