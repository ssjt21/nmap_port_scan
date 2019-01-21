# -*- coding: utf-8 -*-

"""
@author:随时静听
@file: nmapScan.py
@time: 2018/08/23

"""
from IPy import IP
import glob
from multiprocessing import   Process,Pool
import nmap
import os
import re
def getAll(filepath):
    file_lst=glob.glob1(filepath,'*.txt')
    ip_lst=[]

    for filename in file_lst:
        print ' %s ' % filename
        with open(filename,'r') as f:
            for ip in f.readlines():
                ip=ip.strip()

                ip=re.findall('\d+\.\d+\.\d+\.\d+',ip)
                if ip :
                    # print ip
                    ip=ip[0]
                try:
                    ip_=IP(ip)
                    for ip in ip_:
                        # print ip
                        ip_lst.append(ip)
                except:
                    with open('failed.log','a+') as f:
                        print '[!] Failed : %s ,record data to failed.log!' % ip
                        f.write(ip+'\n')
    return  ip_lst



# -sV -p- -T4 -Pn -n --min-parallelism 512 --min-hostgroup 64
def portScan(ip,reportpath,command='-sV -p- -T4 -Pn -n '):

    ip=str(ip)

    filenanme=reportpath+'/'+ip+'.xml'

    if os.path.exists(filenanme):
        print 'exists'
        return
    print '[-] Scanning : %s ....' % ip
    nm=nmap.PortScanner()
    nm.scan(ip,arguments=command)

    with open(filenanme,'w') as f:
        f.write(nm.get_nmap_last_output())
    print nm.command_line()



# def reportExcel(datalst,title=TI):


if __name__ == '__main__':
    import sys
    if len(sys.argv)<3:
        print '[!] Usage: nmapScan.py ipfiledir [reportxmldir]'
        print '[!] Demo: nmapScan.py  ip_path  RESULT_XML_DIR'
        exit(1)
    else:

        REPORTPATH=sys.argv[2]
        REPORTPATH= 'report' if not REPORTPATH else REPORTPATH
        IPPATH=sys.argv[1]
        print REPORTPATH,IPPATH
        if not os.path.exists(IPPATH):
            print "[!] '%s' path does not exists!" % IPPATH
            exit(1)
    if not os.path.exists(REPORTPATH):
        os.mkdir(REPORTPATH)
    result=[]
    pool= Pool()
    ip_lst=getAll(IPPATH)
    print "[*] Total: %s" % len(ip_lst)
    for ip in ip_lst:

        # result.append( pool.apply_async(portScan,(ip,)))
        pool.apply_async(portScan,(ip,REPORTPATH))

    pool.close()
    pool.join()
    print "complete!"
    pass
