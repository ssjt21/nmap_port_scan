## 脚本功能

- 多进程模式对单IP使用端口和服务探测
- 扫描结果导出XML指定文件路径
- ip路径指定的ip文件必须以.txt为后缀

## 依赖包

- 扫描依赖nmap模块 ，你需要在的电脑上首先装上Nmap并配置好环境变量
- IP解析模块,可以对域名进行反向解析，脚本中没有使用，需要的话自己加入
- multiprocessing 多进程支持

```cmd
pip install nmap

pip install IPy

pip install multiprocessing
```

## 使用方法以及nmap参数说明

```cython
#我这里选取的参数是：
# -sV -p- -T4 -Pn -n 

#如果需要提速请使用T5参数以及合适的网络探针数量
--min-parallelism 512  #或者指定各大的数字，但是你要注意，数字过大可导致网络断开

#如果你想分组，请针对程序进行修改并加入：
--min-hostgroup 64 #当你扫描的段比较大的时候可以指定分组扫描，
#当你使用全端口扫描的时候尽量不要指定太大的分组，因为太大将会降低效率或者没有效果

# 进行端口扫描需要明确一点：
# 1.可以跳过主机存活探测 -Pn 或-P0
# 2. 不需要进行反向解析获取主机名称 :-n

## 根据需求，往往可以通过学习nmap扫描的过程来设计不成的扫描参数


########### 使用方法

python nmapScan.py IP_list_dir xml_report_dir

```

- IP_list_dir：存放IP文件的文件夹，文件中IP可以是网段或单个IP，每行一个
- xml_report_dir：扫描结果导出的路径