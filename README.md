
```
                        一款多协程邮箱爆破工具

   _____         .__.__    _________                       __
  /     \ _____  |__|  |   \_   ___ \____________    ____ |  | __
 /  \ /  \\__  \ |  |  |   /    \  \/\_  __ \__  \ _/ ___\|  |/ /
/    Y    \/ __ \|  |  |__ \     \____|  | \// __ \\  \___|    <
\____|__  (____  /__|____/  \______  /|__|  (____  /\___  >__|_ \
        \/     \/                  \/            \/     \/     \/

                                                     by:HumorKing

usage: mail_crack.py [-h] [--domain DOMAIN] --mail MAIL --password PASSWORD [--model MODEL] [--ssl SSL]
                     [--thread THREAD]

多协议邮箱爆破(POP、SMTP、IMAP)

optional arguments:
  -h, --help            show this help message and exit
  --domain DOMAIN, -d DOMAIN
                        邮箱服务器地址
  --mail MAIL, -m MAIL  邮箱地址文件
  --password PASSWORD, -p PASSWORD
                        密码字典
  --model MODEL, -a MODEL
                        协议[pop,imap,smtp,qq] 默认imap
  --ssl SSL, -f SSL     使用SSL(默认False)
  --thread THREAD, -t THREAD
                        协程数(默认100)
```

```
Usage:python mail_carck.py -d pop.exmail.qq.com -m mail.txt -p pass.txt -a imap   #使用imap协议爆破
      python mail_carck.py -m mail.txt -p pass.txt -a qq  #爆破腾讯企业邮箱
```

