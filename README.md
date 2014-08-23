该项目使用golang开发，可以在windows、linux部署。它通过读取预存储的HTTP完整请求，扫描各种web漏洞。
需要预先安装WebHunter。

注意：默认连接127.0.0.1上的mysql数据库，详见ivega/db/db.go

下载源码，进入源码目录，执行go build(生成可执行文件)
依赖库：
mysql driver(github.com/go-sql-driver/mysql)

使用方法详见help命令。
