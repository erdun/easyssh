easyssh
====

根据ssh config 来连接远程机器

     +--------+       +----------+      +-----------+
     | Laptop | <-->  | Jumphost | <--> | FooServer |
     +--------+       +----------+      +-----------+

你只需设置 ssh config

```ssh config
Host Jumphost
ServerAliveInterval 30
HostName 10.0.200.1
Port 22
User alex
IdentityFile /Users/alex/.ssh/id_rsa

Host FooServer
ServerAliveInterval 30
HostName 10.0.200.2
ProxyCommand ssh Jumphost -C -W %h:%p
Port 22
User alex
IdentityFile /Users/alex/.ssh/id_rsa
```

### Api

* Run
在目标机运行命令

```go

easyssh.Run("FooServer", "ls")
```

* SendFile

将本地文件发送到远程服务器

```go
easyssh.SendFile("FooServer", "sourcePath", "destPath")
```
* FetchFile

拉取远程文件

```go
easyssh.FetchFile("FooServer", "sourcePath", "destPath")
```


当然也可以不用 ssh config

```go
cfg := &MainConfig{
  User: "alex",
  HostName: "10.0.200.1",
  KeyPath: "/Users/alex/.ssh/id_rsa",
  Port: 22,
}
client, err := cfg.InitSSHClient()
client.Run(cmd, 30)
```