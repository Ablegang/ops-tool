# 过程记录

## 环境下载

- [go 环境](https://golang.org/dl/)
- [IDE](https://www.jetbrains.com/go/)
  > 一定要开启 go modules，goland-->preferences-->GO-->Go modules

## go mod

新建项目后，在 terminal 执行：
```cli
go mod init <project-name>
```

## go proxy

如果加载包太慢，可以配置镜像
go env -w GOPROXY=https://goproxy.cn,direct

## vendor

关于 vendor ，以前写项目需要运行 go mod vendor 来将三方包加载到 vendor 目录下，其实并不建议这么操作
goland 能够自动跟踪到相关方法，在 External Libraries 下的 Go Modules 下

直接运行 go run main.go 会自动下载相关包，goland 的报错也就没了


# 使用指南

可以直接 go run main.go help 来查看相关操作

如果服务器账号密码不便透露，可以直接将项目编译为执行文件，生成好配置文件后，发给相关的人替换配置文件即可

加密 key 支持修改