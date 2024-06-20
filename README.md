# libevent_https_server

#### 介绍
https server with Libevent

#### 软件架构

使用 `Libevent` 实现的服务器，指定 `root` 位置后可以代理静态网站。


#### 安装教程

1.  安装 `cmake`, `libevent`, `openssl`
2.  修改和指定 `SSL` 证书的路径和网站根目录
3.  `cmake ./`
4.  `make`

#### 使用说明

1.  windows下只能在 `mingw` 中使用，请使用编译命令 `cmake -G "MinGW Makefiles"`，并处理好需要的库
2.  理论上处理好了各种包的依赖 `MVSC` 不应该有问题，但我试了一天以失败告终，有成功的请帮帮我

#### 功能

1.  实现了文件下载的断点续传
2.  可以代理文件夹作为文件服务器
3.  增加了 `windows` 下中文路径的 `GBK` 支持


#### 存在的问题

1. windows下我处理不好各种库的依赖，vcpkg 好像也不怎么好用，不知道为啥
