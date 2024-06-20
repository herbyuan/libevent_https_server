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

1.  windows下若使用 `mingw` ，请使用编译命令 `cmake -G "MinGW Makefiles"`，并处理好需要的库
2. 如果使用 `MVSC` 最好搭配 `vcpkg` 解决依赖，安装 `libevent` 使用命令 `vcpkg install libevent[openssl]` 不然缺少 `libevent_openssl`。 编译使用命令 `cmake ./ -DCMAKE_TOOLCHAIN_FILE=C:/dev/vcpkg/scripts/buildsystems/vcpkg.cmake` 不然找不到对应的cmake文件，然后使用命令 `cmake --build ./ --config RelWithDebInfo` 生成可执行文件

#### 功能

1.  实现了文件下载的断点续传
2.  可以代理文件夹作为文件服务器
3.  增加了 `windows` 下中文路径的 `GBK` 支持


#### 存在的问题

1. windows下我处理不好各种库的依赖，vcpkg 好像也不怎么好用，不知道为啥
