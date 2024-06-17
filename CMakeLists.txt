cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(MyFindPackage)
set(CMAKE_CXX_STANDARD 17)
# message(STATUS "------------------")

# 查找 fmt 库
find_package(fmt REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)
find_package(Libevent REQUIRED)

link_libraries(libevent::core libevent::extra libevent::openssl)
link_libraries(OpenSSL::SSL OpenSSL::Crypto)
link_libraries(fmt::fmt)

# link_libraries(fmt)
# link_libraries(OpenSSL)
# link_libraries(Libevent)

add_executable(server server.cpp utils.cpp)



