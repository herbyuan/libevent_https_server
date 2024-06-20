if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(STATUS "------------------")
    set(CMAKE_GENERATOR "MinGW Makefiles" CACHE INTERNAL "" FORCE)
endif()


cmake_minimum_required(VERSION 3.12)

project(MyFindPackage)
set(CMAKE_CXX_STANDARD 17)
# message(STATUS "------------------")

add_executable(server server.cpp utils.cpp)

if (WIN32)
    target_link_libraries(server PRIVATE ssl crypto)
    target_link_libraries(server PRIVATE event event_openssl ws2_32 bcrypt Iphlpapi)
    target_link_libraries(server PRIVATE iconv)
else()
  find_package(Libevent REQUIRED)
  find_package(OpenSSL REQUIRED)
  target_link_libraries(server libevent::core libevent::extra libevent::openssl)
  target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(server PRIVATE iconv)
endif()






