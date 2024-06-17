#include <iostream>
#include <fstream>
#include <evhttp.h>
#include <string.h>
#include <memory>
#include <cassert>
#include <vector>
#include <sstream>
#include <iomanip>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <event.h>
#include <event2/http.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

#include <fmt/core.h>

#include "utils.h"

using namespace std;
 

int main()
{
#ifdef _WIN32
    // Initialize Winsock
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
    {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }
#endif
    const char *version = event_get_version();
    std::cout << "Libevent version: " << version << std::endl;
    bool use_ssl = 1;
    string address = "0.0.0.0";
    string port = "9999";
    string ssl_cert = "./z2_cert/cert.pem";
    string ssl_key = "./z2_cert/key.pem";
    std::string root_path = "blog/public";
    SetRoot("blog/public");
    event_base *evbase = event_base_new();
    evhttp *httpd = evhttp_new(evbase);
    if (evhttp_bind_socket(httpd, address.c_str(), stoi(port)) == -1)
    {
        cerr << "Bind socket error" << endl;
    }

    SSL_CTX *ctx = nullptr;
    ctx = create_ctx_with_cert(ssl_cert.c_str(), ssl_key.c_str());
    if (ctx != nullptr && use_ssl)
    {
        evhttp_set_bevcb(httpd, SSL_bufferevent_cb, ctx);
        cout << "Listening on https://" << address << ":" << port << endl;
        cout << "Please visit https://z2.zhuoyuan-he.cn:" << port << endl;
    }
    else
    {
        cout << "Couldn't set SSL certs" << endl;
        cout << "Listening on http://" << address << ":" << port << endl;
    }

    evhttp_set_gencb(httpd, OnRequest, nullptr);
    if (event_base_dispatch(evbase) == -1)
    {
        std::cerr << "Failed to run messahe loop." << std::endl;
        return -1;
    }

    // Below shall never be reached...
    cout << "Exiting..." << endl;
    if (httpd)
    {
        evhttp_free(httpd);
    }
    if (evbase)
    {
        event_base_free(evbase);
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}