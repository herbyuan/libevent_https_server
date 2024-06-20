#include "utils.h"
#include <iostream>

std::string root_path = "html";

#include <windows.h>

#ifdef _WIN32
std::string utf8_to_gbk(const std::string &utf8str) {
    std::string gbkstr;
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8str.c_str(), -1, NULL, 0);
    wchar_t *wstr = new wchar_t[size];
    MultiByteToWideChar(CP_UTF8, 0, utf8str.c_str(), -1, wstr, size);

    size = WideCharToMultiByte(936, 0, wstr, -1, NULL, 0, NULL, NULL); // 936 is the code page for GBK
    char *str = new char[size];
    WideCharToMultiByte(936, 0, wstr, -1, str, size, NULL, NULL);
    gbkstr = str;
    delete[] wstr;
    delete[] str;
    return gbkstr;
}
#endif


std::string urlDecode(std::string str)
{
    std::string utf8_str;
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '%') {
            if (i + 2 < str.size()) {
                int hex;
                sscanf(str.substr(i + 1, 2).c_str(), "%x", &hex);
                utf8_str += static_cast<char>(hex);
                i += 2;
            }
        } else if (str[i] == '+') {
            utf8_str += ' ';
        } else {
            utf8_str += str[i];
        }
    }

#ifdef _WIN32
    // // Convert UTF-8 to GBK
    // iconv_t cd = iconv_open("GBK", "UTF-8");
    // if (cd == (iconv_t)-1) {
    //     std::cerr << "iconv_open failed" << std::endl;
    //     return "";
    // }

    // char *inbuf = &utf8_str[0];
    // size_t inbytesleft = utf8_str.size();
    // size_t outbytesleft = inbytesleft * 2;  // GBK may use up to 2 bytes per character
    // char outbuf[outbytesleft];

    // char *outptr = outbuf;
    // size_t result = iconv(cd, &inbuf, &inbytesleft, &outptr, &outbytesleft);
    // if (result == (size_t)-1) {
    //     std::cerr << "iconv failed" << std::endl;
    //     return "";
    // }

    // // Null-terminate the output buffer
    // *outptr = '\0';

    // std::string gbk_str(outbuf);

    // iconv_close(cd);
    std::string gbk_str = utf8_to_gbk(utf8_str);
    return gbk_str;
#else
    return utf8_str.c_str();
#endif
}


// std::string urlDecode(const std::string &str)
// {
//     std::ostringstream decoded;

//     for (size_t i = 0; i < str.size(); ++i)
//     {
//         if (str[i] == '%')
//         {
//             if (i + 2 < str.size())
//             {
//                 int hexValue;
//                 std::istringstream hexStream(str.substr(i + 1, 2));
//                 hexStream >> std::hex >> hexValue;
//                 decoded << static_cast<char>(hexValue);
//                 i += 2;
//             }
//         }
//         else if (str[i] == '+')
//         {
//             decoded << ' ';
//         }
//         else
//         {
//             decoded << str[i];
//         }
//     }
//     return decoded.str();
// }

char const *GetResponseStr(long code)
{
    switch (code)
    {
    case 0:
        return "No Response";

    case 101:
        return "Switching Protocols";

    case 200:
        return "OK";

    case 201:
        return "Created";

    case 202:
        return "Accepted";

    case 203:
        return "Non-Authoritative Information";

    case 204:
        return "No Content";

    case 205:
        return "Reset Content";

    case 206:
        return "Partial Content";

    case 300:
        return "Multiple Choices";

    case 301:
        return "Moved Permanently";

    case 302:
        return "Found";

    case 303:
        return "See Other";

    case 304:
        return "Not Modified";

    case 305:
        return "Use Proxy";

    case 306:
        return " (Unused)";

    case 307:
        return "Temporary Redirect";

    case 400:
        return "Bad Request";

    case 401:
        return "Unauthorized";

    case 402:
        return "Payment Required";

    case 403:
        return "Forbidden";

    case 404:
        return "Not Found";

    case 405:
        return "Method Not Allowed";

    case 406:
        return "Not Acceptable";

    case 407:
        return "Proxy Authentication Required";

    case 408:
        return "Request Timeout";

    case 409:
        return "Conflict";

    case 410:
        return "Gone";

    case 411:
        return "Length Required";

    case 412:
        return "Precondition Failed";

    case 413:
        return "Request Entity Too Large";

    case 414:
        return "Request-URI Too Long";

    case 415:
        return "Unsupported Media Type";

    case 416:
        return "Requested Range Not Satisfiable";

    case 417:
        return "Expectation Failed";

    case 421:
        return "Misdirected Request";

    case 500:
        return "Internal Server Error";

    case 501:
        return "Not Implemented";

    case 502:
        return "Bad Gateway";

    case 503:
        return "Service Unavailable";

    case 504:
        return "Gateway Timeout";

    case 505:
        return "HTTP Version Not Supported";

    default:
        return "Unknown Error";
    }
}

void send_simple_response(struct evhttp_request *req, int code, char const *text = nullptr)
{
    char const *code_text = GetResponseStr(code);
    struct evbuffer *body = evbuffer_new();

    evbuffer_add_printf(body, "<h1>%d: %s</h1>", code, code_text);

    if (text != nullptr)
    {
        evbuffer_add_printf(body, "%s", text);
    }

    evhttp_send_reply(req, code, code_text, body);

    evbuffer_free(body);
}

void common(evhttp_request *req, void *arg)
{
    std::cout << "common uri: " << req->uri << std::endl;
    evhttp_send_reply(req, 200, "OK", NULL);
}

void test(evhttp_request *req, void *arg)
{
    std::cout << "test uri: " << req->uri << std::endl;
    evhttp_send_reply(req, 200, "OK", NULL);
}

bool endsWith(std::string_view str, std::string_view suffix)
{
    if (str.length() < suffix.length())
    {
        return false;
    }
    return str.substr(str.length() - suffix.length()) == suffix;
}

std::string getExtension(std::string path)
{
    size_t pos = path.find_last_of('.');
    if (pos != std::string::npos)
    {
        return path.substr(pos);
    }
    else
    {
        return path; // 如果没有找到点，返回整个字符串作为后缀名
    }
}

char const *mimetype_guess(std::string path)
{
    // these are the ones we need for serving the web client's files...
    std::unordered_map<std::string, const char *> cases =
    {
        {".css", "text/css"},
        {".gif", "image/gif"},
        {".html", "text/html"},
        {".ico", "image/vnd.microsoft.icon"},
        {".js", "application/javascript"},
        {".png", "image/png"},
        {".jpg", "image/jpeg"},
        {".mp4", "video/mp4"},
        {".svg", "image/svg+xml"},
        {".mkv", "video/x-matroska"}
    };

    // Check if the string exists in the unordered_map
    std::string suffix = getExtension(path);
    auto it = cases.find(suffix);
    if (it != cases.end())
    {
        std::cout << it->second << std::endl;
        return it->second;
    }
    else
    {
        return "application/octet-stream";
    }
    // std::array<std::pair<std::string, char const *>, 10> Types = {{
    //     {".css", "text/css"},
    //     {".gif", "image/gif"},
    //     {".html", "text/html"},
    //     {".ico", "image/vnd.microsoft.icon"},
    //     {".js", "application/javascript"},
    //     {".png", "image/png"},
    //     {".jpg", "image/jpeg"},
    //     {".mp4", "video/mp4"},
    //     {".svg", "image/svg+xml"},
    //     {".mkv", "video/x-matroska"}
    // }};

    // for (auto const &[suffix, mime_type] : Types)
    // {
    //     if (endsWith(path, suffix))
    //     {
    //         return mime_type;
    //     }
    // }

    // return "application/octet-stream";
}

int file_read(const std::string &filename, std::string &content)
{
    std::ifstream ifs(filename);
    if (!ifs.good())
    {
        return -1;
    }
    content.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    ifs.close();
    return 0;
}

/* chunk read*/
int file_read2(const std::string &filename, std::string &content)
{
    FILE *fp = fopen(filename.c_str(), "rb");
    if (!fp)
    {
        return -1;
    }
    char buf[1024] = {0};
    for (;;)
    {
        size_t len = fread(buf, 1, sizeof(buf), fp);
        if (len <= 0)
            break;
        content.append(buf, len);
    }
    fclose(fp);
    return 0;
}

evbuffer *make_response(struct evhttp_request *req, std::string_view content)
{
    auto *const out = evbuffer_new();

    char const *key = "Accept-Encoding";
    char const *encoding = evhttp_find_header(req->input_headers, key);
    std::cout << "encoding: " << encoding << std::endl;
    evbuffer_add(out, std::data(content), std::size(content));

    return out;
}

/* use evbuffer_add_file() to improve perf */
void serve_file2(evhttp_request *req, std::string path)
{
    // evbuffer *evb = evbuffer_new();
    // {
    //     int fd;
    //     struct stat st;
    //     /* Otherwise it's a file; add it to the buffer to get
    //      * sent via sendfile */
    //     if ((fd = open(path.c_str(), O_RDONLY)) < 0) {
    //         printf("open error\n");
    //         return;
    //     }

    //     if (fstat(fd, &st)<0) {
    //         /* Make sure the length still matches, now that we
    //          * opened the file :/ */
    //         printf("fstat\n");
    //         return;
    //     }
    //     evhttp_add_header(req->output_headers, "Content-Type", mimetype_guess(path));
    //     evbuffer_add_file(evb, fd, 0, st.st_size);
    // }
    // evhttp_send_reply(req, 200, "OK", evb);
    // // send_simple_response(req, HTTP_NOTFOUND, path.c_str());
    // return;
    // std::string content;
    FILE *fp = fopen(path.c_str(), "rb");
    if (!fp)
    {
        send_simple_response(req, HTTP_NOTFOUND, path.c_str());
        return;
    }
    // Get the file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    evhttp_add_header(req->output_headers, "Content-Type", mimetype_guess(path));
    evbuffer *outbuf = evhttp_request_get_output_buffer(req);
    // evbuffer_set_flags(outbuf, EVBUFFER_FLAG_DRAINS_TO_FD);
    evutil_socket_t fd = fileno(fp);

    int64_t offset = 0;
    int64_t length = -1;
    struct evkeyvalq *headers = evhttp_request_get_input_headers(req);
    const char *range_header = evhttp_find_header(headers, "Range");

    if (range_header)
    {
        std::cout << "Range header found: " << range_header << std::endl;
        long start = 0, end = file_size - 1;
        const char *range_values = strstr(range_header, "=");
        if (range_values)
        {
            range_values++; // Move past the '=' character
            if (sscanf(range_values, "%ld-%ld", &start, &end) == 2)
            {
                // Adjust the start and end positions based on the Range header
                if (start < 0) start = 0;
                if (end >= file_size || end < start) end = file_size - 1;
            }
            else if (sscanf(range_values, "-%ld", &end) == 1)
            {
                // If only end position is provided
                if (end >= file_size) end = file_size - 1;
                start = file_size - end;
                end = file_size - 1;
            }
            else if (sscanf(range_values, "%ld-", &start) == 1)
            {
                // If only start position is provided
                if (start < 0) start = 0;
                end = file_size - 1;
            }
        }

        // Set the file pointer to the start position
        fseek(fp, start, SEEK_SET);
        // Calculate the length of the content to be sent
        long content_length = end - start + 1;
        evbuffer * evb = evbuffer_new();
        // Add the file data to the buffer

        std::cout << "SENDING PARTIAL CONTENT: " << start << "-" << end << std::endl;
        assert(evbuffer_add_file(evb, fd, start, content_length) != -1);

        // Send the response with the appropriate headers
        char header_str[100]; // Make sure this is large enough to hold the formatted string
        snprintf(header_str, sizeof(header_str), "bytes %ld-%ld/%ld", start, end, file_size);
        evhttp_add_header(req->output_headers, "Content-Range", header_str);
        evhttp_send_reply(req, 206, "Partial Content", evb);

        // Cleanup
        // fclose(fp);   // no need
        // evbuffer_free(evb);   // not sure??
        return;
    }

    std::cout << "Sending whole file" << std::endl;
    if (evbuffer_add_file(outbuf, (int)fd, 0, -1) == -1)
    {
        send_simple_response(req, HTTP_NOTFOUND, "Failed to add file to buffer.");
        fprintf(stderr, "Failed to add file to buffer.\n");
    }
    
    evhttp_send_reply(req, HTTP_OK, "OK", outbuf);
    // fclose(fp);
    std::cout << "file sent" << std::endl;
}

void serve_file(evhttp_request *req, std::string path)
{
    std::string content;
    if (file_read(path, content) != 0)
    {
        send_simple_response(req, HTTP_NOTFOUND, path.c_str());
        return;
    }

    evhttp_add_header(req->output_headers, "Content-Type", mimetype_guess(path));
    evbuffer *const response = make_response(req, std::string_view{std::data(content), std::size(content)});
    evhttp_send_reply(req, HTTP_OK, "OK", response);
    evbuffer_free(response);
}

void handle_web_client(evhttp_request *req, void *arg)
{
    const char *uri = evhttp_request_get_uri(req);
    evhttp_uri *decoded = evhttp_uri_parse(uri);
    if (!decoded)
    {
        printf("It's not a good URI. Sending BADREQUEST\n");
        evhttp_send_error(req, HTTP_BADREQUEST, 0);
        // send_simple_response(req, HTTP_NOTFOUND);
        return;
    }
    const char *path;
    path = evhttp_uri_get_path(decoded);
    if (!path)
        path = "/";
    std::string decoded_path;
    // decoded_path = evhttp_uridecode(path, 0, NULL);
    decoded_path = urlDecode(path);
    std::cout << decoded_path << std::endl;
    if (decoded_path == "")
    {
        evhttp_send_error(req, HTTP_BADREQUEST, 0);
        return;
    }
    if (decoded_path.find("..") != std::string::npos)
    {
        send_simple_response(req, HTTP_NOTFOUND);
        return;
    }
    std::string whole_path = root_path + decoded_path;
    // Remove trailing slash
    while (!whole_path.empty() && whole_path.back() == '/') {
        whole_path.pop_back();
    }
    std::cout << "whole_path = " << whole_path << std::endl;

    struct stat st;
    if (stat(whole_path.c_str(), &st)<0) {
        evhttp_send_error(req, HTTP_BADREQUEST, 0);
        return;
    }

    if (S_ISDIR(st.st_mode))
    {
        std::cout << "dir requested." << std::endl;
        /* If it's a directory and no index page, read the comments and make a little
         * index page */
        if (std::empty(whole_path) || whole_path.back() != '/')
        {
            whole_path += "/";
        }
        FILE *fp = fopen((whole_path + "index.html").c_str(), "rb");
        if (!fp)
        {
            std::cout << "index.html doesn't exist, list dir" << std::endl;
            // list dir
            std::cout << "list dir: " << whole_path << std::endl;
            /* If it's a directory, read the comments and make a little
             * index page */
#ifdef _WIN32
            HANDLE d;
            WIN32_FIND_DATAA ent;
            char *pattern;
            size_t dirlen;
#else
            DIR *d;
            struct dirent *ent;
#endif
            const char *trailing_slash = "";

            if (!strlen(path) || path[strlen(path) - 1] != '/')
                trailing_slash = "/";

#ifdef _WIN32
            dirlen = strlen(whole_path.c_str());
            pattern = static_cast<char*> (malloc(dirlen + 3));
            memcpy(pattern, whole_path.c_str(), dirlen);
            pattern[dirlen] = '\\';
            pattern[dirlen + 1] = '*';
            pattern[dirlen + 2] = '\0';
            d = FindFirstFileA(pattern, &ent);
            free(pattern);
            if (d == INVALID_HANDLE_VALUE)
            {
                std::cout << "error _win32" << std::endl;
                return;
            }
#else
            if (!(d = opendir(whole_path.c_str())))
            {
                evhttp_send_error(req, 404, "Document was not found");
                return;
            }
#endif
            evbuffer * evb = evbuffer_new();
            evbuffer_add_printf(evb,
                                "<!DOCTYPE html>\n"
                                "<html>\n <head>\n"
                                "  <meta charset='utf-8'>\n"
                                "  <title>%s</title>\n"
                                "  <base href='%s%s'>\n"
                                " </head>\n"
                                " <body>\n"
                                "  <h1>%s</h1>\n"
                                "  <ul>\n",
                                decoded_path, /* XXX html-escape this. */
                                path,         /* XXX html-escape this? */
                                trailing_slash,
                                decoded_path /* XXX html-escape this */);

            std::vector<std::string> files;
#ifdef _WIN32
            do
            {
                std::string name = ent.cFileName;
                if (ent.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    name += "/";
                }
                files.push_back(name);
#else
            while ((ent = readdir(d)))
            {
                std::string name = ent->d_name;
                if (ent->d_type == DT_DIR)
                {
                    name += "/";
                }
                files.push_back(name);
#endif

#ifdef _WIN32
            } while (FindNextFileA(d, &ent));
#else
            }
#endif

            // Sort the file names
            std::sort(files.begin(), files.end());

            // Print the sorted file names
            for (const auto &file : files)
            {
                evbuffer_add_printf(evb,
                    "    <li><a href=\"%s\">%s</a>\n",
                    file.c_str(), file.c_str()); /* XXX escape this */
            }
            evbuffer_add_printf(evb, "</ul></body></html>\n");
#ifdef _WIN32
            FindClose(d);
#else
            closedir(d);
#endif
            evhttp_add_header(evhttp_request_get_output_headers(req),
                              "Content-Type", "text/html");
            evhttp_send_reply(req, 200, "OK", evb);
            evbuffer_free(evb);
            return;
        }
        else
        {
            std::cout << "index.html exists" << std::endl;
            fclose(fp);
            whole_path += "index.html";
            serve_file2(req, whole_path);
        }
        return;
    }
    if (whole_path.back() == '/')
        whole_path += "index.html";
    serve_file2(req, whole_path);
    std::cout << "after serve_file2()" << std::endl;
    

    // // remove any trailing query / fragment
    // subpath = subpath.substr(0, subpath.find_first_of("?#"));
    // if (std::empty(subpath) || subpath.back() == '/')
    // {
    //     subpath += "index.html";
    // }
    // if (subpath.find("..") != std::string::npos)
    // {
    //     send_simple_response(req, HTTP_NOTFOUND);
    //     return;
    // }
    // else
    // {
    //     std::string path = root_path + urlDecode(subpath);
    //     // std::cout << "\tpath: " << path << std::endl;
    //     // serve_file(req, path);
    //     serve_file2(req, path);
    // }
}

void OnRequest(evhttp_request *req, void *arg)
{
    if (req == nullptr || req->evcon == nullptr)
    {
        std::cout << "ERROR at handle_request()\n";
        return;
    }

    // struct evkeyvalq *headers = evhttp_request_get_input_headers(req);
    // struct evkeyval *header;
    // std::cout << "======Request Headers:" << std::endl;
    // for (header = headers->tqh_first; header; header = header->next.tqe_next) {
    //     std::cout << header->key << ": " << header->value << std::endl;
    // }

    evhttp_add_header(req->output_headers, "Access-Control-Allow-Origin", "*");

    enum evhttp_cmd_type request_method = evhttp_request_get_command(req);
    auto *OutBuf = evhttp_request_get_output_buffer(req);
    assert((char *)OutBuf != nullptr);
    if (request_method == EVHTTP_REQ_GET)
    {
        // 处理GET请求
        printf("Received a GET request for %s\n", req->uri);
    }
    else if (request_method == EVHTTP_REQ_POST)
    {
        // 处理POST请求
        printf("Received a POST request\n");
    }
    else
    {
        // 处理其他类型的请求
        printf("Received a request with method: %d\n", request_method);
        evhttp_add_header(req->output_headers, "Accept-Ranges", "bytes");
        evhttp_send_reply(req, 200, "OK", NULL);
    }
    if (request_method == EVHTTP_REQ_POST)
    {
        // 获取POST数据
        struct evbuffer *buf = evhttp_request_get_input_buffer(req);
        size_t len = evbuffer_get_length(buf);
        if (len > 0)
        {
            // 分配足够大的内存来存储POST数据
            char *post_data = (char *)malloc(len + 1);
            evbuffer_copyout(buf, post_data, len);
            post_data[len] = '\0'; // 添加字符串结束符
            // 打印POST数据
            std::cout << "Received POST data: " << (char *)post_data << std::endl;
            evbuffer_add_printf(OutBuf, "%s\n", post_data);
            evhttp_send_reply(req, HTTP_OK, "", OutBuf);
            free(post_data); // 释放内存
        }
        else
        {
            printf("No POST data received\n");
        }
    }

    if (request_method == EVHTTP_REQ_GET)
    {
        handle_web_client(req, nullptr);
        std::cout << "after handle_web_client()" << std::endl;
        // evbuffer_add_printf(OutBuf, "<html><body><center><h1>Hello World!</h1></center></body></html>\n");
        // evhttp_send_reply(req, HTTP_OK, "", OutBuf);
    }
}

SSL_CTX *create_ctx_with_cert(char const *cert, char const *key)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == nullptr)
    {
        return nullptr;
    }
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1)
    {
        printf("Couldn't set RPC SSL with cert file %s\n", cert);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1)
    {
        printf("Couldn't set RPC SSL with key file %s\n", key);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_check_private_key(ctx) == 1)
    {
        printf("Set RPC SSL context with certs\n");
        return ctx;
    }
    SSL_CTX_free(ctx);
    return nullptr;
}

bufferevent *SSL_bufferevent_cb(event_base *base, void *arg)
{
    bufferevent *ret = nullptr;
    SSL_CTX *ctx = static_cast<SSL_CTX *>(arg);
    SSL *ssl = SSL_new(ctx);
    bufferevent *bev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
    return bev;
}

void SetRoot(const std::string &_rootpath)
{
    root_path = _rootpath;
}



