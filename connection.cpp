#include <condition_variable>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <Poco/Base64Decoder.h>
#include <Poco/Base64Encoder.h>
#include <Poco/Checksum.h>
#include <Poco/URI.h>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/WebSocket.h>
#include "connection.h"

enum {
    CCPC_RAW_TERMINAL_DATA = 0,
    CCPC_RAW_KEY_DATA,
    CCPC_RAW_MOUSE_DATA,
    CCPC_RAW_EVENT_DATA,
    CCPC_RAW_TERMINAL_CHANGE,
    CCPC_RAW_MESSAGE_DATA,
    CCPC_RAW_FEATURE_FLAGS,
    CCPC_RAW_FILE_REQUEST,
    CCPC_RAW_FILE_RESPONSE,
    CCPC_RAW_FILE_DATA
};

#define CCPC_RAW_FEATURE_FLAG_BINARY_CHECKSUM        0x0001
#define CCPC_RAW_FEATURE_FLAG_FILESYSTEM_SUPPORT     0x0002
#define CCPC_RAW_FEATURE_FLAG_SEND_ALL_WINDOWS       0x0004
#define CCPC_RAW_FEATURE_FLAG_HAS_EXTENDED_FEATURES  0x8000

using namespace Poco::Net;

struct RequestData {
    std::mutex lock;
    std::condition_variable cv;
    file_request_result_t res;
    uint8_t * data;
    uint32_t size;
    uint8_t status = 0; // 0 = free, 1 = waiting, 2 = success, 3 = error
};

static uint16_t supportedFeatures = 0;
static uint32_t supportedExtendedFeatures = 0;
static bool isVersion1_1 = false;
static std::string fileWriteRequests[256];
static HTTPClientSession * connection = NULL;
static WebSocket * websocket = NULL;
static std::mutex websocketLock;
static bool exiting = false;
static bool isOpen = true;
static std::thread * inputThread = NULL;
static RequestData requests[256];
static uint8_t nextRequest = 0;
static int computerID = 0;

static std::string b64encode(const std::string& orig) {
    std::stringstream ss;
    Poco::Base64Encoder enc(ss);
    enc.write(orig.c_str(), orig.size());
    enc.close();
    return ss.str();
}

static std::string b64decode(const std::string& orig) {
    std::stringstream ss;
    std::stringstream out(orig);
    Poco::Base64Decoder dec(out);
    std::copy(std::istreambuf_iterator<char>(dec), std::istreambuf_iterator<char>(), std::ostreambuf_iterator<char>(ss));
    return ss.str();
}

static void rawWriter(const std::string& data) {
    //fprintf(stderr, "> %s", data.c_str());
    try {
        std::lock_guard<std::mutex> lock(websocketLock);
        websocket->sendFrame(data.c_str(), data.size());
    } catch (NetException& e) {
        fprintf(stderr, "Error sending: %s\n", e.message().c_str());
        //isOpen = false;
    }
}

static void sendRawData(const uint8_t type, const uint8_t id, const std::function<void(std::ostream&)>& callback) {
    std::stringstream output;
    output.put(type);
    output.put(id);
    callback(output);
    std::string str = b64encode(output.str());
    str.erase(std::remove_if(str.begin(), str.end(), [](char c)->bool {return c == '\n' || c == '\r'; }), str.end());
    Poco::Checksum chk;
    if (/*type != CCPC_RAW_FEATURE_FLAGS &&*/ (supportedFeatures & CCPC_RAW_FEATURE_FLAG_BINARY_CHECKSUM)) chk.update(output.str());
    else chk.update(str);
    const uint32_t sum = chk.checksum();
    char tmpdata[21];
    if (str.length() > 65535) {
        if (isVersion1_1) {
            snprintf(tmpdata, 21, "%012zX%08x", str.length(), sum);
            rawWriter("!CPD" + std::string(tmpdata, 12) + str + std::string(tmpdata + 12, 8) + "\n");
        } else fprintf(stderr, "Attempted to send raw packet that's too large to a client that doesn't support large packets (%zu bytes); dropping packet.", str.length());
    } else {
        snprintf(tmpdata, 13, "%04X%08x", (unsigned)str.length(), sum);
        rawWriter("!CPC" + std::string(tmpdata, 4) + str + std::string(tmpdata + 4, 8) + "\n");
    }
}

int connectToServer(const char * url, int id) {
    Poco::URI uri;
    try {
        uri = Poco::URI(url);
    } catch (Poco::SyntaxException &e) {
        return EINVAL;
    }
    if (uri.getHost() == "localhost") uri.setHost("127.0.0.1");
    HTTPClientSession * cs;
    if (uri.getScheme() == "ws") cs = new HTTPClientSession(uri.getHost(), uri.getPort());
    else if (uri.getScheme() == "wss") {
        Context::Ptr ctx = new Context(Context::CLIENT_USE, "", Context::VERIFY_RELAXED, 9, true, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
        cs = new HTTPSClientSession(uri.getHost(), uri.getPort(), ctx);
    } else {
        return EINVAL;
    }
    if (uri.getPathAndQuery().empty()) uri.setPath("/");
    HTTPRequest request(HTTPRequest::HTTP_GET, uri.getPathAndQuery(), HTTPMessage::HTTP_1_1);
    request.add("User-Agent", "ccfs/1.0");
    request.add("Accept-Charset", "UTF-8");
    HTTPResponse response;
    WebSocket* ws;
    try {
        ws = new WebSocket(*cs, request, response);
    } catch (Poco::Exception &e) {
        return ECONNREFUSED;
    } catch (std::exception &e) {
        return EIO;
    }
    ws->setReceiveTimeout(Poco::Timespan(1, 0));
#if POCO_VERSION >= 0x01090100
    ws->setMaxPayloadSize(65536);
#endif
    connection = cs; websocket = ws;
    isOpen = true; computerID = id;
    inputThread = new std::thread([](){
        exiting = false;
        std::string data;
        while (!exiting) {
            char buf[65536];
            while (isOpen) {
                int flags = 0;
                int res;
                try {
                    res = websocket->receiveFrame(buf, 65536, flags);
                    if (res == 0 && flags == 0) {
                        isOpen = false;
                        break;
                    } else if (res < 0) continue;
                } catch (Poco::TimeoutException &e) {
                    continue;
                } catch (NetException &e) {
                    isOpen = false;
                    break;
                }
                if ((flags & 0x0f) == WebSocket::FRAME_OP_CLOSE) {
                    isOpen = false;
                    break;
                } else if ((flags & 0x0f) == WebSocket::FRAME_OP_PING) {
                    websocket->sendFrame(buf, res, WebSocket::FRAME_FLAG_FIN | WebSocket::FRAME_OP_PONG);
                } else {
                    data += std::string(buf, res);
                    break;
                }
            }
            if (data.empty()) {
                exiting = true;
                break;
            }
            //fprintf(stderr, "< %s", data.c_str());
            long sizen;
            size_t off = 8;
            if (data[3] == 'C') sizen = std::stol(data.substr(4, 4), nullptr, 16);
            else if (data[3] == 'D') {sizen = std::stol(data.substr(4, 12), nullptr, 16); off = 16;}
            else continue;
            if (data.size() < sizen + off + 8) continue;
            std::string ddata = b64decode(data.substr(off, sizen));
            Poco::Checksum chk;
            if (supportedFeatures & CCPC_RAW_FEATURE_FLAG_BINARY_CHECKSUM) chk.update(ddata);
            else chk.update(data.substr(off, sizen));
            if (chk.checksum() != std::stoul(data.substr(sizen + off, 8), NULL, 16)) {
                fprintf(stderr, "Invalid checksum: expected %08X, got %08lX\n", chk.checksum(), std::stoul(data.substr(sizen + off, 8), NULL, 16));
                data.clear();
                continue;
            }
            std::stringstream in(ddata);
            uint8_t type = (uint8_t)in.get();
            uint8_t id = (uint8_t)in.get();
            //printf("Message type %d for %d\n", type, id);
            switch (type) {
            case CCPC_RAW_TERMINAL_CHANGE: {
                uint8_t quit = (uint8_t)in.get();
                if (quit == 1) {
                    break;
                } else if (quit == 2) {
                    exiting = true;
                    return;
                }
                break;
            } case CCPC_RAW_FEATURE_FLAGS: {
                uint16_t f = 0;
                uint32_t ef = 0;
                in.read((char*)&f, 2);
                if (f & CCPC_RAW_FEATURE_FLAG_HAS_EXTENDED_FEATURES) in.read((char*)&ef, 4);
                supportedFeatures = f & (CCPC_RAW_FEATURE_FLAG_BINARY_CHECKSUM | CCPC_RAW_FEATURE_FLAG_FILESYSTEM_SUPPORT | CCPC_RAW_FEATURE_FLAG_SEND_ALL_WINDOWS);
                supportedExtendedFeatures = ef & (0x00000000);
                break;
            } case CCPC_RAW_FILE_RESPONSE: {
                uint8_t type = in.get();
                uint8_t id = in.get();
                //printf("Response for %d (status %d)\n", id, requests[id].status);
                if (requests[id].status == 1) {
                    std::unique_lock<std::mutex> lock(requests[id].lock);
                    switch (type) {
                        case CCPC_RAW_FILE_REQUEST_MAKEDIR:
                        case CCPC_RAW_FILE_REQUEST_DELETE:
                        case CCPC_RAW_FILE_REQUEST_COPY:
                        case CCPC_RAW_FILE_REQUEST_MOVE:
                        case CCPC_RAW_FILE_REQUEST_OPEN: {
                            uint8_t f = in.get();
                            if (f) {
                                std::string msg(1, f);
                                while ((f = in.get())) msg += f;
                                requests[id].res.strRes = strdup(msg.c_str());
                            } else requests[id].res.strRes = NULL;
                            break;
                        }
                        case CCPC_RAW_FILE_REQUEST_EXISTS:
                        case CCPC_RAW_FILE_REQUEST_ISDIR:
                        case CCPC_RAW_FILE_REQUEST_ISREADONLY: {
                            requests[id].res.boolRes = in.get();
                            break;
                        }
                        case CCPC_RAW_FILE_REQUEST_GETSIZE:
                        case CCPC_RAW_FILE_REQUEST_GETCAPACITY:
                        case CCPC_RAW_FILE_REQUEST_GETFREESPACE: {
                            in.read((char*)&requests[id].res.intRes, 4);
                            break;
                        }
                        case CCPC_RAW_FILE_REQUEST_GETDRIVE: {
                            uint8_t f;
                            std::string msg;
                            while ((f = in.get())) msg += f;
                            requests[id].res.strRes = strdup(msg.c_str());
                            break;
                        }
                        case CCPC_RAW_FILE_REQUEST_LIST:
                        case CCPC_RAW_FILE_REQUEST_FIND: {
                            in.read((char*)&requests[id].res.listRes.size, 4);
                            if (requests[id].res.listRes.size != 0xFFFFFFFF) {
                                requests[id].res.listRes.list = (const char **)calloc(requests[id].res.listRes.size, sizeof(const char *));
                                for (uint32_t i = 0; i < requests[id].res.listRes.size; i++) {
                                    uint8_t f;
                                    std::string msg;
                                    while ((f = in.get())) msg += f;
                                    requests[id].res.listRes.list[i] = strdup(msg.c_str());
                                }
                            } else requests[id].res.listRes.list = NULL;
                            break;
                        }
                        case CCPC_RAW_FILE_REQUEST_ATTRIBUTES: {
                            in.read((char*)&requests[id].res.attributesRes, 24);
                            break;
                        }
                    }
                    requests[id].status = 2;
                    //printf("Notifying request %d\n", id);
                    requests[id].cv.notify_all();
                }
                break;
            } case CCPC_RAW_FILE_DATA: {
                uint8_t err = in.get();
                uint8_t id = in.get();
                if (requests[id].status == 1) {
                    std::unique_lock<std::mutex> lock(requests[id].lock);
                    in.read((char*)&requests[id].size, 4);
                    requests[id].data = (uint8_t*)malloc(requests[id].size);
                    in.read((char*)requests[id].data, requests[id].size);
                    requests[id].status = err ? 3 : 2;
                    requests[id].cv.notify_all();
                }
                break;
            }}
            data.clear();
            std::this_thread::yield();
        }
        for (int i = 0; i < 256; i++) {
            if (requests[i].status == 1) {
                std::unique_lock<std::mutex> lock(requests[i].lock);
                requests[i].status = 3;
                requests[i].cv.notify_all();
            }
        }
    });
    sendRawData(CCPC_RAW_FEATURE_FLAGS, 0, [](std::ostream& out) {
        uint16_t flags = CCPC_RAW_FEATURE_FLAG_BINARY_CHECKSUM | CCPC_RAW_FEATURE_FLAG_FILESYSTEM_SUPPORT;
        out.write((char*)&flags, 2);
    });
    while ((supportedFeatures & (CCPC_RAW_FEATURE_FLAG_BINARY_CHECKSUM | CCPC_RAW_FEATURE_FLAG_FILESYSTEM_SUPPORT)) != (CCPC_RAW_FEATURE_FLAG_BINARY_CHECKSUM | CCPC_RAW_FEATURE_FLAG_FILESYSTEM_SUPPORT)) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return 0;
}

void disconnectFromServer() {
    isOpen = false;
    inputThread->join();
    try {websocket->shutdown();} catch (...) {}
    delete inputThread;
    delete websocket;
    delete connection;
}

file_request_result_t sendFileRequest(uint8_t type, const char * path, const char * path2 = NULL) {
    if (!isOpen || exiting) {
        file_request_result_t res;
        switch (type) {
            case CCPC_RAW_FILE_REQUEST_MAKEDIR:
            case CCPC_RAW_FILE_REQUEST_DELETE:
            case CCPC_RAW_FILE_REQUEST_COPY:
            case CCPC_RAW_FILE_REQUEST_MOVE:
            case CCPC_RAW_FILE_REQUEST_GETDRIVE:
                res.strRes = strdup("Connection closed");
                break;
            case CCPC_RAW_FILE_REQUEST_EXISTS:
            case CCPC_RAW_FILE_REQUEST_ISDIR:
            case CCPC_RAW_FILE_REQUEST_ISREADONLY:
                res.boolRes = 2;
                break;
            case CCPC_RAW_FILE_REQUEST_GETSIZE:
            case CCPC_RAW_FILE_REQUEST_GETCAPACITY:
            case CCPC_RAW_FILE_REQUEST_GETFREESPACE:
                res.intRes = 0xFFFFFFFF;
                break;
            case CCPC_RAW_FILE_REQUEST_LIST:
            case CCPC_RAW_FILE_REQUEST_FIND:
                res.listRes.size = 0xFFFFFFFF;
                res.listRes.list = NULL;
                break;
            case CCPC_RAW_FILE_REQUEST_ATTRIBUTES:
                res.attributesRes.err = 2;
                break;
        }
        return res;
    }
    int id = nextRequest++;
    sendRawData(CCPC_RAW_FILE_REQUEST, computerID, [id, type, path, path2](std::ostream& out) {
        out.put(type);
        out.put(id);
        out.write(path, strlen(path) + 1);
        if (path2 != NULL) out.write(path2, strlen(path2) + 1);
    });
    std::unique_lock<std::mutex> lock(requests[id].lock);
    requests[id].status = 1;
    requests[id].cv.wait_for(lock, std::chrono::seconds(5));
    if (requests[id].status == 1) {
        requests[id].status = 0;
        file_request_result_t res;
        switch (type) {
            case CCPC_RAW_FILE_REQUEST_MAKEDIR:
            case CCPC_RAW_FILE_REQUEST_DELETE:
            case CCPC_RAW_FILE_REQUEST_COPY:
            case CCPC_RAW_FILE_REQUEST_MOVE:
            case CCPC_RAW_FILE_REQUEST_GETDRIVE:
                res.strRes = strdup("Connection timed out");
                break;
            case CCPC_RAW_FILE_REQUEST_EXISTS:
            case CCPC_RAW_FILE_REQUEST_ISDIR:
            case CCPC_RAW_FILE_REQUEST_ISREADONLY:
                res.boolRes = 2;
                break;
            case CCPC_RAW_FILE_REQUEST_GETSIZE:
            case CCPC_RAW_FILE_REQUEST_GETCAPACITY:
            case CCPC_RAW_FILE_REQUEST_GETFREESPACE:
                res.intRes = 0xFFFFFFFF;
                break;
            case CCPC_RAW_FILE_REQUEST_LIST:
            case CCPC_RAW_FILE_REQUEST_FIND:
                res.listRes.size = 0xFFFFFFFF;
                res.listRes.list = NULL;
                break;
            case CCPC_RAW_FILE_REQUEST_ATTRIBUTES:
                res.attributesRes.err = 2;
                break;
        }
        return res;
    }
    requests[id].status = 0;
    return requests[id].res;
}

size_t readFile(const char * path, int binary, uint8_t ** buf) {
    if (!isOpen || exiting) {
        *buf = (uint8_t*)strdup("Connection closed");
        return 0;
    }
    int id = nextRequest++;
    sendRawData(CCPC_RAW_FILE_REQUEST, computerID, [id, binary, path](std::ostream& out) {
        out.put(CCPC_RAW_FILE_REQUEST_OPEN | (binary ? CCPC_RAW_FILE_REQUEST_OPEN_BINARY : 0));
        out.put(id);
        out.write(path, strlen(path) + 1);
    });
    std::unique_lock<std::mutex> lock(requests[id].lock);
    requests[id].status = 1;
    requests[id].cv.wait_for(lock, std::chrono::seconds(5));
    if (requests[id].status == 1) {
        *buf = (uint8_t*)strdup("Connection timed out");
        return 0;
    }
    *buf = requests[id].data;
    size_t retval = requests[id].status == 2 ? requests[id].size : 0;
    requests[id].status = 0;
    return retval;
}

const char * writeFile(const char * path, int binary, int append, const uint8_t * buf, uint32_t size) {
    if (!isOpen || exiting) return strdup("Connection closed");
    int id = nextRequest++;
    sendRawData(CCPC_RAW_FILE_REQUEST, computerID, [id, binary, append, path](std::ostream& out) {
        out.put(CCPC_RAW_FILE_REQUEST_OPEN | CCPC_RAW_FILE_REQUEST_OPEN_WRITE | (binary ? CCPC_RAW_FILE_REQUEST_OPEN_BINARY : 0) | (append ? CCPC_RAW_FILE_REQUEST_OPEN_APPEND : 0));
        out.put(id);
        out.write(path, strlen(path) + 1);
    });
    sendRawData(CCPC_RAW_FILE_DATA, computerID, [id, buf, size](std::ostream& out) {
        out.put(0);
        out.put(id);
        out.write((char*)&size, 4);
        out.write((char*)buf, size);
    });
    std::unique_lock<std::mutex> lock(requests[id].lock);
    requests[id].status = 1;
    requests[id].cv.wait_for(lock, std::chrono::seconds(5));
    if (requests[id].status == 1) return strdup("Connection timed out");
    requests[id].status = 0;
    return requests[id].res.strRes;
}
