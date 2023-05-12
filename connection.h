#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CCPC_RAW_FILE_REQUEST_EXISTS = 0,
    CCPC_RAW_FILE_REQUEST_ISDIR,
    CCPC_RAW_FILE_REQUEST_ISREADONLY,
    CCPC_RAW_FILE_REQUEST_GETSIZE,
    CCPC_RAW_FILE_REQUEST_GETDRIVE,
    CCPC_RAW_FILE_REQUEST_GETCAPACITY,
    CCPC_RAW_FILE_REQUEST_GETFREESPACE,
    CCPC_RAW_FILE_REQUEST_LIST,
    CCPC_RAW_FILE_REQUEST_ATTRIBUTES,
    CCPC_RAW_FILE_REQUEST_FIND,
    CCPC_RAW_FILE_REQUEST_MAKEDIR,
    CCPC_RAW_FILE_REQUEST_DELETE,
    CCPC_RAW_FILE_REQUEST_COPY,
    CCPC_RAW_FILE_REQUEST_MOVE
};

#define CCPC_RAW_FILE_REQUEST_OPEN         0x10
#define CCPC_RAW_FILE_REQUEST_OPEN_WRITE   0x01
#define CCPC_RAW_FILE_REQUEST_OPEN_APPEND  0x02
#define CCPC_RAW_FILE_REQUEST_OPEN_BINARY  0x04

typedef union file_request_result {
    uint8_t boolRes;
    uint32_t intRes;
    const char * strRes;
    struct {
        uint32_t size;
        const char ** list;
    } listRes;
    struct __attribute__((__packed__)) {
        uint32_t size;
        uint64_t created;
        uint64_t modified;
        uint8_t isDir;
        uint8_t isReadOnly;
        uint8_t err;
        uint8_t reserved;
    } attributesRes;
} file_request_result_t;

extern int connectToServer(const char * url, int id);
extern void disconnectFromServer();
extern file_request_result_t sendFileRequest(uint8_t type, const char * path, const char * path2);
extern size_t readFile(const char * path, int binary, uint8_t ** buf);
extern const char * writeFile(const char * path, int binary, int append, const uint8_t * buf, uint32_t size);

#ifdef __cplusplus
}
#endif