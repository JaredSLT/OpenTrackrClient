#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mswsock.h>
#include <process.h>
#define CLOSE closesocket
#define ERR WSAGetLastError()
#define INVALID_SOCK INVALID_SOCKET
#ifndef WSAID_MULTIPLE_RIO
static const GUID WSAID_MULTIPLE_RIO = {0x8509e081, 0x96dd, 0x4425, {0xb0,0x25,0x78,0x04,0xbb,0x43,0x09,0xd1}};
#endif
#ifndef SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER
#define SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER 0xc8000006L
#endif
typedef PVOID RIO_CQ;
typedef PVOID RIO_RQ;
typedef PVOID RIO_BUFID;
#define RIO_INVALID_CQ (RIO_CQ)0
#define RIO_INVALID_RQ (RIO_RQ)0
#define RIO_INVALID_BUFID (RIO_BUFID)0
#define RIO_CORRUPT_CQ 0xFFFFFFFF
typedef struct _RIO_BUF {
    RIO_BUFID BufferId;
    ULONG Offset;
    ULONG Length;
} RIO_BUF, *PRIO_BUF;
typedef struct _RIORESULT {
    LONG Status;
    ULONG BytesTransferred;
    UINT64 SocketContext;
    UINT64 RequestContext;
} RIORESULT, *PRIORESULT;
typedef enum _RIO_NOTIFICATION_COMPLETION_TYPE {
    RIO_EVENT_COMPLETION = 1,
    RIO_IOCP_COMPLETION = 2,
} RIO_NOTIFICATION_COMPLETION_TYPE, *PRIO_NOTIFICATION_COMPLETION_TYPE;
typedef struct _RIO_NOTIFICATION_COMPLETION {
    RIO_NOTIFICATION_COMPLETION_TYPE Type;
    union {
        struct {
            HANDLE EventHandle;
            BOOL NotifyReset;
        } Event;
        struct {
            HANDLE IocpHandle;
            ULONG_PTR CompletionKey;
            LPOVERLAPPED Overlapped;
        } Iocp;
    };
} RIO_NOTIFICATION_COMPLETION, *PRIO_NOTIFICATION_COMPLETION;
typedef BOOL (WINAPI *LPFN_RIOSEND)(RIO_RQ, PRIO_BUF, ULONG, DWORD, PVOID);
typedef BOOL (WINAPI *LPFN_RIORECEIVE)(RIO_RQ, PRIO_BUF, ULONG, DWORD, PVOID);
typedef BOOL (WINAPI *LPFN_RIONOTIFY)(RIO_CQ);
typedef ULONG (WINAPI *LPFN_RIODEQUEUECOMPLETION)(RIO_CQ, PRIORESULT, ULONG);
typedef RIO_CQ (WINAPI *LPFN_RIOCREATECOMPLETIONQUEUE)(DWORD, PRIO_NOTIFICATION_COMPLETION);
typedef RIO_RQ (WINAPI *LPFN_RIOCREATEREQUESTQUEUE)(SOCKET, ULONG, ULONG, ULONG, ULONG, RIO_CQ, RIO_CQ, PVOID);
typedef void (WINAPI *LPFN_RIOCLOSECOMPLETIONQUEUE)(RIO_CQ);
typedef RIO_BUFID (WINAPI *LPFN_RIOREGISTERBUFFER)(PCHAR, DWORD);
typedef void (WINAPI *LPFN_RIODEREGISTERBUFFER)(RIO_BUFID);
typedef BOOL (WINAPI *LPFN_RIORECEIVEEX)(RIO_RQ, PRIO_BUF, ULONG, PRIO_BUF, PRIO_BUF, PRIO_BUF, PRIO_BUF, DWORD, PVOID);
typedef BOOL (WINAPI *LPFN_RIOSENDEX)(RIO_RQ, PRIO_BUF, ULONG, PRIO_BUF, PRIO_BUF, PRIO_BUF, PRIO_BUF, DWORD, PVOID);
typedef BOOL (WINAPI *LPFN_RIORESIZECOMPLETIONQUEUE)(RIO_CQ, DWORD);
typedef BOOL (WINAPI *LPFN_RIORESIZEREQUESTQUEUE)(RIO_RQ, ULONG, ULONG);
typedef struct _RIO_EXTENSION_FUNCTION_TABLE {
    DWORD cbSize;
    LPFN_RIORECEIVE               RIOReceive;
    LPFN_RIORECEIVEEX             RIOReceiveEx;
    LPFN_RIOSEND                  RIOSend;
    LPFN_RIOSENDEX                RIOSendEx;
    LPFN_RIOCLOSECOMPLETIONQUEUE  RIOCloseCompletionQueue;
    LPFN_RIOCREATECOMPLETIONQUEUE RIOCreateCompletionQueue;
    LPFN_RIOCREATEREQUESTQUEUE    RIOCreateRequestQueue;
    LPFN_RIODEQUEUECOMPLETION     RIODequeueCompletion;
    LPFN_RIODEREGISTERBUFFER      RIODeregisterBuffer;
    LPFN_RIONOTIFY                RIONotify;
    LPFN_RIOREGISTERBUFFER        RIORegisterBuffer;
    LPFN_RIORESIZECOMPLETIONQUEUE RIOResizeCompletionQueue;
    LPFN_RIORESIZEREQUESTQUEUE    RIOResizeRequestQueue;
} RIO_EXTENSION_FUNCTION_TABLE, *PRIO_EXTENSION_FUNCTION_TABLE;
#define UDP_SEGMENT 103
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/event.h>
#include <pthread.h>
#define CLOSE close
#define ERR errno
#define INVALID_SOCK (-1)
#endif

#ifdef __linux__
#include <linux/filter.h>
#include <liburing.h>
#define SOL_UDP 17
#define UDP_SEGMENT 103
#endif

#ifdef __SSSE3__
#include <immintrin.h>
#endif

#ifdef __ARM_NEON
#include <arm_neon.h>
#endif

#ifdef __BIG_ENDIAN__
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) ((((uint64_t)htonl(x & 0xFFFFFFFFLL)) << 32) | htonl(x >> 32))
#define ntohll(x) ((((uint64_t)ntohl(x & 0xFFFFFFFFLL)) << 32) | ntohl(x >> 32))
#endif

#define PROTOCOL_ID 0x41727101980LL
#define CONNECT_ACTION 0
#define SCRAPE_ACTION 2
#define ERROR_ACTION 3
#define INITIAL_TIMEOUT 1000
#define MAX_RETRIES 5
#define TIMEOUT_MULTIPLIER 2
#define MAX_PER_REQUEST 74
#define MAX_TIMEOUT 64000
#define BUFSIZE 52428800LL

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#if defined(__linux__)
#define UDP_GSO_LEVEL SOL_UDP
#define UDP_GSO_OPTNAME UDP_SEGMENT
#endif

typedef struct __attribute__((aligned(64))) {
    char hex[41];
    uint8_t bin[20];
} InfoHash;

typedef struct __attribute__((aligned(16))) {
    uint32_t seeders;
    uint32_t completed;
    uint32_t leechers;
} Result;

#ifdef _WIN32
typedef struct {
    RIO_CQ queue;
    RIO_RQ request_queue;
    HANDLE event;
    RIO_BUFID send_buf_id;
    RIO_BUFID recv_buf_id;
    char *send_buffer;
    char *recv_buffer;
    size_t max_chunks;
} RioContext;
typedef RioContext* io_ctx_t;
static RIO_EXTENSION_FUNCTION_TABLE rio = {0};
static bool global_use_rio = false;
#elif defined(__linux__)
typedef struct {
    struct io_uring ring;
    char *send_buffer;
    char *recv_buffer;
    size_t max_chunks;
} IoUringContext;
typedef IoUringContext* io_ctx_t;
#else
typedef void* io_ctx_t;
#endif

static const int8_t hex_table[256] __attribute__((aligned(64))) = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static inline __attribute__((always_inline)) int hex_to_int_fast(unsigned char ch) {
    return hex_table[ch];
}

static inline __attribute__((always_inline)) int hex_to_bin_fast(const char* restrict hex, uint8_t* restrict bin) {
#if defined(__AVX512F__)
    __mmask64 load_mask = (1LL << 40) - 1;
    __m512i input = _mm512_maskz_loadu_epi8(load_mask, hex);
    __m512i input_lower = _mm512_or_si512(input, _mm512_set1_epi8(0x20));
    __m512i values = _mm512_sub_epi8(input_lower, _mm512_set1_epi8('0'));
    __mmask64 lt0 = _mm512_cmp_epi8_mask(values, _mm512_set1_epi8(0), _MM_CMPINT_LT);
    __mmask64 ge0 = ~lt0 & load_mask;
    __mmask64 le9 = _mm512_cmp_epi8_mask(values, _mm512_set1_epi8(10), _MM_CMPINT_LT);
    __mmask64 is_digit = ge0 & le9;
    __mmask64 lt_a = _mm512_cmp_epi8_mask(values, _mm512_set1_epi8('a' - '0'), _MM_CMPINT_LT);
    __mmask64 ge_a = ~lt_a & load_mask;
    __mmask64 le_f = _mm512_cmp_epi8_mask(values, _mm512_set1_epi8('f' - '0' + 1), _MM_CMPINT_LT);
    __mmask64 is_hex = ge_a & le_f;
    __mmask64 is_valid = is_digit | is_hex;
    __mmask64 invalid = _mm512_cmp_epi8_mask(is_valid, _mm512_setzero_si512(), _MM_CMPINT_EQ) & load_mask;
    if (invalid) return -1;
    __m512i alpha_adjust = _mm512_mask_blend_epi8(is_hex, _mm512_setzero_si512(), _mm512_set1_epi8('a' - '0' - 10));
    values = _mm512_sub_epi8(values, alpha_adjust);
    __m512i even_idx = _mm512_setr_epi8(0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
    __m512i odd_idx = _mm512_setr_epi8(1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
    __m512i even_values = _mm512_permutexvar_epi8(even_idx, values);
    __m512i odd_values = _mm512_permutexvar_epi8(odd_idx, values);
    __m512i high = _mm512_slli_epi8(even_values, 4);
    __m512i bytes = _mm512_or_si512(high, odd_values);
    _mm512_mask_storeu_epi8(bin, (1LL << 20) - 1, bytes);
#elif defined(__AVX2__)
    __m256i input = _mm256_loadu_si256((const __m256i *)hex);
    __m256i input_lower = _mm256_or_si256(input, _mm256_set1_epi8(0x20));
    __m256i values = _mm256_sub_epi8(input_lower, _mm256_set1_epi8('0'));
    __m256i lt0 = _mm256_cmpgt_epi8(_mm256_set1_epi8(0), values);
    __m256i ge0 = _mm256_xor_si256(lt0, _mm256_set1_epi8(-1));
    __m256i le9 = _mm256_cmpgt_epi8(_mm256_set1_epi8(10), values);
    __m256i is_digit = _mm256_and_si256(ge0, le9);
    __m256i lt_a = _mm256_cmpgt_epi8(_mm256_set1_epi8('a' - '0'), values);
    __m256i ge_a = _mm256_xor_si256(lt_a, _mm256_set1_epi8(-1));
    __m256i le_f = _mm256_cmpgt_epi8(_mm256_set1_epi8('f' - '0' + 1), values);
    __m256i is_hex = _mm256_and_si256(ge_a, le_f);
    __m256i is_valid = _mm256_or_si256(is_digit, is_hex);
    __m256i invalid = _mm256_cmpeq_epi8(is_valid, _mm256_setzero_si256());
    if (_mm256_movemask_epi8(invalid)) return -1;
    __m256i alpha_adjust = _mm256_and_si256(is_hex, _mm256_set1_epi8('a' - '0' - 10));
    values = _mm256_sub_epi8(values, alpha_adjust);
    __m128i values_low = _mm256_castsi256_si128(values);
    __m128i values_high = _mm256_extracti128_si256(values, 1);
    __m128i even_mask = _mm_setr_epi8(0, 2, 4, 6, 8, 10, 12, 14, -1, -1, -1, -1, -1, -1, -1, -1);
    __m128i odd_mask = _mm_setr_epi8(1, 3, 5, 7, 9, 11, 13, 15, -1, -1, -1, -1, -1, -1, -1, -1);
    __m128i high_low = _mm_slli_epi8(_mm_shuffle_epi8(values_low, even_mask), 4);
    __m128i bytes_low = _mm_or_si128(high_low, _mm_shuffle_epi8(values_low, odd_mask));
    _mm_storel_epi64((__m128i *)bin, bytes_low);
    __m128i high_high = _mm_slli_epi8(_mm_shuffle_epi8(values_high, even_mask), 4);
    __m128i bytes_high = _mm_or_si128(high_high, _mm_shuffle_epi8(values_high, odd_mask));
    _mm_storel_epi64((__m128i *)(bin + 8), bytes_high);
#elif defined(__ARM_NEON)
    for (int offset = 0; offset < 32; offset += 16) {
        uint8x16_t u_input = vld1q_u8((const uint8_t *)(hex + offset));
        int8x16_t input = vreinterpretq_s8_u8(u_input);
        int8x16_t input_lower = vorrq_s8(input, vdupq_s8(0x20));
        int8x16_t values = vsubq_s8(input_lower, vdupq_s8('0'));
        int8x16_t lt0 = vcltq_s8(values, vdupq_s8(0));
        int8x16_t ge0 = veorq_s8(lt0, vdupq_s8(-1));
        int8x16_t le9 = vcltq_s8(values, vdupq_s8(10));
        int8x16_t is_digit = vandq_s8(ge0, le9);
        int8x16_t lt_a = vcltq_s8(values, vdupq_s8('a' - '0'));
        int8x16_t ge_a = veorq_s8(lt_a, vdupq_s8(-1));
        int8x16_t le_f = vcltq_s8(values, vdupq_s8('f' - '0' + 1));
        int8x16_t is_hex = vandq_s8(ge_a, le_f);
        int8x16_t is_valid = vorrq_s8(is_digit, is_hex);
        int8_t min_valid = vminvq_s8(is_valid);
        if (min_valid == 0) return -1;
        int8x16_t alpha_adjust = vandq_s8(is_hex, vdupq_s8('a' - '0' - 10));
        values = vsubq_s8(values, alpha_adjust);
        int8x8_t even_mask = {0, 2, 4, 6, 8, 10, 12, 14};
        int8x8_t odd_mask = {1, 3, 5, 7, 9, 11, 13, 15};
        int8x8_t even = vtbl1_s8(vget_low_s8(values), even_mask);
        int8x8_t odd = vtbl1_s8(vget_low_s8(values), odd_mask);
        int8x8_t high = vshl_n_s8(even, 4);
        int8x8_t bytes = vorr_s8(high, odd);
        vst1_s8((int8_t *)(bin + (offset / 2)), bytes);
    }
#else
    for (int i = 0; i < 16; i++) {
        int high = hex_to_int_fast((unsigned char)hex[i << 1]);
        int low = hex_to_int_fast((unsigned char)hex[(i << 1) | 1]);
        if ((high | low) < 0) return -1;
        uint8_t h = (uint8_t)high;
        uint8_t l = (uint8_t)low;
        uint8_t byte;
        asm volatile (
            "shl $4, %0\n\t"
            "or %1, %0\n\t"
            : "=r" (byte)
            : "0" (h), "r" (l)
        );
        bin[i] = byte;
    }
#endif
#if defined(__ARM_NEON)
    {
        uint8x8_t u_input_last = vld1_u8((const uint8_t *)(hex + 32));
        int8x8_t input_lower_last = vorr_s8(vreinterpret_s8_u8(u_input_last), vdup_n_s8(0x20));
        int8x8_t values_last = vsub_s8(input_lower_last, vdup_n_s8('0'));
        int8x8_t lt0_last = vclt_s8(values_last, vdup_n_s8(0));
        int8x8_t ge0_last = veor_s8(lt0_last, vdup_n_s8(-1));
        int8x8_t le9_last = vclt_s8(values_last, vdup_n_s8(10));
        int8x8_t is_digit_last = vand_s8(ge0_last, le9_last);
        int8x8_t lt_a_last = vclt_s8(values_last, vdup_n_s8('a' - '0'));
        int8x8_t ge_a_last = veor_s8(lt_a_last, vdup_n_s8(-1));
        int8x8_t le_f_last = vclt_s8(values_last, vdup_n_s8('f' - '0' + 1));
        int8x8_t is_hex_last = vand_s8(ge_a_last, le_f_last);
        int8x8_t is_valid_last = vorr_s8(is_digit_last, is_hex_last);
        int8_t min_valid_last = vminv_s8(is_valid_last);
        if (min_valid_last == 0) return -1;
        int8x8_t alpha_adjust_last = vand_s8(is_hex_last, vdup_n_s8('a' - '0' - 10));
        values_last = vsub_s8(values_last, alpha_adjust_last);
        int8x8_t even_mask_last = {0, 2, 4, 6, 0, 0, 0, 0};
        int8x8_t odd_mask_last = {1, 3, 5, 7, 0, 0, 0, 0};
        int8x8_t even_last = vtbl1_s8(values_last, even_mask_last);
        int8x8_t odd_last = vtbl1_s8(values_last, odd_mask_last);
        int8x8_t high_last = vshl_n_s8(even_last, 4);
        int8x8_t bytes_last = vorr_s8(high_last, odd_last);
        *(uint32_t *)(bin + 16) = vget_lane_u32(vreinterpret_u32_s8(bytes_last), 0);
    }
#elif defined(__SSSE3__)
    {
        __m128i input_last = _mm_loadu_si128((const __m128i *)(hex + 32));
        __m128i input_lower_last = _mm_or_si128(input_last, _mm_set1_epi8(0x20));
        __m128i values_last = _mm_sub_epi8(input_lower_last, _mm_set1_epi8('0'));
        __m128i lt0_last = _mm_cmplt_epi8(values_last, _mm_set1_epi8(0));
        __m128i ge0_last = _mm_xor_si128(lt0_last, _mm_set1_epi8(-1));
        __m128i le9_last = _mm_cmplt_epi8(values_last, _mm_set1_epi8(10));
        __m128i is_digit_last = _mm_and_si128(ge0_last, le9_last);
        __m128i lt_a_last = _mm_cmplt_epi8(values_last, _mm_set1_epi8('a' - '0'));
        __m128i ge_a_last = _mm_xor_si128(lt_a_last, _mm_set1_epi8(-1));
        __m128i le_f_last = _mm_cmplt_epi8(values_last, _mm_set1_epi8('f' - '0' + 1));
        __m128i is_hex_last = _mm_and_si128(ge_a_last, le_f_last);
        __m128i is_valid_last = _mm_or_si128(is_digit_last, is_hex_last);
        __m128i invalid_last = _mm_cmpeq_epi8(is_valid_last, _mm_setzero_si128());
        if (_mm_movemask_epi8(invalid_last)) return -1;
        __m128i alpha_adjust_last = _mm_and_si128(is_hex_last, _mm_set1_epi8('a' - '0' - 10));
        values_last = _mm_sub_epi8(values_last, alpha_adjust_last);
        __m128i even_mask_last = _mm_setr_epi8(0, 2, 4, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1);
        __m128i odd_mask_last = _mm_setr_epi8(1, 3, 5, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1);
        __m128i high_last = _mm_slli_epi8(_mm_shuffle_epi8(values_last, even_mask_last), 4);
        __m128i bytes_last = _mm_or_si128(high_last, _mm_shuffle_epi8(values_last, odd_mask_last));
        _mm_storeu_si32((void *)(bin + 16), bytes_last);
    }
#else
    for (int i = 16; i < 20; i++) {
        int high = hex_to_int_fast((unsigned char)hex[i << 1]);
        int low = hex_to_int_fast((unsigned char)hex[(i << 1) | 1]);
        if ((high | low) < 0) return -1;
        uint8_t h = (uint8_t)high;
        uint8_t l = (uint8_t)low;
        uint8_t byte;
        asm volatile (
            "shl $4, %0\n\t"
            "or %1, %0\n\t"
            : "=r" (byte)
            : "0" (h), "r" (l)
        );
        bin[i] = byte;
    }
#endif
    return 0;
}

/* minimal ms time helper */
static inline long long now_ms(void) {
#ifdef _WIN32
    return (long long)GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)(tv.tv_sec * 1000LL + tv.tv_usec / 1000);
#endif
}

static int send_request(int sock, const void* buf, size_t len, bool use_io, io_ctx_t io_ctx) {
    int retries = 0;
    while (retries < MAX_RETRIES) {
#ifdef _WIN32
        if (use_io) {
            RioContext *ctx = (RioContext *)io_ctx;
            if (len > 131072) return -1; // fallback size, though dynamic now but for connect
            memcpy(ctx->send_buffer, buf, len);
            RIO_BUF rio_send = {ctx->send_buf_id, 0, (ULONG)len};
            if (!rio.RIOSend(ctx->request_queue, &rio_send, 1, 0, (PVOID)1ULL)) {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK || err == WSA_IO_PENDING) { retries++; continue; }
                return -1;
            }
            if (rio.RIONotify(ctx->queue) != 0) return -1;
            DWORD wait = WaitForSingleObject(ctx->event, INFINITE);
            if (wait != WAIT_OBJECT_0) return -1;
            RIORESULT results[1];
            ULONG num = rio.RIODequeueCompletion(ctx->queue, results, 1);
            if (num == 0 || num == RIO_CORRUPT_CQ) return -1;
            if (results[0].Status != 0 || results[0].BytesTransferred != (ULONG)len) return -1;
            return 0;
        } else {
            DWORD send_bytes = 0;
            WSABUF wsabuf = {(ULONG)len, (char*)buf};
            if (WSASend(sock, &wsabuf, 1, &send_bytes, 0, NULL, NULL) == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK) { retries++; continue; }
                return -1;
            }
            if (send_bytes == (DWORD)len) return 0;
            return -1;
        }
#elif defined(__linux__)
        if (use_io) {
            struct io_uring *ring = &((IoUringContext *)io_ctx)->ring;
            struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
            if (!sqe) {
                io_uring_submit(ring);
                sqe = io_uring_get_sqe(ring);
                if (!sqe) return -1;
            }
            io_uring_prep_send(sqe, sock, buf, len, MSG_CONFIRM);
            io_uring_sqe_set_data64(sqe, 1ULL);
            io_uring_submit(ring);
            struct io_uring_cqe *cqe;
            if (io_uring_wait_cqe(ring, &cqe) < 0) return -1;
            int res = cqe->res;
            io_uring_cqe_seen(ring, cqe);
            if (res == (int)len) return 0;
            if (res < 0 && (res == -EAGAIN || res == -EWOULDBLOCK)) {
                retries++;
                continue;
            }
            return -1;
        } else {
            ssize_t sent = send(sock, buf, len, MSG_CONFIRM);
            if (sent == (ssize_t)len) return 0;
            if (sent < 0 && (ERR == EAGAIN || ERR == EWOULDBLOCK)) {
                retries++;
                continue;
            }
            return -1;
        }
#else
        ssize_t sent = send(sock, buf, len, 0);
        if (sent == (ssize_t)len) return 0;
        if (sent < 0 && (ERR == EAGAIN || ERR == EWOULDBLOCK)) {
            retries++;
            continue;
        }
        return -1;
#endif
    }
    return -1;
}

static int recv_response(int sock, void* buf, size_t max_len, int timeout_ms, bool use_io, io_ctx_t io_ctx) {
#ifdef _WIN32
    if (use_io) {
        RioContext *ctx = (RioContext *)io_ctx;
        RIO_BUF rio_recv = {ctx->recv_buf_id, 0, (ULONG)max_len};
        if (!rio.RIOReceive(ctx->request_queue, &rio_recv, 1, 0, (PVOID)2ULL)) return -1;
        if (rio.RIONotify(ctx->queue) != 0) return -1;
        DWORD wait = WaitForSingleObject(ctx->event, (DWORD)timeout_ms);
        if (wait == WAIT_TIMEOUT) return 0;
        if (wait != WAIT_OBJECT_0) return -1;
        RIORESULT results[1];
        ULONG num = rio.RIODequeueCompletion(ctx->queue, results, 1);
        if (num == 0 || num == RIO_CORRUPT_CQ) return -1;
        if (results[0].Status != 0) return -1;
        if (results[0].RequestContext == 2ULL && results[0].BytesTransferred > 0) {
            memcpy(buf, ctx->recv_buffer, results[0].BytesTransferred);
            return (int)results[0].BytesTransferred;
        }
        return -1;
    } else {
        WSABUF wsabuf = {(ULONG)max_len, (char*)buf};
        DWORD recv_bytes = 0, flags = 0;
        OVERLAPPED ol = {0};
        ol.hEvent = WSACreateEvent();
        if (ol.hEvent == WSA_INVALID_EVENT) return -1;
        int rv = WSARecv(sock, &wsabuf, 1, &recv_bytes, &flags, &ol, NULL);
        if (rv == 0) {
            WSACloseEvent(ol.hEvent);
            return (int)recv_bytes;
        } else if (WSAGetLastError() == WSA_IO_PENDING) {
            DWORD wait = WSAWaitForMultipleEvents(1, &ol.hEvent, TRUE, (DWORD)timeout_ms, FALSE);
            if (wait == WAIT_TIMEOUT) {
                CancelIoEx((HANDLE)(intptr_t)sock, &ol);
                WSAGetOverlappedResult(sock, &ol, &recv_bytes, TRUE, &flags);
                WSACloseEvent(ol.hEvent);
                return 0;
            } else if (wait != WAIT_OBJECT_0) {
                WSACloseEvent(ol.hEvent);
                return -1;
            }
            if (WSAGetOverlappedResult(sock, &ol, &recv_bytes, FALSE, &flags)) {
                WSACloseEvent(ol.hEvent);
                return (int)recv_bytes;
            }
            WSACloseEvent(ol.hEvent);
            return -1;
        } else {
            WSACloseEvent(ol.hEvent);
            return -1;
        }
    }
#elif defined(__linux__)
    if (use_io) {
        struct io_uring *ring = &((IoUringContext *)io_ctx)->ring;
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        if (!sqe) { io_uring_submit(ring); sqe = io_uring_get_sqe(ring); }
        io_uring_prep_recv(sqe, sock, buf, max_len, 0);
        io_uring_sqe_set_data64(sqe, 2ULL);
        struct timespec ts = { .tv_sec = timeout_ms / 1000, .tv_nsec = (timeout_ms % 1000) * 1000000LL };
        sqe = io_uring_get_sqe(ring);
        io_uring_prep_timeout(sqe, &ts, 0, 0);
        io_uring_sqe_set_data64(sqe, 3ULL);
        io_uring_submit(ring);
        struct io_uring_cqe *cqe;
        if (io_uring_wait_cqe(ring, &cqe) < 0) return -1;
        uint64_t data = io_uring_cqe_get_data64(cqe);
        int res = cqe->res;
        io_uring_cqe_seen(ring, cqe);
        if (data == 3ULL) return 0;
        if (data == 2ULL) {
            if (res > 0) return res;
            return -1;
        }
        return -1;
    } else {
        struct pollfd fds = {.fd = sock, .events = POLLIN};
        int rv = poll(&fds, 1, timeout_ms);
        if (rv == 0) return 0;
        if (rv < 0) return -1;
        if (fds.revents & POLLIN) {
            ssize_t recv_size = recv(sock, buf, max_len, MSG_DONTWAIT);
            if (recv_size > 0) return (int)recv_size;
            return -1;
        }
        return -1;
    }
#elif defined(__APPLE__) || defined(__FreeBSD__)
    int kq = kqueue();
    if (kq == -1) return -1;
    struct kevent ev;
    EV_SET(&ev, sock, EVFILT_READ, EV_ADD | EV_ONESHOT, 0, 0, NULL);
    if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
        CLOSE(kq);
        return -1;
    }
    struct kevent event;
    struct timespec ts = {timeout_ms / 1000, (timeout_ms % 1000) * 1000000LL};
    int rv = kevent(kq, NULL, 0, &event, 1, &ts);
    CLOSE(kq);
    if (rv == 0) return 0;
    if (rv < 0) return -1;
    if (event.flags & EV_ERROR) return -1;
    ssize_t recv_size = recv(sock, buf, max_len, MSG_DONTWAIT);
    if (recv_size > 0) return (int)recv_size;
    return -1;
#else
    struct pollfd fds = {.fd = sock, .events = POLLIN};
    int rv = poll(&fds, 1, timeout_ms);
    if (rv == 0) return 0;
    if (rv < 0) return -1;
    if (fds.revents & POLLIN) {
        ssize_t recv_size = recv(sock, buf, max_len, MSG_DONTWAIT);
        if (recv_size > 0) return (int)recv_size;
        return -1;
    }
    return -1;
#endif
}

static inline __attribute__((always_inline)) int send_recv_with_retry(int sock, const void* send_buf, size_t send_len, void* recv_buf, size_t recv_len, int* timeout_ms, bool use_io, io_ctx_t io_ctx) {
    int retries = 0;
    while (retries < MAX_RETRIES) {
        if (send_request(sock, send_buf, send_len, use_io, io_ctx) < 0) {
            retries++;
            continue;
        }
        int resp_size = recv_response(sock, recv_buf, recv_len, *timeout_ms, use_io, io_ctx);
        if (resp_size > 0) return resp_size;
        if (resp_size == 0) { // timeout
            retries++;
            *timeout_ms = (*timeout_ms * TIMEOUT_MULTIPLIER) < MAX_TIMEOUT ? (*timeout_ms * TIMEOUT_MULTIPLIER) : MAX_TIMEOUT;
            continue;
        }
        return -1;
    }
    return -1;
}

static void setup_socket_options(int sock, size_t num_hashes) {
    char tos = 0x10;
    setsockopt(sock, IPPROTO_IP, IP_TOS, (const void*)&tos, sizeof(tos));
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void*)&reuse, sizeof(reuse));
#ifndef _WIN32
    int reuseport = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&reuseport, sizeof(reuseport));
    int priority = 6;
    setsockopt(sock, SOL_SOCKET, SO_PRIORITY, (const void*)&priority, sizeof(priority));
#endif
    long long bufsize = BUFSIZE + num_hashes * 512LL;
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    bufsize = (long long)(bufsize * 1.15);
#endif
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const void*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const void*)&bufsize, sizeof(bufsize));
#ifdef __linux__
    int no_check = 1, busy_poll = 50, mtu_opt = IP_PMTUDISC_DO;
    setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, (const void*)&no_check, sizeof(no_check));
    setsockopt(sock, SOL_SOCKET, SO_BUSY_POLL, (const void*)&busy_poll, sizeof(busy_poll));
    setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, (const void*)&mtu_opt, sizeof(mtu_opt));
    struct sock_filter filter[] = {
        { 0x28, 0, 0, 0x0000000c }, { 0x15, 0, 7, 0x00000800 }, { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 5, 0x00000011 }, { 0x20, 0, 0, 0x0000001a }, { 0x15, 0, 3, 0x5d9ed55c },
        { 0x28, 0, 0, 0x00000022 }, { 0x15, 0, 1, 0x00000539 }, { 0x6, 0, 0, 0x0000ffff }, { 0x6, 0, 0, 0x00000000 },
    };
    struct sock_fprog prog = { .len = sizeof(filter) / sizeof(filter[0]), .filter = filter };
    setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
#endif
    int dontfrag = 1;
#ifdef _WIN32
    setsockopt(sock, IPPROTO_IP, IP_DONTFRAGMENT, (const void*)&dontfrag, sizeof(dontfrag));
#else
    setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, (const void*)&dontfrag, sizeof(dontfrag));
#endif
#if defined(UDP_GSO_OPTNAME)
    int gso_size = 1472;
    setsockopt(sock, UDP_GSO_LEVEL, UDP_GSO_OPTNAME, (const void*)&gso_size, sizeof(gso_size));
#endif
    int recvtos = 1;
    setsockopt(sock, IPPROTO_IP, IP_RECVTOS, (const void*)&recvtos, sizeof(recvtos));
}

int main(int argc, char* argv[]) {
    long long start_ms = now_ms();

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) return 1;
    SOCKET temp_sock = WSASocket(AF_INET, SOCK_DGRAM, 0, NULL, 0, 0);
    if (temp_sock != INVALID_SOCKET) {
        GUID functionTableId = WSAID_MULTIPLE_RIO;
        DWORD rio_bytes = 0;
        rio.cbSize = sizeof(rio);
        if (WSAIoctl(temp_sock, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, &functionTableId, sizeof(GUID), &rio, sizeof(rio), &rio_bytes, NULL, NULL) == 0) {
            global_use_rio = true;
        }
        closesocket(temp_sock);
    }
#endif

    if (unlikely(argc < 2)) {
        fprintf(stderr, "Usage: %s [-v] [-f <file>] [info_hash_hex1] [info_hash_hex2] ...\n", argv[0]);
        return 1;
    }

    int verbose = 0; /* only used to decide printing execution time */

    InfoHash* hashes = malloc(128 * sizeof(InfoHash));
    if (unlikely(!hashes)) return 1;
    size_t num_hashes = 0, capacity = 128;
    int arg_idx = 1;
    while (arg_idx < argc) {
        if (strcmp(argv[arg_idx], "-v") == 0) {
            verbose = 1;
            arg_idx++;
            continue;
        }
        if (strcmp(argv[arg_idx], "-f") == 0) {
            arg_idx++;
            if (unlikely(arg_idx >= argc)) { fprintf(stderr, "Missing file after -f\n"); free(hashes); return 1; }
            FILE* fp = fopen(argv[arg_idx], "r");
            if (unlikely(!fp)) { perror("fopen"); free(hashes); return 1; }
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                char* start = line;
                while (*start == ' ' || *start == '\t') start++;
                size_t len = strlen(start);
                while (len > 0 && (start[len-1] == ' ' || start[len-1] == '\t' || start[len-1] == '\n' || start[len-1] == '\r')) start[--len] = '\0';
                if (len != 40) continue;
                if (unlikely(num_hashes >= capacity)) {
                    capacity <<= 1;
                    InfoHash* new_hashes = realloc(hashes, capacity * sizeof(InfoHash));
                    if (unlikely(!new_hashes)) { free(hashes); fclose(fp); return 1; }
                    hashes = new_hashes;
                }
                memcpy(hashes[num_hashes].hex, start, 40);
                hashes[num_hashes].hex[40] = '\0';
                if (likely(hex_to_bin_fast(start, hashes[num_hashes].bin) >= 0)) num_hashes++;
            }
            fclose(fp);
            arg_idx++;
        } else {
            const char* hex = argv[arg_idx];
            if (strlen(hex) == 40) {
                if (unlikely(num_hashes >= capacity)) {
                    capacity <<= 1;
                    InfoHash* new_hashes = realloc(hashes, capacity * sizeof(InfoHash));
                    if (unlikely(!new_hashes)) { free(hashes); return 1; }
                    hashes = new_hashes;
                }
                memcpy(hashes[num_hashes].hex, hex, 40);
                hashes[num_hashes].hex[40] = '\0';
                if (likely(hex_to_bin_fast(hex, hashes[num_hashes].bin) >= 0)) num_hashes++;
            }
            arg_idx++;
        }
    }

    if (unlikely(num_hashes == 0)) { fprintf(stderr, "No valid hashes provided\n"); free(hashes); return 1; }

    size_t max_chunks = (num_hashes + MAX_PER_REQUEST - 1) / MAX_PER_REQUEST;
    const size_t max_req_len = 16 + 20 * MAX_PER_REQUEST;
    const size_t max_resp_len = 8 + 12 * MAX_PER_REQUEST;

    struct sockaddr_in servaddr = { .sin_family = AF_INET, .sin_port = htons(1337) };
    inet_pton(AF_INET, "93.158.213.92", &servaddr.sin_addr);

#ifdef _WIN32
    DWORD flags = WSA_FLAG_OVERLAPPED;
    if (global_use_rio) flags |= WSA_FLAG_REGISTERED_IO;
    SOCKET sock = WSASocket(AF_INET, SOCK_DGRAM, 0, NULL, 0, flags);
#else
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
#endif
    if (unlikely(sock == INVALID_SOCK)) { free(hashes); return 1; }

#ifdef _WIN32
    RioContext rio_ctx = {0};
    bool use_io = global_use_rio;
    if (use_io) {
        rio_ctx.event = WSACreateEvent();
        if (rio_ctx.event != WSA_INVALID_EVENT) {
            RIO_NOTIFICATION_COMPLETION completionType = { .Type = RIO_EVENT_COMPLETION, .Event = { .EventHandle = rio_ctx.event, .NotifyReset = TRUE } };
            rio_ctx.queue = rio.RIOCreateCompletionQueue(256, &completionType);
            if (rio_ctx.queue != RIO_INVALID_CQ) {
                rio_ctx.request_queue = rio.RIOCreateRequestQueue(sock, 200, 1, 200, 1, rio_ctx.queue, rio_ctx.queue, NULL);
                if (rio_ctx.request_queue != RIO_INVALID_RQ) {
                    rio_ctx.max_chunks = max_chunks;
                    rio_ctx.send_buffer = malloc(max_chunks * max_req_len);
                    rio_ctx.recv_buffer = malloc(max_chunks * max_resp_len);
                    if (rio_ctx.send_buffer && rio_ctx.recv_buffer) {
                        rio_ctx.send_buf_id = rio.RIORegisterBuffer(rio_ctx.send_buffer, (DWORD)(max_chunks * max_req_len));
                        rio_ctx.recv_buf_id = rio.RIORegisterBuffer(rio_ctx.recv_buffer, (DWORD)(max_chunks * max_resp_len));
                        if (rio_ctx.send_buf_id == RIO_INVALID_BUFID || rio_ctx.recv_buf_id == RIO_INVALID_BUFID) use_io = false;
                    } else use_io = false;
                } else use_io = false;
            } else use_io = false;
        } else use_io = false;
        if (!use_io) {
            if (rio_ctx.send_buffer) free(rio_ctx.send_buffer);
            if (rio_ctx.recv_buffer) free(rio_ctx.recv_buffer);
            if (rio_ctx.queue != RIO_INVALID_CQ) rio.RIOCloseCompletionQueue(rio_ctx.queue);
            if (rio_ctx.event != WSA_INVALID_EVENT) WSACloseEvent(rio_ctx.event);
            if (rio_ctx.send_buf_id != RIO_INVALID_BUFID) rio.RIODeregisterBuffer(rio_ctx.send_buf_id);
            if (rio_ctx.recv_buf_id != RIO_INVALID_BUFID) rio.RIODeregisterBuffer(rio_ctx.recv_buf_id);
        }
    }
    io_ctx_t io_ctx = use_io ? &rio_ctx : NULL;
#elif defined(__linux__)
    IoUringContext iouring_ctx = {0};
    bool use_io = (io_uring_queue_init(128, &iouring_ctx.ring, IORING_SETUP_IOPOLL) >= 0);
    if (!use_io) {
        use_io = (io_uring_queue_init(128, &iouring_ctx.ring, 0) >= 0);
    }
    if (use_io) {
        iouring_ctx.max_chunks = max_chunks;
        iouring_ctx.send_buffer = malloc(max_chunks * max_req_len);
        iouring_ctx.recv_buffer = malloc(max_chunks * max_resp_len);
        if (!iouring_ctx.send_buffer || !iouring_ctx.recv_buffer) {
            free(iouring_ctx.send_buffer);
            free(iouring_ctx.recv_buffer);
            use_io = false;
            io_uring_queue_exit(&iouring_ctx.ring);
        }
    }
    io_ctx_t io_ctx = use_io ? &iouring_ctx : NULL;
#else
    bool use_io = false;
    io_ctx_t io_ctx = NULL;
#endif

    setup_socket_options(sock, num_hashes);

#ifdef _WIN32
    DWORD connreset = FALSE, bytes = 0;
    WSAIoctl(sock, SIO_UDP_CONNRESET, &connreset, sizeof(connreset), NULL, 0, &bytes, NULL, NULL);
    u_long nonblock = 1;
    ioctlsocket(sock, FIONBIO, &nonblock);
#else
    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
#endif

    if (connect(sock, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
#ifdef _WIN32
        if (use_io) {
            free(rio_ctx.send_buffer);
            free(rio_ctx.recv_buffer);
            rio.RIOCloseCompletionQueue(rio_ctx.queue);
            WSACloseEvent(rio_ctx.event);
            rio.RIODeregisterBuffer(rio_ctx.send_buf_id);
            rio.RIODeregisterBuffer(rio_ctx.recv_buf_id);
        }
#elif defined(__linux__)
        if (use_io) {
            free(iouring_ctx.send_buffer);
            free(iouring_ctx.recv_buffer);
            io_uring_queue_exit(&iouring_ctx.ring);
        }
#endif
        CLOSE(sock);
        free(hashes);
        return 1;
    }

#ifdef _WIN32
    srand((unsigned)time(NULL) ^ GetCurrentProcessId());
#else
    srand((unsigned)time(NULL) ^ getpid());
#endif

    uint8_t connect_req[16];
    *(uint64_t*)(connect_req) = htonll(PROTOCOL_ID);
    *(uint32_t*)(connect_req + 8) = htonl(CONNECT_ACTION);
    uint32_t trans_id_connect = rand();
    *(uint32_t*)(connect_req + 12) = htonl(trans_id_connect);
    uint8_t connect_resp[16];
    int timeout_ms = INITIAL_TIMEOUT;

    long long connect_start_ms = now_ms();
    ssize_t resp_size = send_recv_with_retry(sock, connect_req, sizeof(connect_req), connect_resp, sizeof(connect_resp), &timeout_ms, use_io,
        io_ctx
    );
    long long connect_end_ms = now_ms();

    if (unlikely(resp_size < 16 || ntohl(*(uint32_t*)(connect_resp)) != CONNECT_ACTION || ntohl(*(uint32_t*)(connect_resp + 4)) != trans_id_connect)) {
#ifdef _WIN32
        if (use_io) {
            free(rio_ctx.send_buffer);
            free(rio_ctx.recv_buffer);
            rio.RIOCloseCompletionQueue(rio_ctx.queue);
            WSACloseEvent(rio_ctx.event);
            rio.RIODeregisterBuffer(rio_ctx.send_buf_id);
            rio.RIODeregisterBuffer(rio_ctx.recv_buf_id);
        }
#elif defined(__linux__)
        if (use_io) {
            free(iouring_ctx.send_buffer);
            free(iouring_ctx.recv_buffer);
            io_uring_queue_exit(&iouring_ctx.ring);
        }
#endif
        CLOSE(sock);
        free(hashes);
        return 1;
    }

    double rtt_sec = (connect_end_ms - connect_start_ms) / 1000.0;
    int scrape_timeout_ms = (int)(rtt_sec * 2000);
    if (scrape_timeout_ms < 1000) scrape_timeout_ms = 1000;

    uint64_t connection_id = ntohll(*(uint64_t*)(connect_resp + 8));
    size_t max_per_request = MAX_PER_REQUEST;
    size_t num_chunks = max_chunks; // already computed

    Result *results = malloc(num_hashes * sizeof(Result));
    if (unlikely(!results)) {
#ifdef _WIN32
        if (use_io) {
            free(rio_ctx.send_buffer);
            free(rio_ctx.recv_buffer);
            rio.RIOCloseCompletionQueue(rio_ctx.queue);
            WSACloseEvent(rio_ctx.event);
            rio.RIODeregisterBuffer(rio_ctx.send_buf_id);
            rio.RIODeregisterBuffer(rio_ctx.recv_buf_id);
        }
#elif defined(__linux__)
        if (use_io) {
            free(iouring_ctx.send_buffer);
            free(iouring_ctx.recv_buffer);
            io_uring_queue_exit(&iouring_ctx.ring);
        }
#endif
        CLOSE(sock);
        free(hashes);
        return 1;
    }
    memset(results, 0, num_hashes * sizeof(Result));

    struct Pending {
        uint32_t trans_id;
        size_t start;
        size_t count;
        bool done;
    };

    struct Pending *pendings = malloc(num_chunks * sizeof(struct Pending));
    if (unlikely(!pendings)) {
        free(results);
#ifdef _WIN32
        if (use_io) {
            free(rio_ctx.send_buffer);
            free(rio_ctx.recv_buffer);
            rio.RIOCloseCompletionQueue(rio_ctx.queue);
            WSACloseEvent(rio_ctx.event);
            rio.RIODeregisterBuffer(rio_ctx.send_buf_id);
            rio.RIODeregisterBuffer(rio_ctx.recv_buf_id);
        }
#elif defined(__linux__)
        if (use_io) {
            free(iouring_ctx.send_buffer);
            free(iouring_ctx.recv_buffer);
            io_uring_queue_exit(&iouring_ctx.ring);
        }
#endif
        CLOSE(sock);
        free(hashes);
        return 1;
    }
    for (size_t ch = 0; ch < num_chunks; ch++) {
        pendings[ch].start = ch * max_per_request;
        pendings[ch].count = (num_hashes - pendings[ch].start < max_per_request) ? num_hashes - pendings[ch].start : max_per_request;
        pendings[ch].done = false;
    }

    int current_timeout = scrape_timeout_ms;
    int global_retries = 0;
    while (global_retries < MAX_RETRIES) {
        int outstanding = 0;
        for (size_t ch = 0; ch < num_chunks; ch++) {
            if (!pendings[ch].done) outstanding++;
        }
        // Send all pending requests
        if (use_io) {
            // Build requests in send_buffer
            for (size_t ch = 0; ch < num_chunks; ch++) {
                if (pendings[ch].done) continue;
                pendings[ch].trans_id = rand();
                char *req = ((RioContext *)io_ctx)->send_buffer + ch * max_req_len; // works for both Win/Linux as io_ctx
                *(uint64_t *)req = htonll(connection_id);
                *(uint32_t *)(req + 8) = htonl(SCRAPE_ACTION);
                *(uint32_t *)(req + 12) = htonl(pendings[ch].trans_id);
                for (size_t j = 0; j < pendings[ch].count; j++) {
                    const uint8_t *src = hashes[pendings[ch].start + j].bin;
                    uint8_t *dst = (uint8_t *)(req + 16 + 20 * j);
                    asm volatile (
                        "movdqu (%1), %%xmm0\n\t"
                        "movdqu %%xmm0, (%0)\n\t"
                        "movl 16(%1), %%eax\n\t"
                        "movl %%eax, 16(%0)\n\t"
                        :
                        : "r" (dst), "r" (src)
                        : "memory", "xmm0", "eax"
                    );
                }
            }
#ifdef _WIN32
            // Post all sends
            for (size_t ch = 0; ch < num_chunks; ch++) {
                if (pendings[ch].done) continue;
                ULONG req_len = 16 + 20 * pendings[ch].count;
                RIO_BUF rio_send = {rio_ctx.send_buf_id, (ULONG)(ch * max_req_len), req_len};
                rio.RIOSend(rio_ctx.request_queue, &rio_send, 1, 0, (PVOID)(ch | (1ULL << 32)));
            }
            // Post all receives
            for (size_t ch = 0; ch < num_chunks; ch++) {
                if (pendings[ch].done) continue;
                RIO_BUF rio_recv = {rio_ctx.recv_buf_id, (ULONG)(ch * max_resp_len), (ULONG)max_resp_len};
                rio.RIOReceive(rio_ctx.request_queue, &rio_recv, 1, 0, (PVOID)(ch | (2ULL << 32)));
            }
            rio.RIONotify(rio_ctx.queue);
            DWORD wait = WaitForSingleObject(rio_ctx.event, (DWORD)current_timeout);
            if (wait == WAIT_OBJECT_0) {
                RIORESULT *rio_results = malloc((num_chunks * 2) * sizeof(RIORESULT));
                if (rio_results) {
                    ULONG num = rio.RIODequeueCompletion(rio_ctx.queue, rio_results, (ULONG)(num_chunks * 2));
                    for (ULONG i = 0; i < num; i++) {
                        if (rio_results[i].Status != 0) continue;
                        uint64_t context = rio_results[i].RequestContext;
                        size_t ch = (size_t)(context & 0xFFFFFFFF);
                        if ((context >> 32) == 2 && rio_results[i].BytesTransferred > 0) {
                            char *resp = rio_ctx.recv_buffer + ch * max_resp_len;
                            uint32_t action = ntohl(*(uint32_t *)resp);
                            uint32_t trans_id = ntohl(*(uint32_t *)(resp + 4));
                            if (action == SCRAPE_ACTION && trans_id == pendings[ch].trans_id) {
                                const char *src = resp + 8;
                                Result *r = &results[pendings[ch].start];
                                size_t count = pendings[ch].count;
                                size_t j = 0;
#if defined(__AVX2__)
                                __m256i swap_mask = _mm256_setr_epi8(
                                    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
                                    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
                                );
                                for (; j + 8 <= count; j += 8) {
                                    for (int k = 0; k < 3; k++) {
                                        __m256i data = _mm256_loadu_si256((const __m256i *)(src + 12 * j + 32 * k));
                                        __m256i swapped = _mm256_shuffle_epi8(data, swap_mask);
                                        _mm256_storeu_si256((__m256i *)((char *)r + sizeof(Result) * j + 32 * k), swapped);
                                    }
                                }
#endif
                                for (; j < count; j++) {
                                    size_t offset = 12 * j;
                                    r[j].seeders = ntohl(*(uint32_t *)(src + offset));
                                    r[j].completed = ntohl(*(uint32_t *)(src + offset + 4));
                                    r[j].leechers = ntohl(*(uint32_t *)(src + offset + 8));
                                }
                                pendings[ch].done = true;
                                outstanding--;
                            }
                        }
                    }
                    free(rio_results);
                }
            }
#elif defined(__linux__)
            // Post all sends and receives
            struct io_uring *ring = &((IoUringContext *)io_ctx)->ring;
            for (size_t ch = 0; ch < num_chunks; ch++) {
                if (pendings[ch].done) continue;
                struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
                if (!sqe) {
                    io_uring_submit(ring);
                    sqe = io_uring_get_sqe(ring);
                }
                size_t req_len = 16 + 20 * pendings[ch].count;
                io_uring_prep_send(sqe, sock, ((IoUringContext *)io_ctx)->send_buffer + ch * max_req_len, req_len, MSG_CONFIRM);
                io_uring_sqe_set_data64(sqe, ch | (1ULL << 32));
            }
            for (size_t ch = 0; ch < num_chunks; ch++) {
                if (pendings[ch].done) continue;
                struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
                if (!sqe) {
                    io_uring_submit(ring);
                    sqe = io_uring_get_sqe(ring);
                }
                io_uring_prep_recv(sqe, sock, ((IoUringContext *)io_ctx)->recv_buffer + ch * max_resp_len, max_resp_len, 0);
                io_uring_sqe_set_data64(sqe, ch | (2ULL << 32));
            }
            struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
            if (!sqe) io_uring_submit(ring);
            sqe = io_uring_get_sqe(ring);
            struct timespec ts = {.tv_sec = current_timeout / 1000, .tv_nsec = (current_timeout % 1000) * 1000000LL};
            io_uring_prep_timeout(sqe, &ts, 0, 0);
            io_uring_sqe_set_data64(sqe, 3ULL);
            io_uring_submit(ring);
            while (outstanding > 0) {
                struct io_uring_cqe *cqe;
                if (io_uring_wait_cqe(ring, &cqe) < 0) break;
                uint64_t data = io_uring_cqe_get_data64(cqe);
                int res = cqe->res;
                io_uring_cqe_seen(ring, cqe);
                if (data == 3ULL) break;
                size_t ch = data & 0xFFFFFFFF;
                if ((data >> 32) == 2 && res > 0) {
                    char *resp = ((IoUringContext *)io_ctx)->recv_buffer + ch * max_resp_len;
                    uint32_t action = ntohl(*(uint32_t *)resp);
                    uint32_t trans_id = ntohl(*(uint32_t *)(resp + 4));
                    if (action == SCRAPE_ACTION && trans_id == pendings[ch].trans_id) {
                        const char *src = resp + 8;
                        Result *r = &results[pendings[ch].start];
                        size_t count = pendings[ch].count;
                        size_t j = 0;
#if defined(__AVX2__)
                        __m256i swap_mask = _mm256_setr_epi8(
                            3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
                            3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
                        );
                        for (; j + 8 <= count; j += 8) {
                            for (int k = 0; k < 3; k++) {
                                __m256i data = _mm256_loadu_si256((const __m256i *)(src + 12 * j + 32 * k));
                                __m256i swapped = _mm256_shuffle_epi8(data, swap_mask);
                                _mm256_storeu_si256((__m256i *)((char *)r + sizeof(Result) * j + 32 * k), swapped);
                            }
                        }
#endif
                        for (; j < count; j++) {
                            size_t offset = 12 * j;
                            r[j].seeders = ntohl(*(uint32_t *)(src + offset));
                            r[j].completed = ntohl(*(uint32_t *)(src + offset + 4));
                            r[j].leechers = ntohl(*(uint32_t *)(src + offset + 8));
                        }
                        pendings[ch].done = true;
                        outstanding--;
                    }
                }
            }
#endif
        } else {
            // Non-batch mode, use scatter-gather for send
            for (size_t ch = 0; ch < num_chunks; ch++) {
                if (pendings[ch].done) continue;
                pendings[ch].trans_id = rand();
                uint8_t header[16];
                *(uint64_t *)header = htonll(connection_id);
                *(uint32_t *)(header + 8) = htonl(SCRAPE_ACTION);
                *(uint32_t *)(header + 12) = htonl(pendings[ch].trans_id);
                size_t count = pendings[ch].count;
                size_t total_len = 16 + 20 * count;
                int rv;
#ifdef _WIN32
                WSABUF iov[MAX_PER_REQUEST + 1];
                iov[0].buf = (char *)header;
                iov[0].len = 16;
                for (size_t j = 0; j < count; j++) {
                    iov[j + 1].buf = (char *)hashes[pendings[ch].start + j].bin;
                    iov[j + 1].len = 20;
                }
                DWORD send_bytes = 0;
                rv = WSASend(sock, iov, (ULONG)(count + 1), &send_bytes, 0, NULL, NULL);
                if (rv == SOCKET_ERROR || send_bytes != total_len) {
                    int err = WSAGetLastError();
                    if (err == WSAEWOULDBLOCK) continue;
                    // error
                }
#else
                struct iovec iov[MAX_PER_REQUEST + 1];
                iov[0].iov_base = header;
                iov[0].iov_len = 16;
                for (size_t j = 0; j < count; j++) {
                    iov[j + 1].iov_base = hashes[pendings[ch].start + j].bin;
                    iov[j + 1].iov_len = 20;
                }
                struct msghdr msg = {.msg_iov = iov, .msg_iovlen = count + 1};
                ssize_t sent = sendmsg(sock, &msg, 0);
                if (sent != (ssize_t)total_len) {
                    if (ERR == EAGAIN || ERR == EWOULDBLOCK) continue;
                    // error
                }
#endif
            }
        }

        // Receive responses
        if (use_io) {
            // completions already processed in batch above
        } else {
            while (outstanding > 0) {
                uint8_t scrape_resp[8 + 12 * MAX_PER_REQUEST];
                int resp_len = recv_response(sock, scrape_resp, sizeof(scrape_resp), current_timeout, use_io, io_ctx);
                if (resp_len <= 0) break; // timeout or error, retry
                uint32_t action = ntohl(*(uint32_t *)scrape_resp);
                uint32_t trans_id = ntohl(*(uint32_t *)(scrape_resp + 4));
                if (action != SCRAPE_ACTION) continue;
                for (size_t ch = 0; ch < num_chunks; ch++) {
                    if (pendings[ch].trans_id == trans_id && !pendings[ch].done) {
                        size_t exp_len = 8 + 12 * pendings[ch].count;
                        if ((size_t)resp_len < exp_len) break;
#ifdef __AVX2__
                        __m256i swap_mask = _mm256_setr_epi8(
                            3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
                            3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
                        );
                        const char *src = scrape_resp + 8;
                        Result *r = &results[pendings[ch].start];
                        size_t count = pendings[ch].count;
                        size_t j = 0;
                        for (; j + 8 <= count; j += 8) {
                            for (int k = 0; k < 3; k++) {
                                __m256i data = _mm256_loadu_si256((const __m256i *)(src + 12 * j + 32 * k));
                                __m256i swapped = _mm256_shuffle_epi8(data, swap_mask);
                                _mm256_storeu_si256((__m256i *)((char *)r + sizeof(Result) * j + 32 * k), swapped);
                            }
                        }
                        for (; j < count; j++) {
                            size_t offset = 12 * j;
                            r[j].seeders = ntohl(*(uint32_t *)(src + offset));
                            r[j].completed = ntohl(*(uint32_t *)(src + offset + 4));
                            r[j].leechers = ntohl(*(uint32_t *)(src + offset + 8));
                        }
#else
                        for (size_t j = 0; j < pendings[ch].count; j++) {
                            size_t idx = pendings[ch].start + j;
                            results[idx].seeders = ntohl(*(uint32_t *)(scrape_resp + 8 + 12 * j));
                            results[idx].completed = ntohl(*(uint32_t *)(scrape_resp + 8 + 12 * j + 4));
                            results[idx].leechers = ntohl(*(uint32_t *)(scrape_resp + 8 + 12 * j + 8));
                        }
#endif
                        pendings[ch].done = true;
                        outstanding--;
                        break;
                    }
                }
            }
        }
        int still_out = 0;
        for (size_t ch = 0; ch < num_chunks; ch++) if (!pendings[ch].done) still_out++;
        if (still_out == 0) break;
        global_retries++;
        current_timeout = current_timeout * TIMEOUT_MULTIPLIER < MAX_TIMEOUT ? current_timeout * TIMEOUT_MULTIPLIER : MAX_TIMEOUT;
    }

    free(pendings);

    char *json_buf = malloc(num_hashes * 128 + 16);
    if (unlikely(!json_buf)) {
#ifdef _WIN32
        if (use_io) {
            free(rio_ctx.send_buffer);
            free(rio_ctx.recv_buffer);
            rio.RIOCloseCompletionQueue(rio_ctx.queue);
            WSACloseEvent(rio_ctx.event);
            rio.RIODeregisterBuffer(rio_ctx.send_buf_id);
            rio.RIODeregisterBuffer(rio_ctx.recv_buf_id);
        }
#elif defined(__linux__)
        if (use_io) {
            free(iouring_ctx.send_buffer);
            free(iouring_ctx.recv_buffer);
            io_uring_queue_exit(&iouring_ctx.ring);
        }
#endif
        CLOSE(sock);
        free(hashes);
        free(results);
        return 1;
    }
    char *p = json_buf;
    p += sprintf(p, "[");
    for (size_t i = 0; i < num_hashes; i++) {
        if (i > 0) p += sprintf(p, ",");
        p += sprintf(p, "{\"info_hash\":\"%.40s\",\"seeders\":%u,\"leechers\":%u,\"completed\":%u}",
            hashes[i].hex, results[i].seeders, results[i].leechers, results[i].completed);
    }
    p += sprintf(p, "]\n");
    fwrite(json_buf, p - json_buf, 1, stdout);
    free(json_buf);

    free(results);
#ifdef _WIN32
    if (use_io) {
        free(rio_ctx.send_buffer);
        free(rio_ctx.recv_buffer);
        rio.RIOCloseCompletionQueue(rio_ctx.queue);
        WSACloseEvent(rio_ctx.event);
        rio.RIODeregisterBuffer(rio_ctx.send_buf_id);
        rio.RIODeregisterBuffer(rio_ctx.recv_buf_id);
    }
#elif defined(__linux__)
    if (use_io) {
        free(iouring_ctx.send_buffer);
        free(iouring_ctx.recv_buffer);
        io_uring_queue_exit(&iouring_ctx.ring);
    }
#endif
    CLOSE(sock);
    free(hashes);

    long long end_ms = now_ms();
    long long duration_ms = end_ms - start_ms;
    if (verbose) {
        printf("Execution time: %lld ms\n", duration_ms);
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}