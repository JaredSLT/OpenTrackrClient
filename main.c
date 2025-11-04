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
#undef IP_MTU_DISCOVER
#define IP_MTU_DISCOVER 10
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
typedef LARGE_INTEGER timestamp_t;
static LARGE_INTEGER timer_freq;
static inline void timer_init() { QueryPerformanceFrequency(&timer_freq); }
static inline timestamp_t timer_get() { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t; }
static inline long long timer_diff_ns(timestamp_t start, timestamp_t end) {
    return ((end.QuadPart - start.QuadPart) * 1000000000LL) / timer_freq.QuadPart;
}
#define THREAD_HANDLE HANDLE
#define CREATE_THREAD(h, f, d) h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)f, d, 0, NULL)
#define JOIN_THREAD(h) WaitForSingleObject(h, INFINITE)
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
#include <time.h>
typedef struct timespec timestamp_t;
static inline void timer_init() {}
static inline timestamp_t timer_get() { struct timespec ts;
#ifdef __linux__
clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
return ts; }
static inline long long timer_diff_ns(timestamp_t start, timestamp_t end) {
    return (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
}
#define THREAD_HANDLE pthread_t
#define CREATE_THREAD(h, f, d) pthread_create(&h, NULL, f, d)
#define JOIN_THREAD(h) pthread_join(h, NULL)
#endif

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/vm_map.h>
#endif

#ifdef __linux__
#include <linux/filter.h>
#include <liburing.h>
#include <sys/utsname.h>
#include <sys/epoll.h>
#define SOL_UDP 17
#define UDP_SEGMENT 103
#define UDP_GRO 104
#define SO_ZEROCOPY 60
#define MSG_ZEROCOPY (1 << 26)
#define SO_BUSY_POLL 46
#endif

#if defined(__FreeBSD__) && (__FreeBSD__ >= 13)
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
#endif

#ifdef __SSSE3__
#include <immintrin.h>
#endif

#ifdef __ARM_NEON
#include <arm_neon.h>
#endif

#if defined(__POWERPC__) && defined(__ALTIVEC__)
#include <altivec.h>
#endif

#if defined(__riscv) && defined(__riscv_vector)
#include <riscv_vector.h>
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
#define MAX_PER_REQUEST 30
#define MAX_TIMEOUT 64000
#if UINTPTR_MAX == 0xFFFFFFFFUL
#define BUFSIZE 10485760LL
#else
#define BUFSIZE 52428800LL
#endif

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#if defined(__linux__) || defined(__FreeBSD__)
#define UDP_GSO_LEVEL SOL_UDP
#define UDP_GSO_OPTNAME UDP_SEGMENT
#endif

#if defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__)
#define HAVE_LARGE_PAGES
#endif

#if defined(__linux__) || defined(__FreeBSD__)
#define HAVE_SENDMMSG
#define HAVE_RECVMMSG
#include <sys/types.h>
#include <sys/uio.h>
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
    size_t send_alloc_size;
    size_t recv_alloc_size;
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
    size_t send_alloc_size;
    size_t recv_alloc_size;
    bool support_multishot;
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
    __m128i zero = _mm_setzero_si128();
    // For low
    __m128i even_shuf_low = _mm_shuffle_epi8(values_low, even_mask);
    __m128i even_words_low = _mm_unpacklo_epi8(even_shuf_low, zero);
    __m128i high_words_low = _mm_slli_epi16(even_words_low, 4);
    __m128i high_low = _mm_packus_epi16(high_words_low, zero);
    __m128i odd_shuf_low = _mm_shuffle_epi8(values_low, odd_mask);
    __m128i bytes_low = _mm_or_si128(high_low, odd_shuf_low);
    _mm_storel_epi64((__m128i *)bin, bytes_low);
    // For high
    __m128i even_shuf_high = _mm_shuffle_epi8(values_high, even_mask);
    __m128i even_words_high = _mm_unpacklo_epi8(even_shuf_high, zero);
    __m128i high_words_high = _mm_slli_epi16(even_words_high, 4);
    __m128i high_high = _mm_packus_epi16(high_words_high, zero);
    __m128i odd_shuf_high = _mm_shuffle_epi8(values_high, odd_mask);
    __m128i bytes_high = _mm_or_si128(high_high, odd_shuf_high);
    _mm_storel_epi64((__m128i *)(bin + 8), bytes_high);
#elif defined(__SSSE3__)
    __m128i zero = _mm_setzero_si128();
    __m128i even_mask = _mm_setr_epi8(0, 2, 4, 6, 8, 10, 12, 14, -1, -1, -1, -1, -1, -1, -1, -1);
    __m128i odd_mask = _mm_setr_epi8(1, 3, 5, 7, 9, 11, 13, 15, -1, -1, -1, -1, -1, -1, -1, -1);
    for (int offset = 0; offset < 32; offset += 16) {
        __m128i input = _mm_loadu_si128((const __m128i *)(hex + offset));
        __m128i input_lower = _mm_or_si128(input, _mm_set1_epi8(0x20));
        __m128i values = _mm_sub_epi8(input_lower, _mm_set1_epi8('0'));
        __m128i lt0 = _mm_cmplt_epi8(values, _mm_setzero_si128());
        __m128i ge0 = _mm_xor_si128(lt0, _mm_set1_epi8(-1));
        __m128i le9 = _mm_cmplt_epi8(values, _mm_set1_epi8(10));
        __m128i is_digit = _mm_and_si128(ge0, le9);
        __m128i lt_a = _mm_cmplt_epi8(values, _mm_set1_epi8('a' - '0'));
        __m128i ge_a = _mm_xor_si128(lt_a, _mm_set1_epi8(-1));
        __m128i le_f = _mm_cmplt_epi8(values, _mm_set1_epi8('f' - '0' + 1));
        __m128i is_hex = _mm_and_si128(ge_a, le_f);
        __m128i is_valid = _mm_or_si128(is_digit, is_hex);
        __m128i invalid = _mm_cmpeq_epi8(is_valid, _mm_setzero_si128());
        if (_mm_movemask_epi8(invalid)) return -1;
        __m128i alpha_adjust = _mm_and_si128(is_hex, _mm_set1_epi8('a' - '0' - 10));
        values = _mm_sub_epi8(values, alpha_adjust);
        __m128i even_shuf = _mm_shuffle_epi8(values, even_mask);
        __m128i even_words = _mm_unpacklo_epi8(even_shuf, zero);
        __m128i high_words = _mm_slli_epi16(even_words, 4);
        __m128i high = _mm_packus_epi16(high_words, zero);
        __m128i odd_shuf = _mm_shuffle_epi8(values, odd_mask);
        __m128i bytes = _mm_or_si128(high, odd_shuf);
        _mm_storel_epi64((__m128i *)(bin + offset / 2), bytes);
    }
#elif defined(__riscv) && defined(__riscv_vector)
    size_t vl = __riscv_vsetvl_e8m1(16);
    for (int offset = 0; offset < 32; offset += 16) {
        vint8m1_t input = __riscv_vle8_v_i8m1((int8_t *)(hex + offset), vl);
        vint8m1_t input_lower = __riscv_vor_vx_i8m1(input, 0x20, vl);
        vint8m1_t values = __riscv_vsub_vx_i8m1(input_lower, '0', vl);
        vbool8_t lt0 = __riscv_vmslt_vx_i8m1_b8(values, 0, vl);
        vbool8_t ge0 = __riscv_vmnot_m_b8(lt0, vl);
        vbool8_t le9 = __riscv_vmslt_vx_i8m1_b8(values, 10, vl);
        vbool8_t is_digit = __riscv_vmand_mm_b8(ge0, le9, vl);
        vbool8_t lt_a = __riscv_vmslt_vx_i8m1_b8(values, 'a' - '0', vl);
        vbool8_t ge_a = __riscv_vmnot_m_b8(lt_a, vl);
        vbool8_t le_f = __riscv_vmslt_vx_i8m1_b8(values, 'f' - '0' + 1, vl);
        vbool8_t is_hex = __riscv_vmand_mm_b8(ge_a, le_f, vl);
        vbool8_t is_valid = __riscv_vmor_mm_b8(is_digit, is_hex, vl);
        vbool8_t invalid = __riscv_vmnot_m_b8(is_valid, vl);
        if (__riscv_vfirst_m_b8(invalid, vl) >= 0) return -1;
        vint8m1_t alpha_adjust = __riscv_vand_m_vx_i8m1(is_hex, 'a' - '0' - 10, vl);
        values = __riscv_vsub_vv_i8m1(values, alpha_adjust, vl);
        size_t pack_vl = __riscv_vsetvl_e8m1(8);
        vuint8m1_t values_u = __riscv_vreinterpret_v_i8m1_u8m1(values);
        vuint8m1_t even_idx_v = __riscv_vle8_v_u8m1((uint8_t[]){0,2,4,6,8,10,12,14}, pack_vl);
        vuint8m1_t even = __riscv_vrgather_vv_u8m1(values_u, even_idx_v, pack_vl);
        vuint8m1_t odd_idx_v = __riscv_vle8_v_u8m1((uint8_t[]){1,3,5,7,9,11,13,15}, pack_vl);
        vuint8m1_t odd = __riscv_vrgather_vv_u8m1(values_u, odd_idx_v, pack_vl);
        vuint8m1_t high = __riscv_vsll_vx_u8m1(even, 4, pack_vl);
        vuint8m1_t bytes = __riscv_vor_vv_u8m1(high, odd, pack_vl);
        __riscv_vse8_v_u8m1(bin + (offset / 2), bytes, pack_vl);
    }
    // Last 8 chars
    size_t last_vl = __riscv_vsetvl_e8m1(8);
    vint8m1_t input_last = __riscv_vle8_v_i8m1((int8_t *)(hex + 32), last_vl);
    vint8m1_t input_lower_last = __riscv_vor_vx_i8m1(input_last, 0x20, last_vl);
    vint8m1_t values_last = __riscv_vsub_vx_i8m1(input_lower_last, '0', last_vl);
    vbool8_t lt0_last = __riscv_vmslt_vx_i8m1_b8(values_last, 0, last_vl);
    vbool8_t ge0_last = __riscv_vmnot_m_b8(lt0_last, last_vl);
    vbool8_t le9_last = __riscv_vmslt_vx_i8m1_b8(values_last, 10, last_vl);
    vbool8_t is_digit_last = __riscv_vmand_mm_b8(ge0_last, le9_last, last_vl);
    vbool8_t lt_a_last = __riscv_vmslt_vx_i8m1_b8(values_last, 'a' - '0', last_vl);
    vbool8_t ge_a_last = __riscv_vmnot_m_b8(lt_a_last, last_vl);
    vbool8_t le_f_last = __riscv_vmslt_vx_i8m1_b8(values_last, 'f' - '0' + 1, last_vl);
    vbool8_t is_hex_last = __riscv_vmand_mm_b8(ge_a_last, le_f_last, last_vl);
    vbool8_t is_valid_last = __riscv_vmor_mm_b8(is_digit_last, is_hex_last, last_vl);
    vbool8_t invalid_last = __riscv_vmnot_m_b8(is_valid_last, last_vl);
    if (__riscv_vfirst_m_b8(invalid_last, last_vl) >= 0) return -1;
    vint8m1_t alpha_adjust_last = __riscv_vand_m_vx_i8m1(is_hex_last, 'a' - '0' - 10, last_vl);
    values_last = __riscv_vsub_vv_i8m1(values_last, alpha_adjust_last, last_vl);
    size_t pack_vl_last = __riscv_vsetvl_e8m1(4);
    vuint8m1_t values_u_last = __riscv_vreinterpret_v_i8m1_u8m1(values_last);
    vuint8m1_t even_idx_last = __riscv_vle8_v_u8m1((uint8_t[]){0,2,4,6}, pack_vl_last);
    vuint8m1_t even_last = __riscv_vrgather_vv_u8m1(values_u_last, even_idx_last, pack_vl_last);
    vuint8m1_t odd_idx_last = __riscv_vle8_v_u8m1((uint8_t[]){1,3,5,7}, pack_vl_last);
    vuint8m1_t odd_last = __riscv_vrgather_vv_u8m1(values_u_last, odd_idx_last, pack_vl_last);
    vuint8m1_t high_last = __riscv_vsll_vx_u8m1(even_last, 4, pack_vl_last);
    vuint8m1_t bytes_last = __riscv_vor_vv_u8m1(high_last, odd_last, pack_vl_last);
    __riscv_vse8_v_u8m1(bin + 16, bytes_last, pack_vl_last);
#elif defined(__POWERPC__) && defined(__ALTIVEC__)
    vector unsigned char input1 = vec_ld(0, (unsigned char*)hex);
    vector unsigned char input2 = vec_ld(16, (unsigned char*)hex);
    vector unsigned char input3 = vec_ld(32, (unsigned char*)hex);
    vector signed char lower1 = vec_or((vector signed char)input1, vec_splat_s8(0x20));
    vector signed char lower2 = vec_or((vector signed char)input2, vec_splat_s8(0x20));
    vector signed char lower3 = vec_or((vector signed char)input3, vec_splat_s8(0x20));
    vector signed char values1 = vec_sub(lower1, vec_splat_s8('0'));
    vector signed char values2 = vec_sub(lower2, vec_splat_s8('0'));
    vector signed char values3 = vec_sub(lower3, vec_splat_s8('0'));
    vector bool char lt0_1 = vec_cmplt(values1, vec_splat_s8(0));
    vector bool char lt0_2 = vec_cmplt(values2, vec_splat_s8(0));
    vector bool char lt0_3 = vec_cmplt(values3, vec_splat_s8(0));
    vector bool char ge0_1 = vec_nor(lt0_1, lt0_1);
    vector bool char ge0_2 = vec_nor(lt0_2, lt0_2);
    vector bool char ge0_3 = vec_nor(lt0_3, lt0_3);
    vector bool char le9_1 = vec_cmplt(values1, vec_splat_s8(10));
    vector bool char le9_2 = vec_cmplt(values2, vec_splat_s8(10));
    vector bool char le9_3 = vec_cmplt(values3, vec_splat_s8(10));
    vector bool char is_digit1 = vec_and(ge0_1, le9_1);
    vector bool char is_digit2 = vec_and(ge0_2, le9_2);
    vector bool char is_digit3 = vec_and(ge0_3, le9_3);
    vector bool char lt_a1 = vec_cmplt(values1, vec_splat_s8('a' - '0'));
    vector bool char lt_a2 = vec_cmplt(values2, vec_splat_s8('a' - '0'));
    vector bool char lt_a3 = vec_cmplt(values3, vec_splat_s8('a' - '0'));
    vector bool char ge_a1 = vec_nor(lt_a1, lt_a1);
    vector bool char ge_a2 = vec_nor(lt_a2, lt_a2);
    vector bool char ge_a3 = vec_nor(lt_a3, lt_a3);
    vector bool char le_f1 = vec_cmplt(values1, vec_splat_s8('f' - '0' + 1));
    vector bool char le_f2 = vec_cmplt(values2, vec_splat_s8('f' - '0' + 1));
    vector bool char le_f3 = vec_cmplt(values3, vec_splat_s8('f' - '0' + 1));
    vector bool char is_hex1 = vec_and(ge_a1, le_f1);
    vector bool char is_hex2 = vec_and(ge_a2, le_f2);
    vector bool char is_hex3 = vec_and(ge_a3, le_f3);
    vector bool char is_valid1 = vec_or(is_digit1, is_hex1);
    vector bool char is_valid2 = vec_or(is_digit2, is_hex2);
    vector bool char is_valid3 = vec_or(is_digit3, is_hex3);
    vector signed char invalid1 = vec_nor((vector signed char)is_valid1, (vector signed char)is_valid1);
    vector signed char invalid2 = vec_nor((vector signed char)is_valid2, (vector signed char)is_valid2);
    vector signed char invalid3 = vec_nor((vector signed char)is_valid3, (vector signed char)is_valid3);
    if (vec_any_ne(invalid1, vec_splat_s8(0)) || vec_any_ne(invalid2, vec_splat_s8(0)) || vec_any_ne(invalid3, vec_splat_s8(0))) return -1;
    vector signed char alpha_adjust1 = vec_and((vector signed char)is_hex1, vec_splat_s8('a' - '0' - 10));
    vector signed char alpha_adjust2 = vec_and((vector signed char)is_hex2, vec_splat_s8('a' - '0' - 10));
    vector signed char alpha_adjust3 = vec_and((vector signed char)is_hex3, vec_splat_s8('a' - '0' - 10));
    values1 = vec_sub(values1, alpha_adjust1);
    values2 = vec_sub(values2, alpha_adjust2);
    values3 = vec_sub(values3, alpha_adjust3);
    vector unsigned char even_perm = (vector unsigned char){0,2,4,6,8,10,12,14,128,128,128,128,128,128,128,128};
    vector unsigned char odd_perm = (vector unsigned char){1,3,5,7,9,11,13,15,128,128,128,128,128,128,128,128};
    vector signed char even1 = vec_perm(values1, values1, even_perm);
    vector unsigned char high1 = vec_sl((vector unsigned char)even1, vec_splat_u8(4));
    vector signed char odd1 = vec_perm(values1, values1, odd_perm);
    vector unsigned char bytes1 = vec_or(high1, (vector unsigned char)odd1);
    vec_stl((vector signed char)bytes1, 0, (signed char*)bin);
    vector signed char even2 = vec_perm(values2, values2, even_perm);
    vector unsigned char high2 = vec_sl((vector unsigned char)even2, vec_splat_u8(4));
    vector signed char odd2 = vec_perm(values2, values2, odd_perm);
    vector unsigned char bytes2 = vec_or(high2, (vector unsigned char)odd2);
    vec_stl((vector signed char)bytes2, 8, (signed char*)bin);
#elif defined(__ARM_NEON)
    for (int offset = 0; offset < 32; offset += 16) {
        uint8x16_t u_input = vld1q_u8((const uint8_t *)(hex + offset));
        int8x16_t input = vreinterpretq_s8_u8(u_input);
        int8x16_t input_lower = vorrq_s8(input, vdupq_n_s8(0x20));
        int8x16_t values = vsubq_s8(input_lower, vdupq_n_s8('0'));
        int8x16_t lt0 = vcltq_s8(values, vdupq_n_s8(0));
        int8x16_t ge0 = veorq_s8(lt0, vdupq_n_s8(-1));
        int8x16_t le9 = vcltq_s8(values, vdupq_n_s8(10));
        int8x16_t is_digit = vandq_s8(ge0, le9);
        int8x16_t lt_a = vcltq_s8(values, vdupq_n_s8('a' - '0'));
        int8x16_t ge_a = veorq_s8(lt_a, vdupq_n_s8(-1));
        int8x16_t le_f = vcltq_s8(values, vdupq_n_s8('f' - '0' + 1));
        int8x16_t is_hex = vandq_s8(ge_a, le_f);
        int8x16_t is_valid = vorrq_s8(is_digit, is_hex);
        int8_t min_valid = vminvq_s8(is_valid);
        if (min_valid == 0) return -1;
        int8x16_t alpha_adjust = vandq_s8(is_hex, vdupq_n_s8('a' - '0' - 10));
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
#if defined(__AVX2__) || defined(__SSSE3__)
    {
        __m128i input_last = _mm_loadl_epi64((const __m128i *)(hex + 32));
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
        if (_mm_movemask_epi8(invalid_last) & 0xFF) return -1;
        __m128i alpha_adjust_last = _mm_and_si128(is_hex_last, _mm_set1_epi8('a' - '0' - 10));
        values_last = _mm_sub_epi8(values_last, alpha_adjust_last);
        __m128i even_mask_last = _mm_setr_epi8(0, 2, 4, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1);
        __m128i odd_mask_last = _mm_setr_epi8(1, 3, 5, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1);
        __m128i zero = _mm_setzero_si128();
        __m128i even_shuf_last = _mm_shuffle_epi8(values_last, even_mask_last);
        __m128i even_words_last = _mm_unpacklo_epi8(even_shuf_last, zero);
        __m128i high_words_last = _mm_slli_epi16(even_words_last, 4);
        __m128i high_last = _mm_packus_epi16(high_words_last, zero);
        __m128i odd_shuf_last = _mm_shuffle_epi8(values_last, odd_mask_last);
        __m128i bytes_last = _mm_or_si128(high_last, odd_shuf_last);
        *(int32_t *)(bin + 16) = _mm_cvtsi128_si32(bytes_last);
    }
#elif defined(__POWERPC__) && defined(__ALTIVEC__)
    vector unsigned char even_perm_last = (vector unsigned char){0,2,4,6,128,128,128,128,128,128,128,128,128,128,128,128};
    vector unsigned char odd_perm_last = (vector unsigned char){1,3,5,7,128,128,128,128,128,128,128,128,128,128,128,128};
    vector signed char even_last = vec_perm(values3, values3, even_perm_last);
    vector unsigned char high_last = vec_sl((vector unsigned char)even_last, vec_splat_u8(4));
    vector signed char odd_last = vec_perm(values3, values3, odd_perm_last);
    vector unsigned char bytes_last = vec_or(high_last, (vector unsigned char)odd_last);
    *(uint32_t *)(bin + 16) = *(uint32_t *)&bytes_last[0];
#elif defined(__ARM_NEON)
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

static uint32_t xoshiro_state[4];

static void init_rng() {
#ifdef _WIN32
    uint64_t seed = (uint64_t)time(NULL) ^ GetCurrentProcessId();
#else
    uint64_t seed = (uint64_t)time(NULL) ^ getpid();
#endif
    for (int i = 0; i < 4; i++) {
        seed = (seed ^ (seed >> 30)) * 0xBF58476D1CE4E5B9ULL;
        seed = (seed ^ (seed >> 27)) * 0x94D049BB133111EBULL;
        seed = seed ^ (seed >> 31);
        xoshiro_state[i] = (uint32_t)seed;
    }
}

static uint32_t simple_rng() {
    uint32_t result = xoshiro_state[0] + xoshiro_state[3];
    uint32_t t = xoshiro_state[1] << 9;
    xoshiro_state[2] ^= xoshiro_state[0];
    xoshiro_state[3] ^= xoshiro_state[1];
    xoshiro_state[1] ^= xoshiro_state[2];
    xoshiro_state[0] ^= xoshiro_state[3];
    xoshiro_state[2] ^= t;
    xoshiro_state[3] = (xoshiro_state[3] << 11) | (xoshiro_state[3] >> 21);
    return result;
}

static void* large_malloc(size_t size) {
    size = (size + 4095) & ~4095ULL;
#ifdef _WIN32
    SIZE_T lp_min = GetLargePageMinimum();
    if (lp_min == 0) return malloc(size);
    size_t alloc_size = (size + lp_min - 1) & ~(lp_min - 1);
    void* p = VirtualAlloc(NULL, alloc_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (p) return p;
    return VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#elif defined(HAVE_LARGE_PAGES)
#if defined(__linux__)
    int huge_flag = MAP_HUGETLB;
#elif defined(__FreeBSD__)
    int huge_flag = (21 << MAP_HUGE_SHIFT); // MAP_HUGE_2MB
#elif defined(__APPLE__)
    int huge_flag = 0; // No explicit huge page flag for mmap on Apple
#endif
    size_t page_size = 1LL << 21;
    size_t alloc_size = (size + page_size - 1) & ~(page_size - 1);
    void* p = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | huge_flag, -1, 0);
    if (p != MAP_FAILED) {
#ifdef MADV_HUGEPAGE
        madvise(p, alloc_size, MADV_HUGEPAGE);
#endif
        return p;
    }
    p = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) return p;
#elif defined(__APPLE__)
    vm_address_t p = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &p, alloc_size, VM_FLAGS_ANYWHERE);
    if (kr == KERN_SUCCESS) return (void*)p;
#endif
    return malloc(size);
}

static void large_free(void* p, size_t size) {
#ifdef _WIN32
    VirtualFree(p, 0, MEM_RELEASE);
#elif defined(HAVE_LARGE_PAGES)
    size_t page_size = 1LL << 21;
    size_t alloc_size = (size + page_size - 1) & ~(page_size - 1);
    munmap(p, alloc_size);
#elif defined(__APPLE__)
    size_t page_size = 1LL << 21;
    size_t alloc_size = (size + page_size - 1) & ~(page_size - 1);
    vm_deallocate(mach_task_self(), (vm_address_t)p, alloc_size);
#else
    free(p);
#endif
}

static inline char* u32_to_char(uint32_t v, char* p) {
    if (v == 0) {
        *p++ = '0';
        return p;
    }
    char temp[10];
    char* ptr = temp + 10;
    do {
        *--ptr = '0' + (v % 10);
        v /= 10;
    } while (v);
    size_t len = (temp + 10) - ptr;
    memcpy(p, ptr, len);
    return p + len;
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
            io_uring_prep_send(sqe, sock, buf, len, MSG_CONFIRM | MSG_ZEROCOPY);
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
            ssize_t sent = send(sock, buf, len, MSG_CONFIRM | MSG_ZEROCOPY);
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
    long long bufsize = BUFSIZE + num_hashes * 2048LL;
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    bufsize = (long long)(bufsize * 1.15);
#endif
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const void*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const void*)&bufsize, sizeof(bufsize));
#ifdef __linux__
    int no_check = 1, mtu_opt = IP_PMTUDISC_DO;
    setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, (const void*)&no_check, sizeof(no_check));
    setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, (const void*)&mtu_opt, sizeof(mtu_opt));
    int zero = 1;
    setsockopt(sock, SOL_SOCKET, SO_ZEROCOPY, &zero, sizeof(zero));
    int busy_poll = 50;
    setsockopt(sock, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll));
#endif
    int dontfrag = 1;
#ifdef _WIN32
    setsockopt(sock, IPPROTO_IP, IP_DONTFRAGMENT, (const void*)&dontfrag, sizeof(dontfrag));
    int mtu_opt = 2;
    setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, (char*)&mtu_opt, sizeof(mtu_opt));
#else
    setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, (const void*)&dontfrag, sizeof(dontfrag));
#endif
#if defined(UDP_GSO_OPTNAME)
    int gso_size = 1472;
    setsockopt(sock, UDP_GSO_LEVEL, UDP_GSO_OPTNAME, (const void*)&gso_size, sizeof(gso_size));
    int gro = 1;
    setsockopt(sock, UDP_GSO_LEVEL, UDP_GRO, (const void*)&gro, sizeof(gro));
#endif
    int recvtos = 1;
    setsockopt(sock, IPPROTO_IP, IP_RECVTOS, (const void*)&recvtos, sizeof(recvtos));
#ifndef _WIN32
#ifdef SO_TIMESTAMPNS
    int tsns = 1;
    setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPNS, (const void*)&tsns, sizeof(tsns));
#endif
#endif
    int mtu = 1500;
    setsockopt(sock, IPPROTO_IP, IP_MTU, (const void*)&mtu, sizeof(mtu));
}

static void destroy_io_ctx(io_ctx_t io_ctx) {
    if (!io_ctx) return;
#ifdef _WIN32
    RioContext *ctx = (RioContext *)io_ctx;
    if (ctx->send_buffer) large_free(ctx->send_buffer, ctx->send_alloc_size);
    if (ctx->recv_buffer) large_free(ctx->recv_buffer, ctx->recv_alloc_size);
    if (ctx->queue != RIO_INVALID_CQ) rio.RIOCloseCompletionQueue(ctx->queue);
    if (ctx->event != WSA_INVALID_EVENT) WSACloseEvent(ctx->event);
    if (ctx->send_buf_id != RIO_INVALID_BUFID) rio.RIODeregisterBuffer(ctx->send_buf_id);
    if (ctx->recv_buf_id != RIO_INVALID_BUFID) rio.RIODeregisterBuffer(ctx->recv_buf_id);
    large_free(io_ctx, sizeof(RioContext));
#elif defined(__linux__)
    IoUringContext *ctx = (IoUringContext *)io_ctx;
    if (ctx->send_buffer) large_free(ctx->send_buffer, ctx->send_alloc_size);
    if (ctx->recv_buffer) large_free(ctx->recv_buffer, ctx->recv_alloc_size);
    io_uring_queue_exit(&ctx->ring);
    large_free(io_ctx, sizeof(IoUringContext));
#endif
}

static io_ctx_t create_io_ctx(int sock, size_t max_chunks, bool* success) {
    *success = false;
#ifdef _WIN32
    io_ctx_t io_ctx = large_malloc(sizeof(RioContext));
    if (!io_ctx) return NULL;
    RioContext* ctx = (RioContext*)io_ctx;
    memset(ctx, 0, sizeof(RioContext));
    ctx->event = WSACreateEvent();
    if (ctx->event == WSA_INVALID_EVENT) goto fail;
    RIO_NOTIFICATION_COMPLETION completionType = { .Type = RIO_EVENT_COMPLETION, .Event = { .EventHandle = ctx->event, .NotifyReset = TRUE } };
    ctx->queue = rio.RIOCreateCompletionQueue(256, &completionType);
    if (ctx->queue == RIO_INVALID_CQ) goto fail;
    ctx->request_queue = rio.RIOCreateRequestQueue(sock, 200, 1, 200, 1, ctx->queue, ctx->queue, NULL);
    if (ctx->request_queue == RIO_INVALID_RQ) goto fail;
    if (!rio.RIOResizeCompletionQueue(ctx->queue, (DWORD)(max_chunks * 2 + 256)) ||
        !rio.RIOResizeRequestQueue(ctx->request_queue, (ULONG)max_chunks, (ULONG)max_chunks)) goto fail;
    ctx->max_chunks = max_chunks;
    size_t send_size = max_chunks * (16 + 20 * MAX_PER_REQUEST);
    size_t recv_size = max_chunks * (8 + 12 * MAX_PER_REQUEST);
    ctx->send_buffer = large_malloc(send_size);
    ctx->recv_buffer = large_malloc(recv_size);
    ctx->send_alloc_size = send_size;
    ctx->recv_alloc_size = recv_size;
    if (!ctx->send_buffer || !ctx->recv_buffer) goto fail;
    ctx->send_buf_id = rio.RIORegisterBuffer(ctx->send_buffer, (DWORD)send_size);
    ctx->recv_buf_id = rio.RIORegisterBuffer(ctx->recv_buffer, (DWORD)recv_size);
    if (ctx->send_buf_id == RIO_INVALID_BUFID || ctx->recv_buf_id == RIO_INVALID_BUFID) goto fail;
    *success = true;
    return io_ctx;
fail:
    destroy_io_ctx(io_ctx);
    return NULL;
#elif defined(__linux__)
    io_ctx_t io_ctx = large_malloc(sizeof(IoUringContext));
    if (!io_ctx) return NULL;
    IoUringContext* ctx = (IoUringContext*)io_ctx;
    memset(ctx, 0, sizeof(IoUringContext));
    if (io_uring_queue_init(128, &ctx->ring, IORING_SETUP_SQPOLL | IORING_SETUP_IOPOLL) < 0) {
        if (io_uring_queue_init(128, &ctx->ring, IORING_SETUP_IOPOLL) < 0) {
            if (io_uring_queue_init(128, &ctx->ring, 0) < 0) goto fail;
        }
    }
    struct utsname u;
    uname(&u);
    int major = 0, minor = 0;
    sscanf(u.release, "%d.%d", &major, &minor);
    ctx->support_multishot = (major > 5 || (major == 5 && minor >= 19));
    ctx->max_chunks = max_chunks;
    size_t send_size = max_chunks * (16 + 20 * MAX_PER_REQUEST);
    ctx->send_alloc_size = send_size;
    ctx->send_buffer = large_malloc(send_size);
    ctx->recv_alloc_size = ctx->support_multishot ? (8 + 12 * MAX_PER_REQUEST) : max_chunks * (8 + 12 * MAX_PER_REQUEST);
    ctx->recv_buffer = large_malloc(ctx->recv_alloc_size);
    if (!ctx->send_buffer || !ctx->recv_buffer) goto fail;
    size_t num_fixed = ctx->support_multishot ? max_chunks : 2 * max_chunks;
    struct iovec *fixed_iovs = malloc(num_fixed * sizeof(struct iovec));
    if (!fixed_iovs) goto fail;
    for (size_t ch = 0; ch < max_chunks; ch++) {
        fixed_iovs[ch].iov_base = ctx->send_buffer + ch * (16 + 20 * MAX_PER_REQUEST);
        fixed_iovs[ch].iov_len = 16 + 20 * MAX_PER_REQUEST;
        if (!ctx->support_multishot) {
            fixed_iovs[max_chunks + ch].iov_base = ctx->recv_buffer + ch * (8 + 12 * MAX_PER_REQUEST);
            fixed_iovs[max_chunks + ch].iov_len = 8 + 12 * MAX_PER_REQUEST;
        }
    }
    if (io_uring_register_buffers(&ctx->ring, fixed_iovs, num_fixed) < 0) goto fail_free_iovs;
    free(fixed_iovs);
    *success = true;
    return io_ctx;
fail_free_iovs:
    free(fixed_iovs);
fail:
    destroy_io_ctx(io_ctx);
    return NULL;
#else
    return NULL;
#endif
}

struct ThreadData {
    size_t start;
    size_t count;
    InfoHash *hashes;
    Result *results;
    int scrape_timeout_ms;
    struct sockaddr_in servaddr;
    bool global_use_rio;
    double rtt_sec;
    char *json;
};

static void* scrape_thread(void* arg) {
    struct ThreadData *data = (struct ThreadData *)arg;
    timestamp_t socket_start = timer_get();
#ifdef _WIN32
    SOCKET sock = WSASocket(AF_INET, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sock != INVALID_SOCKET) {
        SetHandleInformation((HANDLE)(uintptr_t)sock, HANDLE_FLAG_INHERIT, 0);
    }
#else
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
#endif
    if (unlikely(sock == INVALID_SOCK)) return NULL;

    setup_socket_options(sock, data->count);

#ifdef _WIN32
    u_long nonblock = 1;
    ioctlsocket(sock, FIONBIO, &nonblock);
#else
    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
#endif

    timestamp_t socket_end = timer_get();
    timestamp_t connect_start = timer_get();
    if (connect(sock, (struct sockaddr*)&data->servaddr, sizeof(data->servaddr)) < 0) {
        CLOSE(sock);
        return NULL;
    }

    bool use_io = false;
#ifdef _WIN32
    use_io = data->global_use_rio;
#endif
    size_t max_chunks = (data->count + MAX_PER_REQUEST - 1) / MAX_PER_REQUEST;
    io_ctx_t io_ctx = NULL;
    if (use_io) {
        bool success;
        io_ctx = create_io_ctx(sock, max_chunks, &success);
        use_io = success;
    }

    uint8_t connect_req[16];
    *(uint64_t*)(connect_req) = htonll(PROTOCOL_ID);
    *(uint32_t*)(connect_req + 8) = htonl(CONNECT_ACTION);
    uint32_t trans_id_connect = simple_rng();
    *(uint32_t*)(connect_req + 12) = htonl(trans_id_connect);
    uint8_t connect_resp[16];
    int timeout_ms = INITIAL_TIMEOUT;

    ssize_t resp_size = send_recv_with_retry(sock, connect_req, sizeof(connect_req), connect_resp, sizeof(connect_resp), &timeout_ms, use_io, io_ctx);
    timestamp_t connect_end = timer_get();

    if (unlikely(resp_size < 16 || ntohl(*(uint32_t*)(connect_resp)) != CONNECT_ACTION || ntohl(*(uint32_t*)(connect_resp + 4)) != trans_id_connect)) {
        if (use_io) destroy_io_ctx(io_ctx);
        CLOSE(sock);
        return NULL;
    }

    uint64_t connection_id = ntohll(*(uint64_t*)(connect_resp + 8));

    struct Pending {
        uint32_t trans_id;
        size_t start;
        size_t count;
        bool done;
    };

    struct Pending *pendings = malloc(max_chunks * sizeof(struct Pending));
    if (unlikely(!pendings)) {
        if (use_io) destroy_io_ctx(io_ctx);
        CLOSE(sock);
        return NULL;
    }
    for (size_t ch = 0; ch < max_chunks; ch++) {
        pendings[ch].start = ch * MAX_PER_REQUEST;
        pendings[ch].count = (data->count - pendings[ch].start < MAX_PER_REQUEST) ? data->count - pendings[ch].start : MAX_PER_REQUEST;
        pendings[ch].done = false;
    }

    timestamp_t scrape_start = timer_get();
    int current_timeout = data->scrape_timeout_ms;
    int thread_retries = 0;
    while (thread_retries < MAX_RETRIES) {
        int outstanding = 0;
        for (size_t ch = 0; ch < max_chunks; ch++) {
            if (!pendings[ch].done) outstanding++;
        }
        current_timeout = data->scrape_timeout_ms + (simple_rng() % (data->scrape_timeout_ms / 2));
        if (use_io) {
            for (size_t ch = 0; ch < max_chunks; ch++) {
                if (pendings[ch].done) continue;
                pendings[ch].trans_id = simple_rng();
                char *req = ((RioContext *)io_ctx)->send_buffer + ch * (16 + 20 * MAX_PER_REQUEST); // assumes Win/Linux similar
                *(uint64_t *)req = htonll(connection_id);
                *(uint32_t *)(req + 8) = htonl(SCRAPE_ACTION);
                *(uint32_t *)(req + 12) = htonl(pendings[ch].trans_id);
                for (size_t j = 0; j < pendings[ch].count; j++) {
                    const uint8_t *src = data->hashes[data->start + pendings[ch].start + j].bin;
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
            for (size_t ch = 0; ch < max_chunks; ch++) {
                if (pendings[ch].done) continue;
                ULONG req_len = 16 + 20 * pendings[ch].count;
                RIO_BUF rio_send = {((RioContext *)io_ctx)->send_buf_id, (ULONG)(ch * (16 + 20 * MAX_PER_REQUEST)), req_len};
                rio.RIOSend(((RioContext *)io_ctx)->request_queue, &rio_send, 1, 0, (PVOID)(ch | (1ULL << 32)));
            }
            for (size_t ch = 0; ch < max_chunks; ch++) {
                if (pendings[ch].done) continue;
                RIO_BUF rio_recv = {((RioContext *)io_ctx)->recv_buf_id, (ULONG)(ch * (8 + 12 * MAX_PER_REQUEST)), (ULONG)(8 + 12 * MAX_PER_REQUEST)};
                rio.RIOReceive(((RioContext *)io_ctx)->request_queue, &rio_recv, 1, 0, (PVOID)(ch | (2ULL << 32)));
            }
            rio.RIONotify(((RioContext *)io_ctx)->queue);
            DWORD wait = WaitForSingleObject(((RioContext *)io_ctx)->event, (DWORD)current_timeout);
            if (wait == WAIT_OBJECT_0) {
                RIORESULT *rio_results = malloc((max_chunks * 2) * sizeof(RIORESULT));
                if (rio_results) {
                    ULONG num = rio.RIODequeueCompletion(((RioContext *)io_ctx)->queue, rio_results, (ULONG)(max_chunks * 2));
                    for (ULONG i = 0; i < num; i++) {
                        if (rio_results[i].Status != 0) continue;
                        uint64_t context = rio_results[i].RequestContext;
                        size_t ch = (size_t)(context & 0xFFFFFFFF);
                        if ((context >> 32) == 2 && rio_results[i].BytesTransferred > 0) {
                            char *resp = ((RioContext *)io_ctx)->recv_buffer + ch * (8 + 12 * MAX_PER_REQUEST);
                            uint32_t action = ntohl(*(uint32_t *)resp);
                            uint32_t trans_id = ntohl(*(uint32_t *)(resp + 4));
                            if (action == SCRAPE_ACTION && trans_id == pendings[ch].trans_id) {
                                const uint8_t *src = (const uint8_t *)(resp + 8);
                                Result *r = data->results + data->start + pendings[ch].start;
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
            struct io_uring *ring = &((IoUringContext *)io_ctx)->ring;
            for (size_t ch = 0; ch < max_chunks; ch++) {
                if (pendings[ch].done) continue;
                struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
                if (!sqe) {
                    io_uring_submit(ring);
                    sqe = io_uring_get_sqe(ring);
                }
                size_t req_len = 16 + 20 * pendings[ch].count;
                io_uring_prep_send(sqe, sock, NULL, req_len, MSG_CONFIRM | MSG_ZEROCOPY);
                sqe->flags |= IOSQE_BUFFER_SELECT;
                sqe->buf_group = 0;
                sqe->buf_index = ch;
                io_uring_sqe_set_data64(sqe, ch | (1ULL << 32));
            }
            if (!((IoUringContext *)io_ctx)->support_multishot) {
                for (size_t ch = 0; ch < max_chunks; ch++) {
                    if (pendings[ch].done) continue;
                    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
                    if (!sqe) {
                        io_uring_submit(ring);
                        sqe = io_uring_get_sqe(ring);
                    }
                    io_uring_prep_recv(sqe, sock, NULL, 8 + 12 * MAX_PER_REQUEST, 0);
                    sqe->flags |= IOSQE_BUFFER_SELECT;
                    sqe->buf_group = 0;
                    sqe->buf_index = max_chunks + ch;
                    io_uring_sqe_set_data64(sqe, ch | (2ULL << 32));
                }
            } else {
                struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
                if (!sqe) {
                    io_uring_submit(ring);
                    sqe = io_uring_get_sqe(ring);
                }
                io_uring_prep_recv(sqe, sock, ((IoUringContext *)io_ctx)->recv_buffer, ((IoUringContext *)io_ctx)->recv_alloc_size, 0);
                sqe->ioprio |= IORING_RECV_MULTISHOT;
                io_uring_sqe_set_data64(sqe, 2ULL << 32);
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
                uint64_t data64 = io_uring_cqe_get_data64(cqe);
                int res = cqe->res;
                io_uring_cqe_seen(ring, cqe);
                if (data64 == 3ULL) break;
                size_t ch = data64 & 0xFFFFFFFF;
                if ((data64 >> 32) == 1) continue;
                if ((data64 >> 32) == 2 && res > 0) {
                    char scrape_resp_buf[4096];
                    char *resp;
                    uint32_t trans_id;
                    if (((IoUringContext *)io_ctx)->support_multishot) {
                        if (res > sizeof(scrape_resp_buf)) continue;
                        memcpy(scrape_resp_buf, ((IoUringContext *)io_ctx)->recv_buffer, res);
                        resp = scrape_resp_buf;
                        trans_id = ntohl(*(uint32_t *)(resp + 4));
                        ch = (size_t)-1;
                        for (size_t i = 0; i < max_chunks; i++) {
                            if (pendings[i].trans_id == trans_id && !pendings[i].done) {
                                ch = i;
                                break;
                            }
                        }
                        if (ch == (size_t)-1) continue;
                    } else {
                        resp = ((IoUringContext *)io_ctx)->recv_buffer + ch * (8 + 12 * MAX_PER_REQUEST);
                        trans_id = ntohl(*(uint32_t *)(resp + 4));
                    }
                    uint32_t action = ntohl(*(uint32_t *)resp);
                    if (action == SCRAPE_ACTION && trans_id == pendings[ch].trans_id) {
                        const uint8_t *src = (const uint8_t *)(resp + 8);
                        Result *r = data->results + data->start + pendings[ch].start;
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
#ifdef HAVE_SENDMMSG
            int pending_count = 0;
            for (size_t ch = 0; ch < max_chunks; ch++) if (!pendings[ch].done) pending_count++;
            struct mmsghdr mmsg[pending_count];
            struct iovec iovs[pending_count * (MAX_PER_REQUEST + 1)];
            size_t iov_idx = 0;
            size_t msg_idx = 0;
            for (size_t ch = 0; ch < max_chunks; ch++) {
                if (pendings[ch].done) continue;
                pendings[ch].trans_id = simple_rng();
                uint8_t header[16];
                *(uint64_t *)header = htonll(connection_id);
                *(uint32_t *)(header + 8) = htonl(SCRAPE_ACTION);
                *(uint32_t *)(header + 12) = htonl(pendings[ch].trans_id);
                struct msghdr *msg = &mmsg[msg_idx].msg_hdr;
                msg->msg_name = NULL;
                msg->msg_namelen = 0;
                msg->msg_control = NULL;
                msg->msg_controllen = 0;
                msg->msg_flags = 0;
                msg->msg_iov = &iovs[iov_idx];
                msg->msg_iovlen = pendings[ch].count + 1;
                iovs[iov_idx].iov_base = header;
                iovs[iov_idx].iov_len = 16;
                iov_idx++;
                for (size_t j = 0; j < pendings[ch].count; j++) {
                    iovs[iov_idx].iov_base = data->hashes[data->start + pendings[ch].start + j].bin;
                    iovs[iov_idx].iov_len = 20;
                    iov_idx++;
                }
                msg_idx++;
            }
            int sent = sendmmsg(sock, mmsg, msg_idx, 0);
            if (sent < 0 || (size_t)sent != msg_idx) {
#endif
            for (size_t ch = 0; ch < max_chunks; ch++) {
                if (pendings[ch].done) continue;
                pendings[ch].trans_id = simple_rng();
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
                    iov[j + 1].buf = (char *)data->hashes[data->start + pendings[ch].start + j].bin;
                    iov[j + 1].len = 20;
                }
                DWORD send_bytes = 0;
                rv = WSASend(sock, iov, (ULONG)(count + 1), &send_bytes, 0, NULL, NULL);
                if (rv == SOCKET_ERROR || send_bytes != total_len) continue;
#else
                struct iovec iov[MAX_PER_REQUEST + 1];
                iov[0].iov_base = header;
                iov[0].iov_len = 16;
                for (size_t j = 0; j < count; j++) {
                    iov[j + 1].iov_base = data->hashes[data->start + pendings[ch].start + j].bin;
                    iov[j + 1].iov_len = 20;
                }
                struct msghdr msg = {.msg_iov = iov, .msg_iovlen = count + 1};
                ssize_t sent = sendmsg(sock, &msg, 0);
                if (sent != (ssize_t)total_len) continue;
#endif
            }
#ifdef HAVE_SENDMMSG
            }
#endif
#ifdef _WIN32
            char *recv_bufs = large_malloc(max_chunks * (8 + 12 * MAX_PER_REQUEST));
            HANDLE *events = malloc(max_chunks * sizeof(HANDLE));
            OVERLAPPED *ol = malloc(max_chunks * sizeof(OVERLAPPED));
            WSABUF *wsabuf = malloc(max_chunks * sizeof(WSABUF));
            size_t active = 0;
            for (size_t i = 0; i < max_chunks; i++) {
                if (pendings[i].done) continue;
                wsabuf[active].len = (ULONG)(8 + 12 * MAX_PER_REQUEST);
                wsabuf[active].buf = recv_bufs + i * (8 + 12 * MAX_PER_REQUEST);
                memset(&ol[active], 0, sizeof(OVERLAPPED));
                ol[active].hEvent = WSACreateEvent();
                events[active] = ol[active].hEvent;
                DWORD flags = 0;
                int rv = WSARecv(sock, &wsabuf[active], 1, NULL, &flags, &ol[active], NULL);
                if (rv == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    if (err != WSA_IO_PENDING) {
                        WSACloseEvent(ol[active].hEvent);
                        continue;
                    }
                }
                active++;
            }
            while (active > 0 && outstanding > 0) {
                DWORD wait = WaitForMultipleObjects((DWORD)active, events, FALSE, (DWORD)current_timeout);
                if (wait == WAIT_TIMEOUT) break;
                if (wait >= WAIT_OBJECT_0 && wait < WAIT_OBJECT_0 + active) {
                    int idx = wait - WAIT_OBJECT_0;
                    DWORD bytes = 0, flags = 0;
                    if (WSAGetOverlappedResult(sock, &ol[idx], &bytes, FALSE, &flags)) {
                        if (bytes > 8) {
                            char *resp = wsabuf[idx].buf;
                            uint32_t action = ntohl(*(uint32_t *)resp);
                            uint32_t trans_id = ntohl(*(uint32_t *)(resp + 4));
                            if (action == SCRAPE_ACTION) {
                                for (size_t ch = 0; ch < max_chunks; ch++) {
                                    if (pendings[ch].trans_id == trans_id && !pendings[ch].done) {
                                        size_t exp_len = 8 + 12 * pendings[ch].count;
                                        if (bytes != exp_len) break;
                                        const uint8_t *src = (const uint8_t *)(resp + 8);
                                        Result *r = data->results + data->start + pendings[ch].start;
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
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    WSACloseEvent(ol[idx].hEvent);
                    for (int j = idx; j < (int)active - 1; j++) {
                        wsabuf[j] = wsabuf[j + 1];
                        ol[j] = ol[j + 1];
                        events[j] = events[j + 1];
                    }
                    active--;
                }
            }
            for (size_t i = 0; i < max_chunks; i++) {
                if (ol[i].hEvent) WSACloseEvent(ol[i].hEvent);
            }
            free(wsabuf);
            free(ol);
            free(events);
            large_free(recv_bufs, max_chunks * (8 + 12 * MAX_PER_REQUEST));
#else
            bool use_poller = false;
            int poller_fd = -1;
#if defined(__linux__)
            poller_fd = epoll_create1(0);
            if (poller_fd >= 0) {
                struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.u64 = 0};
                if (epoll_ctl(poller_fd, EPOLL_CTL_ADD, sock, &ev) == 0) use_poller = true;
                else { close(poller_fd); poller_fd = -1; }
            }
#elif defined(__APPLE__) || defined(__FreeBSD__)
            poller_fd = kqueue();
            if (poller_fd >= 0) {
                struct kevent ev;
                EV_SET(&ev, sock, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
                if (kevent(poller_fd, &ev, 1, NULL, 0, NULL) == 0) use_poller = true;
                else { close(poller_fd); poller_fd = -1; }
            }
#endif
            if (!use_poller) {
                while (outstanding > 0) {
#if defined(HAVE_RECVMMSG)
                    const int max_batch = 32;
                    struct mmsghdr mmsg[max_batch];
                    struct iovec iov[max_batch];
                    char scrape_resp[max_batch][4096];
                    for (int b = 0; b < max_batch; b++) {
                        iov[b].iov_base = scrape_resp[b];
                        iov[b].iov_len = 4096;
                        mmsg[b].msg_hdr.msg_iov = &iov[b];
                        mmsg[b].msg_hdr.msg_iovlen = 1;
                        mmsg[b].msg_hdr.msg_name = NULL;
                        mmsg[b].msg_hdr.msg_namelen = 0;
                        mmsg[b].msg_hdr.msg_control = NULL;
                        mmsg[b].msg_hdr.msg_controllen = 0;
                        mmsg[b].msg_hdr.msg_flags = 0;
                        mmsg[b].msg_len = 0;
                    }
                    int num = recvmmsg(sock, mmsg, max_batch, MSG_DONTWAIT, NULL);
                    if (num <= 0) {
                        if (num < 0 && (ERR == EAGAIN || ERR == EWOULDBLOCK)) break;
                        break;
                    }
                    for (int b = 0; b < num; b++) {
                        int resp_len = mmsg[b].msg_len;
                        if (resp_len <= 0) continue;
                        uint32_t action = ntohl(*(uint32_t *)scrape_resp[b]);
                        uint32_t trans_id = ntohl(*(uint32_t *)(scrape_resp[b] + 4));
                        if (action != SCRAPE_ACTION) continue;
                        for (size_t ch = 0; ch < max_chunks; ch++) {
                            if (pendings[ch].trans_id == trans_id && !pendings[ch].done) {
                                size_t exp_len = 8 + 12 * pendings[ch].count;
                                if ((size_t)resp_len < exp_len) break;
#ifdef __AVX2__
                                __m256i swap_mask = _mm256_setr_epi8(
                                    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
                                    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
                                );
                                const uint8_t *src = (const uint8_t *)(scrape_resp[b] + 8);
                                Result *r = data->results + data->start + pendings[ch].start;
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
                                    data->results[data->start + idx].seeders = ntohl(*(uint32_t *)(scrape_resp[b] + 8 + 12 * j));
                                    data->results[data->start + idx].completed = ntohl(*(uint32_t *)(scrape_resp[b] + 8 + 12 * j + 4));
                                    data->results[data->start + idx].leechers = ntohl(*(uint32_t *)(scrape_resp[b] + 8 + 12 * j + 8));
                                }
#endif
                                pendings[ch].done = true;
                                outstanding--;
                                break;
                            }
                        }
                    }
#else
                char scrape_resp[4096];
                ssize_t resp_len = recv(sock, scrape_resp, sizeof(scrape_resp), MSG_DONTWAIT);
                if (resp_len <= 0) {
                    if (ERR == EAGAIN || ERR == EWOULDBLOCK) break;
                    break;
                }
                uint32_t action = ntohl(*(uint32_t *)scrape_resp);
                uint32_t trans_id = ntohl(*(uint32_t *)(scrape_resp + 4));
                if (action != SCRAPE_ACTION) continue;
                for (size_t ch = 0; ch < max_chunks; ch++) {
                    if (pendings[ch].trans_id == trans_id && !pendings[ch].done) {
                        size_t exp_len = 8 + 12 * pendings[ch].count;
                        if ((size_t)resp_len < exp_len) break;
#ifdef __AVX2__
                        __m256i swap_mask = _mm256_setr_epi8(
                            3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
                            3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
                        );
                        const uint8_t *src = (const uint8_t *)(scrape_resp + 8);
                        Result *r = data->results + data->start + pendings[ch].start;
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
                            data->results[data->start + idx].seeders = ntohl(*(uint32_t *)(scrape_resp + 8 + 12 * j));
                            data->results[data->start + idx].completed = ntohl(*(uint32_t *)(scrape_resp + 8 + 12 * j + 4));
                            data->results[data->start + idx].leechers = ntohl(*(uint32_t *)(scrape_resp + 8 + 12 * j + 8));
                        }
#endif
                        pendings[ch].done = true;
                        outstanding--;
                        break;
                    }
                }
#endif
                }
            }
#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
            else if (use_poller) {
                struct timespec ts = {current_timeout / 1000, (current_timeout % 1000) * 1000000LL};
                bool timed_out = false;
#if defined(__linux__)
                struct epoll_event events[1];
                int nfds = epoll_wait(poller_fd, events, 1, current_timeout);
#else
                struct kevent events[1];
                int nfds = kevent(poller_fd, NULL, 0, events, 1, &ts);
#endif
                if (nfds <= 0) timed_out = true;
                if (timed_out) {
                    thread_retries++;
                    current_timeout *= TIMEOUT_MULTIPLIER;
                    if (current_timeout > MAX_TIMEOUT) current_timeout = MAX_TIMEOUT;
                    continue;
                }
                while (outstanding > 0) {
#if defined(HAVE_RECVMMSG)
                    const int max_batch = 32;
                    struct mmsghdr mmsg[max_batch];
                    struct iovec iov[max_batch];
                    char scrape_resp[max_batch][4096];
                    for (int b = 0; b < max_batch; b++) {
                        iov[b].iov_base = scrape_resp[b];
                        iov[b].iov_len = 4096;
                        mmsg[b].msg_hdr.msg_iov = &iov[b];
                        mmsg[b].msg_hdr.msg_iovlen = 1;
                        mmsg[b].msg_hdr.msg_name = NULL;
                        mmsg[b].msg_hdr.msg_namelen = 0;
                        mmsg[b].msg_hdr.msg_control = NULL;
                        mmsg[b].msg_hdr.msg_controllen = 0;
                        mmsg[b].msg_hdr.msg_flags = 0;
                        mmsg[b].msg_len = 0;
                    }
                    int num = recvmmsg(sock, mmsg, max_batch, MSG_DONTWAIT, NULL);
                    if (num <= 0) {
                        if (num < 0 && (ERR == EAGAIN || ERR == EWOULDBLOCK)) break;
                        break;
                    }
                    for (int b = 0; b < num; b++) {
                        int resp_len = mmsg[b].msg_len;
                        if (resp_len <= 0) continue;
                        uint32_t action = ntohl(*(uint32_t *)scrape_resp[b]);
                        uint32_t trans_id = ntohl(*(uint32_t *)(scrape_resp[b] + 4));
                        if (action != SCRAPE_ACTION) continue;
                        for (size_t ch = 0; ch < max_chunks; ch++) {
                            if (pendings[ch].trans_id == trans_id && !pendings[ch].done) {
                                size_t exp_len = 8 + 12 * pendings[ch].count;
                                if ((size_t)resp_len < exp_len) break;
#ifdef __AVX2__
                                __m256i swap_mask = _mm256_setr_epi8(
                                    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
                                    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
                                );
                                const uint8_t *src = (const uint8_t *)(scrape_resp[b] + 8);
                                Result *r = data->results + data->start + pendings[ch].start;
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
                                    data->results[data->start + idx].seeders = ntohl(*(uint32_t *)(scrape_resp[b] + 8 + 12 * j));
                                    data->results[data->start + idx].completed = ntohl(*(uint32_t *)(scrape_resp[b] + 8 + 12 * j + 4));
                                    data->results[data->start + idx].leechers = ntohl(*(uint32_t *)(scrape_resp[b] + 8 + 12 * j + 8));
                                }
#endif
                                pendings[ch].done = true;
                                outstanding--;
                                break;
                            }
                        }
                    }
#else
                    char scrape_resp[4096];
                    ssize_t resp_len = recv(sock, scrape_resp, sizeof(scrape_resp), MSG_DONTWAIT);
                    if (resp_len <= 0) {
                        if (ERR == EAGAIN || ERR == EWOULDBLOCK) break;
                        else break;
                    }
                    uint32_t action = ntohl(*(uint32_t *)scrape_resp);
                    uint32_t trans_id = ntohl(*(uint32_t *)(scrape_resp + 4));
                    if (action != SCRAPE_ACTION) continue;
                    for (size_t ch = 0; ch < max_chunks; ch++) {
                        if (pendings[ch].trans_id == trans_id && !pendings[ch].done) {
                            size_t exp_len = 8 + 12 * pendings[ch].count;
                            if ((size_t)resp_len < exp_len) break;
#ifdef __AVX2__
                            __m256i swap_mask = _mm256_setr_epi8(
                                3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
                                3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
                            );
                            const uint8_t *src = (const uint8_t *)(scrape_resp + 8);
                            Result *r = data->results + data->start + pendings[ch].start;
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
                                data->results[data->start + idx].seeders = ntohl(*(uint32_t *)(scrape_resp + 8 + 12 * j));
                                data->results[data->start + idx].completed = ntohl(*(uint32_t *)(scrape_resp + 8 + 12 * j + 4));
                                data->results[data->start + idx].leechers = ntohl(*(uint32_t *)(scrape_resp + 8 + 12 * j + 8));
                            }
#endif
                            pendings[ch].done = true;
                            outstanding--;
                            break;
                        }
                    }
#endif
                }
            }
#endif
            if (poller_fd >= 0) CLOSE(poller_fd);
#endif
        }
        int still_out = 0;
        for (size_t ch = 0; ch < max_chunks; ch++) if (!pendings[ch].done) still_out++;
        if (still_out == 0) break;
        thread_retries++;
        current_timeout = current_timeout * TIMEOUT_MULTIPLIER < MAX_TIMEOUT ? current_timeout * TIMEOUT_MULTIPLIER : MAX_TIMEOUT;
    }
    timestamp_t scrape_end = timer_get();

    free(pendings);
    if (use_io) destroy_io_ctx(io_ctx);
    CLOSE(sock);

    size_t json_capacity = data->count * 128 + 1;
    data->json = malloc(json_capacity);
    if (data->json) {
        char *p = data->json;
        for (size_t j = 0; j < data->count; j++) {
            if (j > 0) *p++ = ',';
            memcpy(p, "{\"info_hash\":\"", 14); p += 14;
            memcpy(p, data->hashes[data->start + j].hex, 40); p += 40;
            memcpy(p, "\",\"seeders\":", 11); p += 11;
            p = u32_to_char(data->results[data->start + j].seeders, p);
            memcpy(p, ",\"leechers\":", 12); p += 12;
            p = u32_to_char(data->results[data->start + j].leechers, p);
            memcpy(p, ",\"completed\":", 13); p += 13;
            p = u32_to_char(data->results[data->start + j].completed, p);
            *p++ = '}';
        }
        *p = '\0';
    } else {
        data->json = NULL;
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    timer_init();
    timestamp_t total_start = timer_get();
    long long start_ms = now_ms();

#ifdef _WIN32
    timestamp_t init_start = timer_get();
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) return 1;
    timestamp_t init_end = timer_get();
#endif

    if (unlikely(argc < 2)) {
        fprintf(stderr, "Usage: %s [-v] [-f <file>] [info_hash_hex1] [info_hash_hex2] ...\n", argv[0]);
        return 1;
    }

    int verbose = 0;

    timestamp_t parse_start = timer_get();
    InfoHash* hashes = NULL;
    size_t capacity = 0;
    size_t num_hashes = 0;
    int arg_idx = 1;
    while (arg_idx < argc) {
        if (strcmp(argv[arg_idx], "-v") == 0) {
            verbose = 1;
            arg_idx++;
            continue;
        }
        if (strcmp(argv[arg_idx], "-f") == 0) {
            arg_idx++;
            if (unlikely(arg_idx >= argc)) {
                fprintf(stderr, "Missing file after -f\n");
                return 1;
            }
            FILE* fp = fopen(argv[arg_idx], "rb");
            if (unlikely(!fp)) {
                perror("fopen");
                return 1;
            }
            fseek(fp, 0, SEEK_END);
            long fsize = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            char* buffer = malloc(fsize + 1);
            if (unlikely(!buffer)) {
                fclose(fp);
                return 1;
            }
            size_t read_size = fread(buffer, 1, fsize, fp);
            buffer[read_size] = '\0';
            fclose(fp);
            char* ptr = buffer;
            char* end_ptr = buffer + read_size;
            while (ptr < end_ptr) {
                char* line_start = ptr;
                while (ptr < end_ptr && *ptr != '\r' && *ptr != '\n') ptr++;
                char* line_end = ptr;
                if (ptr < end_ptr && *ptr == '\r') ptr++;
                if (ptr < end_ptr && *ptr == '\n') ptr++;
                while (line_start < line_end && (*line_start == ' ' || *line_start == '\t')) line_start++;
                while (line_end > line_start && (line_end[-1] == ' ' || line_end[-1] == '\t')) line_end--;
                size_t len = line_end - line_start;
                if (len == 40) {
                    if (num_hashes == capacity) {
                        size_t new_capacity = capacity ? capacity * 2 : 1024;
                        InfoHash* new_hashes = realloc(hashes, new_capacity * sizeof(InfoHash));
                        if (unlikely(!new_hashes)) {
                            free(buffer);
                            free(hashes);
                            return 1;
                        }
                        hashes = new_hashes;
                        capacity = new_capacity;
                    }
                    memcpy(hashes[num_hashes].hex, line_start, 40);
                    hashes[num_hashes].hex[40] = '\0';
                    if (hex_to_bin_fast(line_start, hashes[num_hashes].bin) >= 0) {
                        num_hashes++;
                    }
                }
            }
            free(buffer);
            arg_idx++;
        } else {
            const char* hex = argv[arg_idx];
            size_t len = strlen(hex);
            if (len == 40) {
                if (num_hashes == capacity) {
                    size_t new_capacity = capacity ? capacity * 2 : 1024;
                    InfoHash* new_hashes = realloc(hashes, new_capacity * sizeof(InfoHash));
                    if (unlikely(!new_hashes)) {
                        free(hashes);
                        return 1;
                    }
                    hashes = new_hashes;
                    capacity = new_capacity;
                }
                memcpy(hashes[num_hashes].hex, hex, 40);
                hashes[num_hashes].hex[40] = '\0';
                if (hex_to_bin_fast(hex, hashes[num_hashes].bin) >= 0) {
                    num_hashes++;
                }
            }
            arg_idx++;
        }
    }
    if (num_hashes > 0) {
        InfoHash* shrunk = realloc(hashes, num_hashes * sizeof(InfoHash));
        if (shrunk) hashes = shrunk;
    }
    timestamp_t parse_end = timer_get();

    if (unlikely(num_hashes == 0)) { fprintf(stderr, "No valid hashes provided\n"); free(hashes); return 1; }

    struct sockaddr_in servaddr = { .sin_family = AF_INET, .sin_port = htons(1337) };
    inet_pton(AF_INET, "93.158.213.92", &servaddr.sin_addr);

    init_rng();

#ifdef _WIN32
    static bool global_use_rio = false;
#else
    static bool global_use_rio = false;
#endif

    Result *results = malloc(num_hashes * sizeof(Result));
    if (unlikely(!results)) {
        free(hashes);
        return 1;
    }
    memset(results, 0, num_hashes * sizeof(Result));

    size_t num_threads = (num_hashes + MAX_PER_REQUEST - 1) / MAX_PER_REQUEST;
    if (num_threads > 4) num_threads = 4;
    if (num_threads < 1) num_threads = 1;
    if (global_use_rio) num_threads = 1; // simplify for RIO

    THREAD_HANDLE threads[4];
    struct ThreadData td[4];
    size_t per_thread = num_hashes / num_threads;
    size_t extra = num_hashes % num_threads;
    size_t cur = 0;
    for (size_t i = 0; i < num_threads; i++) {
        td[i].start = cur;
        td[i].count = per_thread + (i < extra ? 1 : 0);
        cur += td[i].count;
        td[i].hashes = hashes;
        td[i].results = results;
        td[i].servaddr = servaddr;
        td[i].global_use_rio = global_use_rio;
        td[i].scrape_timeout_ms = 1000; // default, will set later
        td[i].rtt_sec = 0.1; // default
        td[i].json = NULL;
        CREATE_THREAD(threads[i], scrape_thread, &td[i]);
    }

    timestamp_t json_start = timer_get();
    putchar('[');
    for (size_t i = 0; i < num_threads; i++) {
        JOIN_THREAD(threads[i]);
        if (i > 0) putchar(',');
        if (td[i].json) {
            fputs(td[i].json, stdout);
            free(td[i].json);
        }
    }
    putchar(']');
    putchar('\n');
    timestamp_t json_end = timer_get();

    free(results);
    free(hashes);

    timestamp_t total_end = timer_get();
    long long duration_ms = now_ms() - start_ms;
    if (verbose) {
#ifdef _WIN32
        printf("Initialization time: %lld ns\n", timer_diff_ns(init_start, init_end));
#endif
        printf("Hash parsing time: %lld ns\n", timer_diff_ns(parse_start, parse_end));
        printf("Execution time: %lld ms\n", duration_ms);
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
