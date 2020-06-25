#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <trace.h>
#include <initcall.h>

#include <platform_config.h>

#include <kernel/afl.h>
#include <kernel/panic.h>
#include <kernel/linker.h>

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
#error AFL support is incompatible with CFG_CORE_UNMAP_CORE_AT_EL0
#endif

extern uint8_t __afl_text_start[];
extern uint8_t __afl_text_end[];

static uintptr_t _text_start = &__afl_text_start;
static uintptr_t _text_end = &__afl_text_end;

#define afl_cov_is_enabled(task_id) ((__afl_cov_enabled & ((uint64_t)1 << task_id)) != 0)
#define afl_cov_enable(task_id) do { __afl_cov_enabled |= (uint64_t)1 << task_id; } while(0);
#define afl_cov_disable(task_id) do { __afl_cov_enabled &= ~((uint64_t)1 << task_id); } while(0);

#ifdef AFL_FULL_MAP
static uint8_t __afl_cov_full_map[FULL_MAP_SIZE];
#endif

#define unlikely(x)     __builtin_expect((x),0)

void __sanitizer_cov_trace_pc(void);

__attribute__( ( always_inline ) ) static inline uint32_t __get_LR(void) {
    register uintptr_t result;

    __asm volatile ("mov %0, x30\n" : "=r" (result) );

    return(result);
}

void __afl_reset_thread_ctx(void) {
    // Set thread info registers to default values
    __afl_set_ctx_ptr(0);
}

void __afl_thread_suspend(void) {
    __afl_reset_thread_ctx();
}

void __afl_thread_resume(void) {
    struct tee_ta_session *sess;

    //EMSG("Resume: tee_ta_get_current_session(&sess) == TEE_SUCCESS: %x", tee_ta_get_current_session(&sess) == TEE_SUCCESS);    

    if (tee_ta_get_current_session(&sess) == TEE_SUCCESS && sess->afl_ctx && sess->afl_ctx->enabled) {
        __afl_set_ctx_ptr(sess->afl_ctx);
    }
}

void __sanitizer_cov_trace_pc(void) {
    uintptr_t addr = (uintptr_t) __get_LR();

    struct afl_ctx* ctx = __afl_ctx_ptr();

    if (ctx != NULL) {
#ifdef AFL_FULL_MAP
        uintptr_t map_addr = (addr - _text_start) >> 1;
        size_t map_idx = map_addr / 8;
        size_t map_bit = map_addr % 8;

        assert(map_idx < sizeof(__afl_cov_full_map));

        __afl_cov_full_map[map_idx] |= 1u << map_bit;
#endif

#ifdef AFL_DEBUG
        struct tee_ta_session *sess;

        assert(tee_ta_get_current_session(&sess) == TEE_SUCCESS);

        if (sess->afl_ctx != ctx) {
            EMSG("ctx: %p != %p", sess->afl_ctx, ctx);
            assert(sess->afl_ctx == ctx);
        }
#endif

        // Right shift 1 as instructions are 2-byte (thumb) or 4-byte aligned(arm or aarch64)
        addr = (addr >> 1);

        //if ((ctx->prev_loc & (~(MAP_SIZE - 1))) != 0) {
        //    EMSG("Incorrect prev_loc: %x mask: %x val: %x", ctx->prev_loc, (~(MAP_SIZE - 1)), ctx->prev_loc & (~(MAP_SIZE - 1)));
        //    assert((ctx->prev_loc & (~(MAP_SIZE - 1))) == 0);
        //}

        ctx->bitmap[(addr ^ ctx->prev_loc) & (MAP_SIZE - 1)]++;
        //ctx->prev_loc = (addr >> 1) & (MAP_SIZE - 1);
        ctx->prev_loc = (addr >> 1); 
    }
}

TEE_Result syscall_afl_cov_bitmap_init(void* input, size_t input_len) {
    struct tee_ta_session *sess;

    assert(tee_ta_get_current_session(&sess) == TEE_SUCCESS);

    assert(sess->afl_ctx == NULL);
    assert(__afl_ctx_ptr() == NULL);

    sess->afl_ctx = malloc(sizeof(struct afl_ctx));

    if (unlikely(sess->afl_ctx == NULL)) {
        EMSG("Out of memory");
        panic();
    }

    memset(sess->afl_ctx, 0, sizeof(struct afl_ctx));

    sess->afl_ctx->input = input;
    sess->afl_ctx->input_len = input_len;

    return TEE_SUCCESS;
}

TEE_Result syscall_afl_cov_bitmap_shutdown(void* dst) {
    struct tee_ta_session *sess;

    assert(tee_ta_get_current_session(&sess) == TEE_SUCCESS);

    assert(sess->afl_ctx != NULL);
    assert(__afl_ctx_ptr() == NULL);

    if (dst) {
        memcpy(dst, sess->afl_ctx->bitmap, MAP_SIZE);
    }

    free(sess->afl_ctx);
    sess->afl_ctx = NULL;

    return TEE_SUCCESS;
}

#ifdef AFL_FULL_MAP
TEE_Result afl_copy_full_map(void* buf, size_t* buf_len) {
    memcpy(buf, __afl_cov_full_map, FULL_MAP_SIZE);

    *buf_len = FULL_MAP_SIZE;

    return TEE_SUCCESS;
}

TEE_Result afl_reset_full_map() {
    memset(__afl_cov_full_map, 0, FULL_MAP_SIZE);

    return TEE_SUCCESS;
}

TEE_Result afl_init(void)
{
    EMSG("AFL cov Start: %x End: %x Map: %x (need: %x)", _text_start, _text_end, sizeof(__afl_cov_full_map), (_text_end - _text_start) / 8ull / 2ull);

    assert((_text_end - _text_start) / 8ull / 2ull < sizeof(__afl_cov_full_map));

    __afl_reset_thread_ctx();

    return TEE_SUCCESS;
}

driver_init(afl_init);
#endif