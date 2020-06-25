#ifndef __KERNEL_AFL_H
#define __KERNEL_AFL_H

#include <assert.h>
#include <kernel/tee_ta_manager.h>

#define AFL_FULL_MAP
//#define AFL_DEBUG

#define MAP_SIZE (1 << 16)
#define FULL_MAP_SIZE (1 << 16)

typedef struct afl_ctx {
    bool enabled;
    char bitmap[MAP_SIZE];
    uint64_t prev_loc;

    void* input;
    size_t input_len;
};

typedef struct afl_svc_trace_ctx {
    bool trace_enabled;

    // cmd buffer
    void* cmd_buf; /* malloc */
    void* cmd_buf_last_p;
    void* cmd_buf_last_append_p;

    // data buffer
    void* data_buf;  /* malloc */
    void* data_buf_append_p;

    // buffer ids
    uint32_t num_bufs;
    void** buf_ptrs;  /* malloc */
    uint32_t* buf_sizes;  /* malloc */

    // handles
    uint32_t num_handles;
    uint32_t* handles;  /* malloc */
    uint32_t* handle_buf_ids;  /* malloc */
};

/* called from thread.c */
void __afl_thread_suspend(void);
void __afl_thread_resume(void);

struct thread_svc_regs;

void __afl_svc_trace_log_call(uint64_t scn, struct thread_svc_regs *regs, uint64_t* args);
void __afl_svc_trace_log_call_post(uint64_t scn, const struct thread_svc_regs *regs, const uint64_t* args);

/* called by afl-tee TA */
TEE_Result syscall_afl_cov_bitmap_init(void* input, size_t input_len);
TEE_Result syscall_afl_cov_bitmap_shutdown(void* dst);

/* called by afl-tee PTA */
TEE_Result afl_svc_trace_start(uint32_t session_id);
TEE_Result afl_svc_trace_stop(uint32_t session_id, void* dst, uint32_t* dst_len);

#ifdef AFL_FULL_MAP
TEE_Result afl_copy_full_map(void* buf, size_t* buf_len);
TEE_Result afl_reset_full_map();
#endif

static inline struct afl_ctx* __afl_ctx_ptr(void) {
    register uintptr_t ptr;

    /* Note: tpidrro_el0 is readable by EL0, however this will only leak a kernel VA */
    __asm volatile ("mrs %0, tpidrro_el0" : "=r" (ptr) );

    return (struct afl_ctx*)ptr;
}

static inline void __afl_set_ctx_ptr(struct afl_ctx* ptr) {
    asm volatile("msr tpidrro_el0, %0" :: "r" (ptr) : "memory");
}

#endif