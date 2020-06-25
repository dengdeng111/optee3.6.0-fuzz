#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include <kernel/panic.h>
#include <kernel/thread.h>
#include <kernel/tee_ta_manager.h>

#include <mm/tee_mmu.h>

#include <tee/tee_svc.h>

#include <initcall.h>
#include <platform_config.h>
#include <tee_syscall_numbers.h>

#include <kernel/afl.h>

// evil hack
#define abort panic

#include "../../../afl-tee/shared/info.c"
#include "../../../afl-tee/shared/validate.c"

#include "../../../afl-tee/shared/include/afl-tee-trace.h"

static bool has_buffer(struct afl_svc_trace_ctx* ctx, void* ptr, size_t size) {
    if (ctx->buf_ptrs && ctx->buf_sizes) {
        for (uint32_t i = 0; i < ctx->num_bufs; i++) {
            if (ctx->buf_ptrs[i] == ptr && size <= ctx->buf_sizes[i]) {
                return true;
            }
        }
    }

    return false;
}

static uint32_t lookup_buffer_id(struct afl_svc_trace_ctx* ctx, void* ptr, size_t size) {
    if (ctx->buf_ptrs && ctx->buf_sizes) {
        for (uint32_t i = 0; i < ctx->num_bufs; i++) {
            if (ctx->buf_ptrs[i] == ptr && size <= ctx->buf_sizes[i]) {
                return i;
            }
        }
    }

    assert(0);
}

static uint32_t assign_buffer_id(struct afl_svc_trace_ctx* ctx, void* ptr, size_t size) {
    assert(ctx->num_bufs + 1 < MAX_BUF_COUNT);

    ctx->buf_ptrs = (void**)realloc(ctx->buf_ptrs, (ctx->num_bufs + 1) * sizeof(void*));
    ctx->buf_sizes = (uint32_t*)realloc(ctx->buf_sizes, (ctx->num_bufs + 1) * sizeof(&ctx->buf_sizes[0]));

    assert(ctx->buf_ptrs != NULL);
    assert(ctx->buf_sizes != NULL);

    ctx->buf_ptrs[ctx->num_bufs] = ptr;
    ctx->buf_sizes[ctx->num_bufs] = size;

    return ctx->num_bufs++;
}

static inline size_t get_buf_size(uint32_t scn, uint64_t* args, uint64_t arg_info) {
    uint8_t len_arg_nr = GET_ARG_BUF_LEN_ARG(arg_info);
    uint8_t arg_buf_size = GET_ARG_BUF_SIZE(arg_info);

    //EMSG("get_buf_size(%x, %p, %x)", scn, args, arg_info);
    //EMSG(" len_arg_nr = %x", len_arg_nr);
    //EMSG(" arg_buf_size = %x", arg_buf_size);
    
    if (len_arg_nr < syscall_num_args(scn)) {
        uint32_t len_arg_info = syscall_arg_info(scn, len_arg_nr);

        //EMSG(" len_arg_info = %x", len_arg_info);

        switch (len_arg_info & 0xFF) {
            case ARG_VALUE:
                if (arg_buf_size > 0) {
                    return args[len_arg_nr] * arg_buf_size;
                }
                else {
                    return args[len_arg_nr];
                }

            case ARG_VALUE_INOUT_PTR: {
                uint32_t len = 0;

                if (tee_svc_copy_from_user(&len, args[len_arg_nr], sizeof(len)) == TEE_SUCCESS) {
                    if (arg_buf_size > 0) {
                        return len * arg_buf_size;
                    }
                    else {
                        return len;
                    }
                }
                break;
            }

            default:
                EMSG("Unexpected arg type: %x", len_arg_info);
                assert(0);
        }
    }
    else if (arg_buf_size > 0) {
        return arg_buf_size;
    }

    return SIZE_MAX;
}

static inline bool has_handle(struct afl_svc_trace_ctx* ctx, uint32_t handle) {
    for (uint32_t i = 0; i < ctx->num_handles; i++) {
        if (ctx->handles[i] == handle) {
            return true;
        }
    }

    return false;
}

static inline uint32_t lookup_handle_buffer_id(struct afl_svc_trace_ctx* ctx, uint32_t handle) {
    for (uint32_t i = 0; i < ctx->num_handles; i++) {
        if (ctx->handles[i] == handle) {
            return ctx->handle_buf_ids[i];
        }
    }

    assert(0);
}

static inline void track_created_handles(struct afl_svc_trace_ctx* ctx, uint32_t scn, uint64_t* args) {
    for (uint32_t i = 0; i < syscall_num_args(scn); i++) {
        uint64_t arg_info = syscall_arg_info(scn, i);

        switch (arg_info & 0xFF) {
            case ARG_HANDLE_OUT_PTR:
                {
                    uint32_t handle;

                    assert(has_buffer(ctx, (void*)args[i], sizeof(handle))); // we should have one assigned in append_cmd()
                    assert(tee_svc_copy_from_user(&handle, (void*)args[i], sizeof(handle)) == TEE_SUCCESS);

                    if (has_handle(ctx, handle)) {
                        assert(lookup_handle_buffer_id(ctx, handle) == lookup_buffer_id(ctx, (void*)args[i], sizeof(handle)));
                    }
                    else { // register as a new handle
                        ctx->handles = realloc(ctx->handles, (ctx->num_handles + 1) * sizeof(handle));
                        ctx->handle_buf_ids = realloc(ctx->handle_buf_ids, (ctx->num_handles + 1) * sizeof(handle));

                        assert(ctx->handles != NULL);
                        assert(ctx->handle_buf_ids != NULL);

                        ctx->handles[ctx->num_handles] = handle;
                        ctx->handle_buf_ids[ctx->num_handles] = lookup_buffer_id(ctx, (void*)args[i], sizeof(handle));

                        ctx->num_handles++;
                    }
                }
                break;
        }
    }
}

static inline void print_invoke_syscall_info(uint32_t scn, uint64_t* args) {
    static char buf[256] = {0};

    size_t off = 0;

    off += snprintf(&buf[off], sizeof(buf) - off, "%s[%i](", syscall_name(scn), scn);

    for (uint32_t i = 0; i < syscall_num_args(scn); i++) {
        if (i >= 1) {
            off += snprintf(&buf[off], sizeof(buf) - off, ", ");
        }

        uint64_t arg_info = syscall_arg_info(scn, i);

        switch (arg_info & 0xFF) {
            case ARG_VALUE:
            case ARG_HANDLE:

            case ARG_VALUE_OUT_PTR:
            case ARG_HANDLE_OUT_PTR:
                off += snprintf(&buf[off], sizeof(buf) - off, "%x", args[i]);
                break;

            case ARG_VALUE_INOUT_PTR:
                {
                    uint32_t val;

                    if (tee_svc_copy_from_user(&val, (void*)args[i], sizeof(val)) == TEE_SUCCESS) {
                        off += snprintf(&buf[off], sizeof(buf) - off, "%x=%x", args[i], val);    
                    }
                    else {
                        off += snprintf(&buf[off], sizeof(buf) - off, "%x=<invalid addr>", args[i]);    
                    }
                }
                break;

            case ARG_BUF_IN_ADDR:
            case ARG_BUF_OUT_ADDR:
            case ARG_BUF_INOUT_ADDR:
                off += snprintf(&buf[off], sizeof(buf) - off, "*%x:%x", args[i], get_buf_size(scn, args, arg_info));
                break;

            default:
                assert(0);
        }
    }

    trace_ext_puts(buf);

    // Dump attributes
    off = 0;
    off += snprintf(&buf[off], sizeof(buf) - off, ")\n");

    for (uint32_t i = 0; i < syscall_num_args(scn); i++) {
        uint64_t arg_info = syscall_arg_info(scn, i);

        switch (arg_info & 0xFF) {
            case ARG_BUF_IN_ADDR:
            case ARG_BUF_INOUT_ADDR:
                if (GET_ARG_BUF_TYPE(arg_info) > 0) {
                    switch (GET_ARG_BUF_TYPE(arg_info)) {
                        case ARG_TYPE_ATTR: 
                            {
                                uint32_t num_args = get_buf_size(scn, args, arg_info) / sizeof(struct utee_attribute);

                                assert(get_buf_size(scn, args, arg_info) % sizeof(struct utee_attribute) == 0);

                                struct utee_attribute attr;

                                for (uint32_t attrn = 0; attrn < num_args; attrn++) {
                                    assert(tee_svc_copy_from_user(&attr, &((struct utee_attribute*)args[i])[attrn], sizeof(attr)) == TEE_SUCCESS);

                                    off += snprintf(&buf[off], sizeof(buf) - off, " attr %x { id: %x, a: %x, b: %x }\n", attrn, attr.attribute_id, attr.a, attr.b);
                                }
                            }
                            break;

                        default:
                            assert(0);
                    }
                }
                break;
        }
    }

    trace_ext_puts(buf);
}

static inline void print_post_invoke_syscall_info(uint32_t scn, uint64_t* args, uint32_t ret_val) {
    static char buf[256] = {0};
    size_t off = 0;

    bool had_first = false;

    for (uint32_t i = 0; i < syscall_num_args(scn); i++) {
        if (had_first) {
            off += snprintf(&buf[off], sizeof(buf) - off, ", ");
        }

        uint64_t arg_info = syscall_arg_info(scn, i);

        switch (arg_info & 0xFF) {
            case ARG_HANDLE_OUT_PTR:
                if (had_first) {
                    off += snprintf(&buf[off], sizeof(buf) - off, ", ");
                }
                else {
                    off += snprintf(&buf[off], sizeof(buf) - off, " [");
                    had_first = true;
                }

                off += snprintf(&buf[off], sizeof(buf) - off, "*%p = %x", args[i], *((uint32_t*)args[i]));
                break;
        }
    }

    if (had_first) {
        off += snprintf(&buf[off], sizeof(buf) - off, "]\n");
    }

    if (off > 0)
        trace_ext_puts(buf);
}

static void validate_args(uint64_t scn, uint64_t* args) {
    for (uint32_t i = 0; i < syscall_num_args(scn); i++) {
        uint64_t arg_info = syscall_arg_info(scn, i);

        switch (arg_info & 0xFF) {
            case ARG_VALUE:
            case ARG_HANDLE:

            case ARG_VALUE_OUT_PTR:
            case ARG_VALUE_INOUT_PTR:
            case ARG_HANDLE_OUT_PTR: // Upper bits are not used
                assert((arg_info >> 8) == 0);
                break;

            case ARG_BUF_IN_ADDR:
            case ARG_BUF_OUT_ADDR:
            case ARG_BUF_INOUT_ADDR:
                //assert(get_buf_size(scn, args, arg_info) != SIZE_MAX);
                //assert(get_buf_size(scn, args, arg_info) < 1 << 20);
                break;

            default:
                EMSG("validate_args(): Unexpected arg type: %x", arg_info);
                assert(0);
        }
    }
}

static inline bool is_valid_address(void* addr, size_t len) {
    struct tee_ta_session *s;

    if (tee_ta_get_current_session(&s) != TEE_SUCCESS)
        assert(0);

    return tee_mmu_check_access_rights(to_user_ta_ctx(s->ctx),
                                       TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER,
                                       (uaddr_t)addr, len) == TEE_SUCCESS;
}

static uint32_t determine_arg_type(struct afl_svc_trace_ctx* ctx, uint64_t scn, uint64_t* args) {
    uint32_t cmd_arg_type = 0;

    for (uint32_t i = 0; i < syscall_num_args(scn); i++) {
        uint64_t arg_info = syscall_arg_info(scn, i);

        switch (arg_info & 0xFF) {
            case ARG_VALUE:
                SET_ARG_TYPE(cmd_arg_type, i, ARG_VALUE_32);
                break;

            case ARG_HANDLE:
                // There are a bunch of test cases that use bad handles
                // Also, in some cases the handle is optional
                if (has_handle(ctx, args[i])) { 
                    SET_ARG_TYPE(cmd_arg_type, i, ARG_BUFFER_DEREF32);
                }
                else {
                    SET_ARG_TYPE(cmd_arg_type, i, ARG_VALUE_32);
                }
                break;

            case ARG_VALUE_OUT_PTR:
            case ARG_HANDLE_OUT_PTR:
            case ARG_BUF_OUT_ADDR:
                {
                    void* buf_ptr = (void*)args[i];
                    size_t buf_size = (((arg_info & 0xFF) == ARG_VALUE_OUT_PTR || (arg_info & 0xFF) == ARG_HANDLE_OUT_PTR) ? sizeof(uint64_t) : get_buf_size(scn, args, arg_info));

                    if (is_valid_address(buf_ptr, buf_size) && buf_size) {
                        if (has_buffer(ctx, (void*)args[i], buf_size)) {
                            SET_ARG_TYPE(cmd_arg_type, i, ARG_BUFFER_REF);
                        }
                        else {
                            SET_ARG_TYPE(cmd_arg_type, i, ARG_BUFFER_ALLOC);
                        }
                    }
                    else {
                        EMSG("Ignore invalid address: %p:%x", buf_ptr, buf_size);

                        SET_ARG_TYPE(cmd_arg_type, i, ARG_VALUE_32);
                    }
                }
                break;

            case ARG_VALUE_INOUT_PTR:
            case ARG_BUF_IN_ADDR:
            case ARG_BUF_INOUT_ADDR:
                {
                    void* buf_ptr = (void*)args[i];
                    size_t buf_size = (((arg_info & 0xFF) == ARG_VALUE_INOUT_PTR) ? sizeof(uint64_t) : get_buf_size(scn, args, arg_info));
                    
                    if (is_valid_address(buf_ptr, buf_size) && buf_size) {
                        if (GET_ARG_BUF_TYPE(arg_info) > 0 && GET_ARG_BUF_TYPE(arg_info) == ARG_TYPE_ATTR) {
                            uint32_t num_args = 0;
                            size_t data_size = 0;
                            size_t data_offset = 0;

                            struct utee_attribute attr = {0};

                            buf_size = get_buf_size(scn, args, arg_info);
                            num_args = buf_size / sizeof(struct utee_attribute);

                            assert(buf_size % sizeof(struct utee_attribute) == 0);
                            assert(num_args > 0);

                            if (num_args > 1) /* TODO: multi attr support */
                                num_args = 1;

                            assert(tee_svc_copy_from_user(&attr, (void*)args[i], sizeof(attr)) == TEE_SUCCESS);

                            if (is_valid_address(attr.a, attr.b) && attr.b) {
                                SET_ARG_TYPE(cmd_arg_type, i, ARG_TEE_ATTR);
                            }
                            else { /* TODO: support attr without addresses */
                                EMSG("Ignore invalid attr address: %p:%x", buf_ptr, buf_size);

                                SET_ARG_TYPE(cmd_arg_type, i, ARG_VALUE_32);
                            }
                        }
                        // Did we see this buffer before?
                        else if (has_buffer(ctx, (void*)args[i], buf_size)) {
                            SET_ARG_TYPE(cmd_arg_type, i, ARG_BUFFER_REF);
                        }
                        else {
                            SET_ARG_TYPE(cmd_arg_type, i, ARG_DATA_PRIVATE);
                        }
                    }
                    else {
                        EMSG("Ignore invalid address: %p:%x", buf_ptr, buf_size);

                        SET_ARG_TYPE(cmd_arg_type, i, ARG_VALUE_32);
                    }
                }
                break;

            default:
                assert(0);
        }
    }

    return cmd_arg_type;
}

static void append_cmd(struct afl_svc_trace_ctx* ctx, uint64_t scn, uint64_t* args) {
    uint32_t cmd_arg_type = determine_arg_type(ctx, scn, args);

    uintptr_t cmd_buff_size = (uintptr_t)ctx->cmd_buf_last_append_p - (uintptr_t)ctx->cmd_buf;

    if (cmd_buff_size > 1024) { // Max 1 kb of commands
        return;
    }

    ctx->cmd_buf = realloc(ctx->cmd_buf, cmd_buff_size + max_invoke_entry_size());

    assert(ctx->cmd_buf != NULL);

    ctx->cmd_buf_last_append_p = (uintptr_t)ctx->cmd_buf + cmd_buff_size;
    ctx->cmd_buf_last_p = ctx->cmd_buf_last_append_p;

    CMD_BUF_APPEND(ctx->cmd_buf_last_append_p, scn, cmd_arg_type);

    for (uint32_t i = 0; i < syscall_num_args(scn); i++) {
        uint64_t arg_info = syscall_arg_info(scn, i);
        uint32_t arg_type = GET_ARG_TYPE(cmd_arg_type, i);

        switch (arg_type) {
            case ARG_NONE:
            case ARG_VALUE_NULL:
                break;

            case ARG_VALUE_32:
                CMD_BUF_APPEND_ARG_VALUE32(ctx->cmd_buf_last_append_p, args[i]);
                break;

            case ARG_BUFFER_DEREF32:
                {
                    switch (arg_info & 0xFF) {
                        case ARG_HANDLE:
                            assert(has_handle(ctx, args[i]));

                            CMD_BUF_APPEND_ARG_DEREF32(ctx->cmd_buf_last_append_p, lookup_handle_buffer_id(ctx, args[i]));
                            break;

                        default:
                            assert(0);
                    }
                }
                break;

            case ARG_BUFFER_ALLOC:
                { // Lookup buffer or assign a new one
                    size_t buf_size;
                    uint32_t buf_id;

                    switch (arg_info & 0xFF) {
                        case ARG_VALUE_INOUT_PTR:
                        case ARG_VALUE_OUT_PTR:
                        case ARG_HANDLE_OUT_PTR:
                            buf_size = sizeof(uint64_t);

                            assert(!has_buffer(ctx, (void*)args[i], buf_size));

                            buf_id = assign_buffer_id(ctx, (void*)args[i], buf_size);

                            CMD_BUF_APPEND_ARG_BUFFER_ALLOC(ctx->cmd_buf_last_append_p, buf_id, buf_size);
                            break;

                        case ARG_BUF_IN_ADDR:
                        case ARG_BUF_INOUT_ADDR:
                        case ARG_BUF_OUT_ADDR:
                            buf_size = get_buf_size(scn, args, arg_info);

                            assert(!has_buffer(ctx, (void*)args[i], buf_size));

                            buf_id = assign_buffer_id(ctx, (void*)args[i], buf_size);

                            CMD_BUF_APPEND_ARG_BUFFER_ALLOC(ctx->cmd_buf_last_append_p, buf_id, buf_size);
                            break;

                        default:
                            assert(0);
                    }
                }
                break;

            case ARG_BUFFER_REF:
                { // Lookup buffer or assign a new one
                    size_t buf_size;

                    switch (arg_info & 0xFF) {
                        case ARG_VALUE_INOUT_PTR:
                        case ARG_VALUE_OUT_PTR:
                        case ARG_HANDLE_OUT_PTR:
                            buf_size = sizeof(uint64_t);

                            assert(has_buffer(ctx, (void*)args[i], buf_size));

                            CMD_BUF_APPEND_ARG_BUFFER_REF(ctx->cmd_buf_last_append_p, lookup_buffer_id(ctx, (void*)args[i], buf_size), buf_size);
                            break;

                        case ARG_BUF_IN_ADDR:
                        case ARG_BUF_INOUT_ADDR:
                        case ARG_BUF_OUT_ADDR:
                            buf_size = get_buf_size(scn, args, arg_info);

                            assert(has_buffer(ctx, (void*)args[i], buf_size));

                            CMD_BUF_APPEND_ARG_BUFFER_REF(ctx->cmd_buf_last_append_p, lookup_buffer_id(ctx, (void*)args[i], buf_size), buf_size);
                            break;

                        default:
                            assert(0);
                    }
                }
                break;

            case ARG_DATA_PRIVATE:
                { // Copy data + set offset
                    size_t data_size = 0;
                    size_t data_offset = 0;

                    assert(args[i] != NULL);

                    switch (arg_info & 0xFF) {
                        case ARG_VALUE_INOUT_PTR:
                            data_size = sizeof(uint64_t);

                            data_offset = DATA_BUF_APPEND(ctx->data_buf, (void*)args[i], data_size);

                            CMD_BUF_APPEND_ARG_DATA(ctx->cmd_buf_last_append_p, data_offset, data_size);
                            break;

                        case ARG_BUF_IN_ADDR:
                        case ARG_BUF_INOUT_ADDR:
                            data_size = get_buf_size(scn, args, arg_info);

                            if (data_size > 512) // Even the biggest keys etc should fit in 512 bytes
                                data_size = 512;

                            data_offset = DATA_BUF_APPEND(ctx->data_buf, (void*)args[i], data_size);

                            CMD_BUF_APPEND_ARG_DATA(ctx->cmd_buf_last_append_p, data_offset, data_size);
                            break;

                        default:
                            assert(0);
                    }
                }
                break;

            case ARG_TEE_ATTR:
                {
                    uint32_t num_args = 0;
                    size_t buf_size = 0;
                    size_t data_size = 0;
                    size_t data_offset = 0;

                    struct utee_attribute attr = {0};

                    switch (arg_info & 0xFF) {
                        case ARG_BUF_IN_ADDR:
                            buf_size = get_buf_size(scn, args, arg_info);
                            num_args = buf_size / sizeof(struct utee_attribute);

                            assert(buf_size % sizeof(struct utee_attribute) == 0);

                            if (num_args > 1) /* TODO: multi attr support */
                                num_args = 1;

                            assert(tee_svc_copy_from_user(&attr, (void*)args[i], sizeof(attr)) == TEE_SUCCESS);

                            data_size = attr.b;
                            data_offset = DATA_BUF_APPEND(ctx->data_buf, attr.a, data_size);

                            CMD_BUF_APPEND_ARG_TEE_ATTR(ctx->cmd_buf_last_append_p, attr.attribute_id, data_offset, data_size);
                            break;

                        default:
                            assert(0);
                    }
                }
                break;

            default:
                EMSG("Unexpected arg type: %x", arg_type);
                assert(0);
        }
    }
}  

static void do_svc_log_call(struct afl_svc_trace_ctx* ctx, uint64_t scn, uint64_t* args) {
    print_invoke_syscall_info(scn, args);

    validate_args(scn, args);

    append_cmd(ctx, scn, args);
}

static void do_svc_log_call_post(struct afl_svc_trace_ctx* ctx, uint64_t scn, const uint64_t* args, uint32_t ret_val) {
    print_post_invoke_syscall_info(scn, args, ret_val);

    if (ret_val == TEE_SUCCESS) {
        track_created_handles(ctx, scn, args);
    }
}

static uint64_t get_reg_val(const struct thread_svc_regs *regs, uint32_t reg_nr) {
    uint64_t val = 0;

    switch (reg_nr) {
        #define __SW_CASE(n) \
                case n: \
                    val = regs->x ## n; \
                    break;

        __SW_CASE(0);
        __SW_CASE(1);
        __SW_CASE(2);
        __SW_CASE(3);
        __SW_CASE(4);
        __SW_CASE(5);
        __SW_CASE(6);
        __SW_CASE(7);

        default:
            assert(0);
    }

    return val;
}

// Use this instead of get_reg_val with 32-bit TAs
static uint64_t ta32_get_arg_val(const struct thread_svc_regs *regs, uint32_t reg_nr) {
    if (reg_nr < 4) { // First 4 arguments are passed as registers 
        return get_reg_val(regs, reg_nr);
    }

    uint32_t stack_args = regs->x6;
    uint32_t* stack_args_ptr = (uint32_t*)regs->x5;

    if (reg_nr > stack_args + 4) {
        EMSG("get_arg_val(%i) but %i arguments provided on the stack", reg_nr, stack_args);
        panic();
    }

    return stack_args_ptr[reg_nr - 4];
}

static bool is_svc_ignored(uint64_t scn) {
    switch (scn) {
        case TEE_SCN_RETURN:
        case TEE_SCN_PANIC:
        case TEE_SCN_LOG:
        case TEE_SCN_WAIT:

        case TEE_SCN_OPEN_TA_SESSION:
        case TEE_SCN_CLOSE_TA_SESSION:
        case TEE_SCN_INVOKE_TA_COMMAND:

        /* too noisy for demos */
        case TEE_SCN_CRYP_OBJ_GET_INFO:
            return true;

        default:
            return false;
    }
}

/* Called from arch_svc.c */
void __afl_svc_trace_log_call(uint64_t scn, struct thread_svc_regs *regs, uint64_t* args) {
    struct tee_ta_session *sess;

    assert(tee_ta_get_current_session(&sess) == TEE_SUCCESS);

    if (sess->svc_trace_ctx != NULL && sess->svc_trace_ctx->trace_enabled) {
        if (!is_svc_ignored(scn)) {
            for (uint32_t i = 0; i < syscall_num_args(scn); i++) {
                args[i] = get_reg_val(regs, i);
            }

            do_svc_log_call(sess->svc_trace_ctx, scn, args);
        }
    }
}

void __afl_svc_trace_log_call_post(uint64_t scn, const struct thread_svc_regs *regs, const uint64_t* args) {
    struct tee_ta_session *sess;

    assert(tee_ta_get_current_session(&sess) == TEE_SUCCESS);

    if (sess->svc_trace_ctx != NULL && sess->svc_trace_ctx->trace_enabled) {
        if (!is_svc_ignored(scn)) {
            do_svc_log_call_post(sess->svc_trace_ctx, scn, args, regs->x0);
        }
    }
}

static inline void update_data_offsets(void* buf, uint32_t buf_len, uint32_t data_offset) {
    CTX ctx = {
        .buf = buf,
        .buf_len = buf_len,

        .cmd_first = buf,
        .cmd_current = NULL,

        .data = buf,
        .data_len = buf_len,

        .p_error = NULL
    };

    while (CMD_NEXT(&ctx) != NULL) {
        const SYSCALL_INVOKE* const sys_invoke_p = CMD_CURRENT(&ctx);

        SVC_FOREACH_ARG(sys_invoke_p, 0, syscall_num_args(sys_invoke_p->nr), p_arg, arg_type, {
            switch (arg_type) {
                case ARG_DATA_SHARED:
                case ARG_DATA_PRIVATE:
                    ((SYSCALL_ARG*)p_arg)->data.offset += data_offset;
                    break;

                case ARG_TEE_ATTR:
                    ((SYSCALL_ARG*)p_arg)->tee_attr.offset += data_offset;
                    break;

                default:
                    break;
            }
        });
    }
}

/* entry_std.c */
extern struct tee_ta_session_head tee_open_sessions;

/* Called by AFL-TEE PTA */
TEE_Result afl_svc_trace_start(uint32_t session_id) {
    struct tee_ta_session* sess = tee_ta_get_session(session_id, true, &tee_open_sessions);

    if (sess == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    EMSG("Start tracing... (sess_id: %x)", session_id);

    if (!sess->svc_trace_ctx) {
        sess->svc_trace_ctx = (struct afl_svc_trace_ctx*)malloc(sizeof(struct afl_svc_trace_ctx));

        memset(sess->svc_trace_ctx, 0, sizeof(struct afl_svc_trace_ctx));
    }

    struct afl_svc_trace_ctx* ctx = sess->svc_trace_ctx;

    assert(ctx != NULL);
    assert(!ctx->trace_enabled);

    ctx->trace_enabled = true;

    tee_ta_put_session(sess);

    return TEE_SUCCESS;
}

TEE_Result afl_svc_trace_stop(uint32_t session_id, void* dst, uint32_t* dst_len) {
    struct tee_ta_session* sess = tee_ta_get_session(session_id, true, &tee_open_sessions);

    if (sess == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    EMSG("Stop tracing... (sess_id: %x)", session_id);

    struct afl_svc_trace_ctx* ctx = sess->svc_trace_ctx;

    assert(ctx != NULL);
    assert(ctx->trace_enabled);

    ctx->trace_enabled = false;

    if (CMD_BUF_SIZE(ctx->cmd_buf)) {
        assert(ctx->cmd_buf != NULL);
        assert(ctx->cmd_buf_last_append_p != NULL);

        // Terminate command buffer
        CMD_BUF_APPEND(ctx->cmd_buf_last_append_p, 0xFF, 0);

        size_t cmd_len = CMD_BUF_SIZE(ctx->cmd_buf);
        size_t data_len = DATA_BUF_SIZE(ctx->data_buf);

        EMSG("Cmd len %x Data len %x", cmd_len, data_len);

        if (cmd_len + data_len > *dst_len) {
            return TEE_ERROR_BAD_PARAMETERS;
        }

        update_data_offsets(ctx->cmd_buf, cmd_len, cmd_len);

        memcpy(dst, ctx->cmd_buf, cmd_len);

        if (data_len) {
            assert(ctx->data_buf != NULL);

            memcpy((void*)((uintptr_t) dst + cmd_len), ctx->data_buf, data_len);
        }

        *dst_len = cmd_len + data_len;
    }
    else {
        *dst_len = 0;
    }

    tee_ta_put_session(sess);

    return TEE_SUCCESS;
}

TEE_Result afl_trace_init(void)
{
    __cache_data();

    return TEE_SUCCESS;
}

driver_init(afl_trace_init);