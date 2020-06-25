#include <compiler.h>
#include <stdio.h>
#include <trace.h>
#include <kernel/pseudo_ta.h>
#include <mm/tee_pager.h>
#include <mm/tee_mm.h>
#include <string.h>
#include <string_ext.h>
#include <malloc.h>
#include <kernel/afl.h>

#define TA_NAME         "afl.ta"

#define AFL_UUID { 0xd96a5b41, 0xe2c8, 0xb1af, { 0x87, 0x94, 0x10, 0x03, 0xa5, 0xd5, 0xc7, 0x1b } }

#define AFL_PTA_CMD_ENABLE_SVC_TRACE            0
#define AFL_PTA_CMD_DISABLE_SVC_TRACE           1
#define AFL_PTA_CMD_COPY_FULL_MAP               2
#define AFL_PTA_CMD_RESET_FULL_MAP              3


static TEE_Result enable_svc_trace(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
    if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE) != type) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    DMSG("Enable SVC tracing for session %x", p[0].value.a);

    return afl_svc_trace_start(p[0].value.a);
}

static TEE_Result disable_svc_trace(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
    if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE) != type) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    DMSG("Disable SVC tracing for session %x", p[0].value.a);

    return afl_svc_trace_stop(p[0].value.a, p[1].memref.buffer, &p[1].memref.size);
}

#ifdef AFL_FULL_MAP
static TEE_Result copy_full_map(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
    if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE) != type) {
        EMSG("expect 1 output values as argument");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (p[0].memref.size < FULL_MAP_SIZE) {
        EMSG("Output buffer too small");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    afl_copy_full_map(p[0].memref.buffer, &p[0].memref.size);

    return TEE_SUCCESS;
}

static TEE_Result reset_full_map(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
    if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE) != type) {
        EMSG("expect no arguments");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    afl_reset_full_map();

    return TEE_SUCCESS;
}
#endif

/*
 * Trusted Application Entry Points
 */

static TEE_Result invoke_command(void *psess __unused,
                                 uint32_t cmd, uint32_t ptypes,
                                 TEE_Param params[TEE_NUM_PARAMS])
{
    switch (cmd) {
        case AFL_PTA_CMD_ENABLE_SVC_TRACE:
            return enable_svc_trace(ptypes, params);
        case AFL_PTA_CMD_DISABLE_SVC_TRACE:
            return disable_svc_trace(ptypes, params);
#ifdef AFL_FULL_MAP
        case AFL_PTA_CMD_COPY_FULL_MAP:
            return copy_full_map(ptypes, params);
        case AFL_PTA_CMD_RESET_FULL_MAP:
            return reset_full_map(ptypes, params);
#endif
        default:
            break;
    }
    return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = AFL_UUID, .name = TA_NAME,
                   .flags = PTA_DEFAULT_FLAGS,
                   .invoke_command_entry_point = invoke_command);
