// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <kernel/panic.h>
#include <kernel/thread.h>
#include <trace.h>

void __do_panic(const char *file __maybe_unused,
		const int line __maybe_unused,
		const char *func __maybe_unused,
		const char *msg __maybe_unused)
{
	// Set thread info registers to default values
    __afl_set_ctx_ptr(0);

	/* disable prehemption */
	(void)thread_mask_exceptions(THREAD_EXCP_ALL);

	/* TODO: notify other cores */

	/* trace: Panic ['panic-string-message' ]at FILE:LINE [<FUNCTION>]" */
	if (!file && !func && !msg)
		EMSG_RAW("Panic");
	else
		EMSG_RAW("Panic %s%s%sat %s:%d %s%s%s",
			 msg ? "'" : "", msg ? msg : "", msg ? "' " : "",
			 file ? file : "?", file ? line : 0,
			 func ? "<" : "", func ? func : "", func ? ">" : "");

	EPRINT_STACK();
	/* abort current execution */

	struct tee_ta_session *sess;

    //EMSG("Resume: tee_ta_get_current_session(&sess) == TEE_SUCCESS: %x", tee_ta_get_current_session(&sess) == TEE_SUCCESS);    

    if (tee_ta_get_current_session(&sess) == TEE_SUCCESS && sess->afl_ctx && sess->afl_ctx->enabled) {
    	EMSG_RAW("AFL Input:");
        //hexdump(sess->afl_ctx->input, sess->afl_ctx->input_len);
        dhex_dump(NULL, 0, 0, sess->afl_ctx->input, sess->afl_ctx->input_len);
    }

	while (1)
		;
}
