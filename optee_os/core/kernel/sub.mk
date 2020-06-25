srcs-$(CFG_CORE_SANITIZE_KADDRESS) += asan.c
cflags-remove-asan.c-y += $(cflags_kasan)
srcs-y += assert.c
srcs-y += console.c
srcs-$(CFG_DT) += dt.c
srcs-y += pm.c
srcs-y += handle.c
srcs-y += interrupt.c
srcs-$(CFG_LOCKDEP) += lockdep.c
srcs-$(CFG_CORE_DYN_SHM) += msg_param.c
srcs-y += panic.c
srcs-y += refcount.c
srcs-y += tee_misc.c
srcs-y += tee_ta_manager.c
srcs-$(CFG_CORE_SANITIZE_UNDEFINED) += ubsan.c
srcs-y += scattered_array.c
srcs-y += huk_subkey.c

srcs-y += afl.c
srcs-y += afl_svc_trace.c

cflags-afl.c-y += -fno-sanitize=all
cflags-asan.c-y += -fno-sanitize=all 
cflags-assert.c-y += -fno-sanitize=all 
cflags-console.c-y += -fno-sanitize=all 
cflags-interrupt.c-y += -fno-sanitize=all 
cflags-msg_param.c-y += -fno-sanitize=all 
cflags-panic.c-y += -fno-sanitize=all 
cflags-refcount.c-y += -fno-sanitize=all 
cflags-tee_ta_manager.c-y += -fno-sanitize=all 
cflags-ubsan.c-y += -fno-sanitize=all 

cflags-afl_svc_trace.c-y += -I../afl-tee/shared/include
cflags-afl_svc_trace.c-y += -Wno-pedantic -Wno-discarded-qualifiers -Wno-missing-prototypes -Wno-switch-default
cflags-afl_svc_trace.c-y += -Wno-unused-parameter -Wno-missing-declarations -Wno-declaration-after-statement -Wno-format

cflags-remove-afl.c-y += -fsanitize-coverage=trace-pc
cflags-remove-afl_svc_trace.c-y += -fsanitize-coverage=trace-pc
cflags-remove-asan.c-y += -fsanitize-coverage=trace-pc
cflags-remove-assert.c-y += -fsanitize-coverage=trace-pc
cflags-remove-console.c-y += -fsanitize-coverage=trace-pc
cflags-remove-interrupt.c-y += -fsanitize-coverage=trace-pc
cflags-remove-msg_param.c-y += -fsanitize-coverage=trace-pc
cflags-remove-panic.c-y += -fsanitize-coverage=trace-pc
cflags-remove-refcount.c-y += -fsanitize-coverage=trace-pc
cflags-remove-tee_misc.c-y += -fsanitize-coverage=trace-pc
cflags-remove-tee_ta_manager.c-y += -fsanitize-coverage=trace-pc
cflags-remove-ubsan.c-y += -fsanitize-coverage=trace-pc