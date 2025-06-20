#include "mocks.h"
#include "lcx_ecfp.h"
// APPs expect a specific length
cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t *length)
{
    (void) cv;
    *length = (size_t) 32;
    return 0x00000000;
}

// Simulates writing to NVM
void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len)
{
    if (!dst_adr || !src_adr || src_len == 0) {
        return;
    }
    memcpy(dst_adr, src_adr, src_len);
}

try_context_t fuzz_exit_jump_ctx = {0};
try_context_t *G_exception_context = &fuzz_exit_jump_ctx;

try_context_t *try_context_get(void)
{
    return G_exception_context;
}

try_context_t *try_context_set(try_context_t *context)
{
    try_context_t *previous = G_exception_context;
    G_exception_context     = context;
    return previous;
}

void __attribute__((noreturn)) os_sched_exit(bolos_task_status_t exit_code) {
    if(fuzz_exit_jump_ctx.jmp_buf != 0)
        longjmp(fuzz_exit_jump_ctx.jmp_buf, 1);
}

void __attribute__((noreturn)) os_lib_end(void) {
if(fuzz_exit_jump_ctx.jmp_buf != NULL)
        longjmp(fuzz_exit_jump_ctx.jmp_buf, 1);
}

extern uint8_t EXPECTED_key_usage = 0;
extern cx_curve_t EXPECTED_curve = {0};
bolos_err_t os_pki_get_info(uint8_t *key_usage, uint8_t *trusted_name, size_t *trusted_name_len, cx_ecfp_384_public_key_t *public_key) {
    *key_usage = EXPECTED_key_usage;
    public_key->curve = EXPECTED_curve;
    return 0x00; 
}


