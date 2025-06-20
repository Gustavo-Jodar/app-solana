#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <setjmp.h>
#include <stddef.h>
#include "os.h"
#include "utils.h"
#include "transaction_summary.h"
#include "sol/message.h"
#include "sol/parser.h"
#include "apdu.h"
#include "io.h"
#include <string.h>
#include "mock/mocks.h"

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

void handleApdu(volatile unsigned int *flags, volatile unsigned int *tx, int rx) {
    if (!flags || !tx) {
        THROW(ApduReplySdkInvalidParameter);
    }

    if (rx < 0) {
        THROW(ApduReplySdkExceptionIoOverflow);
    }

    const int ret = apdu_handle_message(G_io_apdu_buffer, rx, &G_command);
    if (ret != 0) {
        PRINTF("Clear received invalid command\n");
        MEMCLEAR(G_command);
        THROW(ret);
    }

    if (G_command.state == ApduStatePayloadInProgress) {
        PRINTF("Received first chunk of split payload\n");
        THROW(ApduReplySuccess);
    }

    switch (G_command.instruction) {
        case InsDeprecatedGetAppConfiguration:
        case InsGetAppConfiguration:
            G_io_apdu_buffer[0] = N_storage.settings.allow_blind_sign;
            G_io_apdu_buffer[1] = N_storage.settings.pubkey_display;
            G_io_apdu_buffer[2] = MAJOR_VERSION;
            G_io_apdu_buffer[3] = MINOR_VERSION;
            G_io_apdu_buffer[4] = PATCH_VERSION;
            *tx = 5;
            THROW(ApduReplySuccess);

        case InsDeprecatedGetPubkey:
        case InsGetPubkey:
            handle_get_pubkey(flags, tx);
            break;

        case InsDeprecatedSignMessage:
        case InsSignMessage:
            handle_sign_message_parse_message(tx);
            handle_sign_message_ui(flags);
            break;

        case InsSignOffchainMessage:
            handle_sign_offchain_message(flags, tx);
            break;

        case InsTrustedInfoGetChallenge:
            handle_get_challenge(tx);
            break;

        case InsTrustedInfoProvideInfo:
            handle_provide_trusted_info();
            break;
        
        case InsTrustedInfoProvideDynamicDescriptor:
            handle_provide_dynamic_descriptor();
            break;

        default:
            THROW(ApduReplyUnimplementedInstruction);
    }
}

static void reset_main_globals(void) {
    MEMCLEAR(G_command);
    MEMCLEAR(G_io_seproxyhal_spi_buffer);
}

ApduCommand G_command;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if(setjmp(fuzz_exit_jump_ctx.jmp_buf) != 0)
        return 0;
    
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;
    
    reset_getpubkey_globals();
    reset_main_globals();
    roll_challenge();
    memset(&G_io_apdu_buffer, 0, IO_APDU_BUFFER_SIZE);

    // FIRST APDU bytes to get to the desired function
    uint8_t apdu_first_bytes[] = {
        0xE0, 0x06, 0x01, 0x00, 0xA4, 0x01, 0x03, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x01,
        0xF5, 0x80, 0x00, 0x30, 0x39, 0x02, 0x00, 0x01, 0x03, 0x21, 0xA3, 0x6F, 0xE7, 0x4E,
        0x12, 0x34, 0xC3, 0x5E, 0x62, 0xBF, 0xD7, 0x00, 0xFD, 0x24, 0x7B, 0x92, 0xC4, 0xD4,
        0xE0, 0xE5, 0x38, 0x40, 0x1A, 0xC5, 0x1F, 0x5C, 0x4A, 0xE9, 0x76, 0x57, 0xA7, 0x94,
        0x02, 0x68, 0xAC, 0x4C, 0x37, 0xEA, 0x0B, 0xC9, 0x6C, 0x9C, 0x40, 0xEF, 0x33, 0xAC,
        0xE0, 0x7A, 0x30, 0x34, 0xD6, 0x50, 0xC4, 0x37, 0x37, 0xFE, 0xA9, 0x56, 0x8B, 0x8C,
        0x91, 0xDA, 0x54
    };

    const uint8_t *entry = apdu_first_bytes;

    const size_t first_len = sizeof(apdu_first_bytes);

    if (size + first_len < IO_APDU_BUFFER_SIZE) {
        
        // Append fixed + fuzz data to APDU buffer
        memcpy(G_io_apdu_buffer, entry, first_len);
        memcpy(G_io_apdu_buffer + first_len, data, size);
        rx = first_len + size;
        
        G_io_apdu_buffer[OFFSET_LC] = size;

        handleApdu(&flags, &tx, rx);
    }

    return 0;
}

