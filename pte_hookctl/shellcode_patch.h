/*
 * shellcode_patch.h — ARM64 shellcode runtime patcher.
 *
 * Patches MOVZ/MOVK immediate sequences inside a pre-compiled shellcode
 * template with runtime-determined 64-bit addresses.
 *
 * Only this file is needed on-device; replaces the full Python shellcode.py.
 */
#ifndef SHELLCODE_PATCH_H
#define SHELLCODE_PATCH_H

#include <stdint.h>
#include <string.h>

/*
 * Encode a 64-bit value into 4 consecutive ARM64 MOVZ + MOVK instructions.
 *
 * ARM64 MOVZ encoding:  0xD2800000 | (hw << 21) | (imm16 << 5) | rd
 * ARM64 MOVK encoding:  0xF2800000 | (hw << 21) | (imm16 << 5) | rd
 *
 * Parameters:
 *   code      - pointer to shellcode buffer
 *   offset    - byte offset of the first instruction (MOVZ) in the buffer
 *   value     - 64-bit value to encode
 *   rd        - destination register number (0-30)
 */
static inline void patch_movz_movk_fixed4(uint8_t *code, int offset,
                                           uint64_t value, int rd)
{
    uint16_t parts[4] = {
        (uint16_t)(value & 0xFFFF),
        (uint16_t)((value >> 16) & 0xFFFF),
        (uint16_t)((value >> 32) & 0xFFFF),
        (uint16_t)((value >> 48) & 0xFFFF),
    };

    /* Instruction 0: MOVZ Xd, #parts[0], LSL #0 */
    uint32_t insn = 0xD2800000u | (0u << 21) | ((uint32_t)parts[0] << 5) | (uint32_t)rd;
    memcpy(code + offset, &insn, 4);

    /* Instructions 1-3: MOVK Xd, #parts[i], LSL #(i*16) */
    for (int i = 1; i < 4; i++) {
        insn = 0xF2800000u | ((uint32_t)i << 21) | ((uint32_t)parts[i] << 5) | (uint32_t)rd;
        memcpy(code + offset + i * 4, &insn, 4);
    }
}

/*
 * Strip ARM64 TBI (Top Byte Ignore) tag from a pointer.
 */
static inline uint64_t untag_ptr(uint64_t ptr)
{
    return ptr & 0x00FFFFFFFFFFFFFFull;
}

/*
 * Decode a hex string into a byte buffer.
 * Returns the number of bytes written, or -1 on error.
 */
static inline int hex_decode(const char *hex, uint8_t *out, int max_len)
{
    int len = 0;
    while (hex[0] && hex[1] && len < max_len) {
        unsigned int byte;
        char tmp[3] = { hex[0], hex[1], 0 };
        if (sscanf(tmp, "%02x", &byte) != 1)
            return -1;
        out[len++] = (uint8_t)byte;
        hex += 2;
    }
    return len;
}

/*
 * Encode a byte buffer into a hex string.
 * out must have at least len*2+1 bytes.
 */
static inline void hex_encode(const uint8_t *data, int len, char *out)
{
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        out[i * 2]     = hex_chars[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex_chars[data[i] & 0xF];
    }
    out[len * 2] = '\0';
}

#endif /* SHELLCODE_PATCH_H */
