#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

/* Returns word_count * 8 lowercase hexadecimal characters from rand_s, or an
 * empty string when the platform RNG fails. */
std::wstring security_random_hex(size_t word_count);

/* Locale-independent Win32-style hexadecimal formatting. */
std::wstring format_hex32(uint32_t value);
