#define _CRT_RAND_S

#include "security-random.hpp"

#include <cstdlib>

std::wstring security_random_hex(size_t word_count)
{
	static const wchar_t digits[] = L"0123456789abcdef";
	std::wstring result;
	result.reserve(word_count * 8);

	for (size_t word_index = 0; word_index < word_count; word_index++) {
		unsigned int word = 0;
		if (rand_s(&word) != 0)
			return {};

		for (int shift = 28; shift >= 0; shift -= 4)
			result += digits[(word >> shift) & 0xF];
	}

	return result;
}
