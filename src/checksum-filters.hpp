#pragma once

#include <boost/iostreams/constants.hpp>
#include <boost/iostreams/categories.hpp>
#include <openssl/sha.h>

class sha256_filter {
public:
	SHA256_CTX hasher;
	unsigned char digest[SHA256_DIGEST_LENGTH]{};
	typedef char char_type;

	struct category : boost::iostreams::output,
			  boost::iostreams::input,
			  boost::iostreams::filter_tag,
			  boost::iostreams::multichar_tag,
			  boost::iostreams::closable_tag {};

	/* FIXME TODO Signal that errors happened somehow */
	sha256_filter() { SHA256_Init(&hasher); }

	template<typename Sink> std::streamsize write(Sink &dest, const char *s, std::streamsize n)
	{
		SHA256_Update(&hasher, s, n);
		boost::iostreams::write(dest, s, n);
		return n;
	}

	template<typename Source> std::streamsize read(Source &src, char *s, std::streamsize n)
	{
		std::streamsize result = boost::iostreams::read(src, s, n);

		if (result == -1)
			return result;

		SHA256_Update(&hasher, s, result);
		return result;
	}

	template<class Device> void close(Device &device) { SHA256_Final(&digest[0], &hasher); }
};