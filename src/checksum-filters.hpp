#pragma once

#include <memory>
#include <boost/iostreams/constants.hpp>
#include <boost/iostreams/categories.hpp>
#include <openssl/evp.h>
#include <openssl/sha.h>

class sha256_filter {
public:
	std::shared_ptr<EVP_MD_CTX> hasher{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
	unsigned char digest[SHA256_DIGEST_LENGTH]{};
	typedef char char_type;

	struct category : boost::iostreams::output,
			  boost::iostreams::input,
			  boost::iostreams::filter_tag,
			  boost::iostreams::multichar_tag,
			  boost::iostreams::closable_tag {};

	/* FIXME TODO Signal that errors happened somehow */
	sha256_filter()
	{
		if (hasher)
			EVP_DigestInit_ex(hasher.get(), EVP_sha256(), nullptr);
	}

	template<typename Sink> std::streamsize write(Sink &dest, const char *s, std::streamsize n)
	{
		if (hasher)
			EVP_DigestUpdate(hasher.get(), s, n);
		boost::iostreams::write(dest, s, n);
		return n;
	}

	template<typename Source> std::streamsize read(Source &src, char *s, std::streamsize n)
	{
		std::streamsize result = boost::iostreams::read(src, s, n);

		if (result == -1)
			return result;

		if (hasher)
			EVP_DigestUpdate(hasher.get(), s, result);
		return result;
	}

	template<class Device> void close(Device &device)
	{
		if (hasher)
			EVP_DigestFinal_ex(hasher.get(), &digest[0], nullptr);
	}
};