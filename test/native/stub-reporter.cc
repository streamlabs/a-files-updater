/* The tests link the shipped hook-permissions.cc, which reports through the
 * crash reporter. Nothing here talks to Sentry - the category is recorded so a
 * case can assert on it. */

#include "stub-reporter.hpp"

#include <cstdio>
#include <string>

static std::string g_category;

const std::string &last_reported_category()
{
	return g_category;
}

void clear_reported_category()
{
	g_category.clear();
}

void report_handled_error(const std::string &category, const std::string &reason) noexcept
{
	g_category = category;
	printf("      reported %s: %s\n", category.c_str(), reason.c_str());
}
