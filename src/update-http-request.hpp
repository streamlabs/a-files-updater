#pragma once

#include <string>
#include <chrono>

#include <boost/asio.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast.hpp>
#include <boost/bind/bind.hpp>
#include <boost/iostreams/chain.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/traits.hpp>
#include <boost/exception/all.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/locale.hpp>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
namespace beast = boost::beast;
namespace http = boost::beast::http;
namespace ssl = boost::asio::ssl;
namespace bio = boost::iostreams;

struct update_client;
struct update_file_t;

using manifest_body = http::basic_dynamic_body<beast::flat_buffer>;

template<class Body, bool IncludeVersion> struct update_http_request {
	update_http_request(update_client *client_ctx, const std::string &target, const int id);
	~update_http_request();

	size_t download_accum{0};
	size_t content_length{0};
	int worker_id;
	update_client *client_ctx;
	std::string target;
	std::string used_cdn_node_address;

	/* We used to support http and then I realized
	 * I was spending a lot of time supporting both.
	 * Our use case doesn't use it and boost doesn't
	 * allow any convenience to allow using them
	 * interchangeably. Really, my suggestion is that
	 * you should be using ssl regardless anyways. */
	ssl::stream<tcp::socket> ssl_socket;

	http::request<http::empty_body> request;

	beast::multi_buffer response_buf;
	http::response_parser<Body> response_parser;

	void set_sni_hostname();

	/* We need way to detect stuck connection.
	*  For that we use a steady timer what can limit
	*  time for each step of file downloader connection.
	*  Also it limits a receive buffer so a timer limit a too slow fill of the buffer.
	*/
	boost::asio::steady_timer deadline;
	int deadline_default_timeout = 5;
	bool deadline_reached = false;
	int retries = 0;

	void check_deadline_callback_err(const boost::system::error_code &error);
	void switch_deadline_on();

	bool handle_callback_precheck(const boost::system::error_code &error, const std::string &message);
	void handle_download_canceled();
	void handle_download_error(const boost::system::error_code &error, const std::string &str);
	void handle_result(update_file_t *file_ctx);

	void start_connect();
	void handle_connect(const boost::system::error_code &error);
	void handle_handshake(const boost::system::error_code &error);
	void handle_request(boost::system::error_code &error, size_t bytes);
	void handle_response_header(boost::system::error_code &error, size_t bytes);
	void start_reading();
	void handle_response_body(boost::system::error_code &error, size_t bytes_read, update_file_t *file_ctx);
};

// limit response_buf buffer size so together with deadline timeout
// it will create low speed limit for download
// 4kb in 4 seconds is somewhere of old modems
// and be recognized as stuck connection

template<class Body, bool IncludeVersion>
update_http_request<Body, IncludeVersion>::update_http_request(update_client *client_ctx, const std::string &target, const int id)
	: worker_id(id),
	  client_ctx(client_ctx),
	  target(target),
	  ssl_socket(client_ctx->io_ctx, client_ctx->ssl_context),
	  response_buf(file_buffer_size), // see reasons above ^
	  deadline(client_ctx->io_ctx)
{
	std::string full_target;

	if (IncludeVersion) {
		full_target = client_ctx->params->host.path + "/" + client_ctx->params->version + "/" + urlencode(target);
	} else {
		full_target = client_ctx->params->host.path + "/" + target;
	}

	request = {http::verb::get, full_target, 11};

	std::string host = client_ctx->params->host.authority;
	auto colon_pos = host.find(':');
	if (colon_pos != std::string::npos) {
		host = host.substr(0, colon_pos);
	}
	request.set(http::field::host, host);

	request.set(http::field::user_agent, "Streamlabs Desktop updater application/1.0," BOOST_BEAST_VERSION_STRING);
	request.set(http::field::accept, "*/*");

	response_parser.body_limit(std::numeric_limits<unsigned long long>::max());

	deadline.expires_at((std::chrono::steady_clock::time_point::max)());
}

template<class Body, bool IncludeVersion> update_http_request<Body, IncludeVersion>::~update_http_request()
{
	deadline.cancel();
}

template<class Body, bool IncludeVersion> void update_http_request<Body, IncludeVersion>::check_deadline_callback_err(const boost::system::error_code &error)
{
	if (error) {
		if (error == boost::asio::error::operation_aborted) {
			return;
		} else {
			log_error("File download operation deadline error %i", error.value());
			return;
		}
	}

	if (deadline.expiry() <= std::chrono::steady_clock::now()) {
		log_info("Timeout for file download operation triggered for %s", target.c_str());
		deadline_reached = true;

		try {
			deadline.expires_at((std::chrono::steady_clock::time_point::max)());
		} catch (...) {
			log_error("Got error canceling timer");
		}

		// close() (not shutdown()) - only close cancels a pending overlapped read/connect
		// on Windows, so the stalled handler actually fires and the worker is not lost.
		boost::system::error_code ignored_ec;
		ssl_socket.lowest_layer().close(ignored_ec);
	} else {
		// Put the actor back to sleep.
		deadline.async_wait(bind(&update_http_request<Body, IncludeVersion>::check_deadline_callback_err, this, std::placeholders::_1));
	}
}

template<class Body, bool IncludeVersion> void update_http_request<Body, IncludeVersion>::switch_deadline_on()
{
	deadline.expires_after(std::chrono::seconds(deadline_default_timeout));
	check_deadline_callback_err(make_error_code(boost::system::errc::success));
}

template<class Body, bool IncludeVersion>
bool update_http_request<Body, IncludeVersion>::handle_callback_precheck(const boost::system::error_code &error, const std::string &message)
{
	deadline.cancel();

	if (client_ctx->update_download_aborted) {
		handle_download_canceled();
		return true;
	}

	if (error) {
		std::string msg = std::string("Failed to ") + message + ", for : " + target;

		handle_download_error(error, msg);
		return true;
	}

	return false;
}

template<class Body, bool IncludeVersion> void update_http_request<Body, IncludeVersion>::start_connect()
{
	auto connect_handler = [this](auto e, auto) { this->handle_connect(e); };

	switch_deadline_on();

	auto use_node = client_ctx->get_endpoint();

	if (use_node == client_ctx->endpoints.end()) {
		handle_callback_precheck(boost::asio::error::basic_errors::connection_aborted, "get good cdn node");
	} else {
		used_cdn_node_address = (*use_node).endpoint().address().to_string();

		asio::async_connect(ssl_socket.lowest_layer(), use_node, client_ctx->endpoints.end(), connect_handler);
	}
}

template<class Body, bool IncludeVersion> void update_http_request<Body, IncludeVersion>::set_sni_hostname()
{
	if (!SSL_set_tlsext_host_name(ssl_socket.native_handle(), client_ctx->params->host.authority.c_str())) {
		boost::system::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
		handle_callback_precheck(ec, "set SNI hostname");
		return;
	}
}

template<class Body, bool IncludeVersion> void update_http_request<Body, IncludeVersion>::handle_connect(const boost::system::error_code &error)
{
	if (handle_callback_precheck(error, "connect to host")) {
		return;
	}

	set_sni_hostname();

	auto handshake_handler = [this](auto e) { this->handle_handshake(e); };

	switch_deadline_on();

	ssl_socket.async_handshake(ssl::stream_base::handshake_type::client, handshake_handler);
}

template<class Body, bool IncludeVersion> void update_http_request<Body, IncludeVersion>::handle_handshake(const boost::system::error_code &error)
{

	if (handle_callback_precheck(error, "make request handshake")) {
		return;
	}

	auto request_handler = [this](auto e, auto b) { this->handle_request(e, b); };

	switch_deadline_on();

	http::async_write(ssl_socket, request, request_handler);
}

template<class Body, bool IncludeVersion> void update_http_request<Body, IncludeVersion>::handle_request(boost::system::error_code &error, size_t bytes)
{
	if (handle_callback_precheck(error, "make request")) {
		return;
	}

	auto read_handler = [this](auto i, auto e) { this->handle_response_header(i, e); };

	switch_deadline_on();

	http::async_read_header(ssl_socket, response_buf, response_parser, read_handler);
}

template<class Body, bool IncludeVersion> void update_http_request<Body, IncludeVersion>::handle_response_header(boost::system::error_code &error, size_t bytes)
{
	if (handle_callback_precheck(error, "get response header")) {
		return;
	}

	auto &response = response_parser.get();
	int status_code = response.result_int();
	if (status_code != 200) {
		auto target_info = request.target();

		std::string output_str =
			"Server sent status code: " + std::to_string(status_code) + " for: " + std::string(target_info.data(), target_info.size());

		handle_download_error(boost::asio::error::basic_errors::connection_aborted, output_str);
		return;
	}

	try {
		content_length = response_parser.content_length().value();
	} catch (...) {
		content_length = 0;
	}

	if (content_length == 0) {
		auto target_info = request.target();

		std::string output_str = "Received empty header for: " + std::string(target_info.data(), target_info.size());

		handle_download_error(boost::asio::error::basic_errors::connection_aborted, output_str);
		return;
	}

	start_reading();
}
