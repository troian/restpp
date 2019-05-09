/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Artur Troian
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#pragma once

#include <curl/curl.h>

#include <string>
#include <map>
#include <memory>
#include <mutex>
#include <algorithm>
#include <cstring>
#include <functional>

#include <restpp/exception.hh>
#include <restpp/types.hh>

namespace restpp {
/**
 * \class
 */
class http_request {
public:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	struct ops {
		struct {
			uint32_t verify_peer      :1 = 1;
			uint32_t verify_host      :1 = 1;
			uint32_t follow_redirects :1 = 1;
		};
		int         timeout          = 0;
		std::string save_to          = "";
	};
#pragma GCC diagnostic pop

public:
	/**
	 * \brief
	 *
	 * \param[in]
	 * \param[in]
	 * \param[in]
	 */
	http_request(const http_request::ops &ops, const std::string &host, const std::string &path, HTTP_METHOD method);

	/**
	 * \brief
	 *
	 * \param[in]   rhs
	 *
	 * \return None
	 */
	http_request(const http_request &rhs);

	virtual ~http_request() = default;

	/**
	 * \brief
	 *
	 * \param[in]
	 *
	 * \return None
	 */
	void set_debug(http_log_cb cb) {
		_http_log = cb;
	}

	/**
	 * \brief
	 *
	 * \param[in]   headers
	 */
	void set_headers(http_params headers);

	/**
	 * \brief
	 *
	 * \return
	 */
	http_params get_headers() const;

	/*
	 * \brief  Append additional headers
	 *
	 * \param[in]   Header key
	 * \param[in]   Header value
	 */
	void add_header(const std::string& key, const std::string& value);

	void del_header(const std::string &key);

	/**
	 * \brief  Add query paramenter
	 *
	 * \param[in]  Query key
	 * \param[in]  Query value
	 *
	 * \return None
	 */
	void add_query(const std::string &key, const std::string &value);

	/**
	 * \brief
	 *
	 * \param[in]
	 * \param[in]
	 * \param[in]
	 *
	 * \return  http_response
	 */
	http_res perform(const std::string *body, const std::string *content_type);

private:
	void init_curl();

private: // Static methods & callbacks
	/**
	 * \brief  CURL writedata callback function
	 *
	 * \param[in]   data: returned data of size (size * nmemb)
	 * \param[in]   size: size parameter
	 * \param[in]   nmemb: memblock parameter
	 * \param[in]   userdata: pointer to user data to save/work with return data
	 *
	 * \return      (size * nmemb)
	 */
	static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata);

	/**
	 * \brief  CURL header callback function
	 *
	 * \param[in]   data: returned (header line)
	 * \param[in]   size: size of data
	 * \param[in]   nmemb: memblock
	 * \param[in]   userdata: pointer to user data object to save headr data
	 *
	 * \return      (size * nmemb)
	 */
	static size_t header_callback(void *ptr, size_t size, size_t nmemb, void *userdata);

	/**
	 * \brief  CURL read callback function
	 *
	 * \param[in]  data: pointer of max size (size * nmemb) to write data to
	 * \param[in]  size: size parameter
	 * \param[in]  nmemb: memblock parameter
	 * \param[in]  userdata: pointer to user data to read data from
	 *
	 * \return     (size * nmemb)
	 */
	static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userdata);

	/**
	 * \brief  Trim from start
	 *
	 * \param[in]
	 *
	 * \return
	 */
	static inline std::string &ltrim(std::string &s) {
		s.erase(
			s.begin()
			, std::find_if(s.begin()
			               , s.end()
			               , [](int c) { return !std::isspace(c); })
		);
		return s;
	}

	/**
	 * \brief  Trim from end
	 *
	 * \param[in]
	 *
	 * \return
	 */
	static inline std::string &rtrim(std::string &s) {
		s.erase(
			std::find_if(s.rbegin()
			             , s.rend()
			             , [](int c) { return !std::isspace(c); }).base()
			, s.end()
		);
		return s;
	}

	/**
	 * \brief  Trim from both ends
	 *
	 * \param[in]
	 *
	 * \return
	 */
	static inline std::string &trim(std::string &s) {
		return ltrim(rtrim(s));
	}

	/**
	 * \brief
	 *
	 * \param[in]  handle: CURL handle
	 * \param[in]
	 * \param[in]
	 * \param[in]
	 * \param[in]
	 *
	 * \return
	 */
	static int curl_trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp);

	/**
	 * \brief
	 *
	 * \param[in]
	 * \param[in]
	 * \param[in]
	 * \param[in]
	 * \param[in]
	 *
	 * \return None
	 */
	void curl_dump(const char *text, const uint8_t *ptr, size_t size);

private:
	std::shared_ptr<CURL> _curl;
	std::string           _uri;
	HTTP_METHOD           _method;
	http_params           _header_params;
	http_params           _query_params;
	http_req_info         _last_request;
	http_upload_object    _upload_obj;
	http_log_cb           _http_log;
	http_request::ops     _ops;
};

/**
 * \class
 */
class http_req_base : public http_request {
public:
	/**
	 * \brief
	 *
	 * \param[in]
	 * \param[in]
	 * \param[in]
	 *
	 * \return  None
	 */
	http_req_base(const http_request::ops &ops, const std::string &host, const std::string &path, HTTP_METHOD method);

	/**
	 * \brief
	 *
	 * \param[in]  rhs
	 *
	 * \return  None
	 */
	http_req_base(const http_req_base &rhs);

	~http_req_base() override = default;

	/**
	 * \brief
	 *
	 * \return None
	 */
	virtual http_res perform() final;

protected:
	std::shared_ptr<std::string> data_;
	std::string                  content_type_;
};

/**
 * \class http_req_get
 *
 * \brief Perform GET request to the remote
 */
class http_req_get : public http_req_base {
public:
	/**
	 * \brief
	 *
	 * \param[in]  host
	 * \param[in]  path
	 *
	 * \return  None
	 */
	explicit http_req_get(const http_request::ops &ops, const std::string &host, const std::string &path);

	~http_req_get() override = default;
};

/**
 * \class  http_req_post
 *
 * \brief  Perform POST request to the remote
 */
class http_req_post : public http_req_base {
public:
	/**
	 * \brief
	 *
	 * \param[in]  host
	 * \param[in]  path
	 * \param[in]  data
	 *
	 * \return
	 */
	explicit http_req_post(const http_request::ops &ops, const std::string &host, const std::string &path, const std::string &data);

	~http_req_post() override = default;
};

/**
 * \class  http_req_put
 *
 * \brief  Perform PUT request to the remote
 */
class http_req_put : public http_req_base {
public:
	/**
	 * \brief
	 *
	 * \param[in]  host
	 * \param[in]  path
	 * \param[in]  data
	 *
	 * \return
	 */
	explicit http_req_put(const http_request::ops &ops, const std::string &host, const std::string &path, const std::string &data);

	~http_req_put() override = default;
};

/**
 * \class  http_req_del
 *
 * \brief  Perform DEL request to the remote
 */
class http_req_del : public http_req_base {
public:
	/**
	 * \brief
	 *
	 * \param[in]  host
	 * \param[in]  path
	 *
	 * \return
	 */
	explicit http_req_del(const http_request::ops &ops, const std::string &host, const std::string &path, const std::string *data = nullptr);

	~http_req_del() override = default;
};


} // namespace restpp
