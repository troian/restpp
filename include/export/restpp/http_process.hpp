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

#include <string>
#include <map>
#include <memory>
#include <mutex>
#include <algorithm>

#include <cstring>

#include <curl/curl.h>

#include <josepp/crypto.hpp>

#include <restpp/http_exception.hpp>
#include <restpp/http_types.hpp>

#include <types/types.hpp>

/**
 * \class
 */
class http_request {
public:
	/**
	 * \brief
	 *
	 * \param[in]
	 * \param[in]
	 * \param[in]
	 */
	http_request(const std::string &host, const std::string &path, HTTP_METHOD method);

	/**
	 * \brief
	 *
	 * \param[in]   rhs
	 *
	 * \return None
	 */
	http_request(const http_request &rhs);

	virtual ~http_request();

	/**
	 * \brief
	 *
	 * \param[in]
	 *
	 * \return None
	 */
	void set_debug(http_log_cb cb) {
		m_http_log = cb;
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
	http_res perform(const std::string *body, const std::string *content_type, int timeout = 0);

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
			               , std::not1(std::ptr_fun<int, int>(std::isspace)))
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
			             , std::not1(std::ptr_fun<int, int>(std::isspace))).base()
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
	void curl_dump(const char *text, uint8_t *ptr, size_t size);

private:
	CURL              *m_curl;
	std::string        m_uri;
	HTTP_METHOD        m_method;
	http_params        m_header_params;
	http_params        m_query_params;
	bool               m_follow_redirects;
	http_req_info      m_last_request;
	http_upload_object m_upload_obj;

	http_log_cb        m_http_log;
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
	http_req_base(const std::string &host, const std::string &path, HTTP_METHOD method);

	/**
	 * \brief
	 *
	 * \param[in]  rhs
	 *
	 * \return  None
	 */
	http_req_base(const http_req_base &rhs);

	virtual ~http_req_base();

	/**
	 * \brief
	 *
	 * \return None
	 */
	virtual http_res perform(int timeout = 0) final;

public:
	std::string timestamp() {
		return timestamp_;
	}
protected:
	std::shared_ptr<std::string> m_data;
	std::string                  content_type_;

private:
	std::string timestamp_;
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
	explicit http_req_get(const std::string &host, const std::string &path);

	virtual ~http_req_get();
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
	explicit http_req_post(const std::string &host, const std::string &path, const std::string &data);

	virtual ~http_req_post();
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
	explicit http_req_put(const std::string &host, const std::string &path, const std::string &data);

	virtual ~http_req_put();
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
	explicit http_req_del(const std::string &host, const std::string &path);

	explicit http_req_del(const std::string &host, const std::string &path, const std::string &data);

	virtual ~http_req_del();
};

