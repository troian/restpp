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

#include <jwt/jwt.hpp>

/**
 * \brief
 */
typedef std::map<std::string, std::string> http_params;

/**
 * \brief
 */
typedef enum {
	HTTP_METHOD_GET,
	HTTP_METHOD_POST,
	HTTP_METHOD_PUT,
	HTTP_METHOD_DELETE
} HTTP_METHOD;

/**
 * \brief
 */
typedef struct {
	int          code;
	std::string  body;
	http_params  headers;
} http_response;

/**
 * \brief
 */
typedef struct {
	double totalTime;
	double nameLookupTime;
	double connectTime;
	double appConnectTime;
	double preTransferTime;
	double startTransferTime;
	double redirectTime;
	int    redirectCount;
} http_request_info;

typedef struct {
	std::mutex               file_lock;
	FILE                    *file;
} debug_object;

/**
 * \struct UploadObject
 * \brief This structure represents the payload to upload on POST requests
 *
 *  \var upload_object::data
 *  Member 'data' contains the data to upload
 *  \var upload_object::length
 *  Member 'length' contains the length of the data to upload
 */
typedef struct {
	const char *data;
	size_t      length;
} upload_object;

/**
 * \brief
 */
class http_request {
private:
	typedef struct {
		char trace_ascii; /* 1 or 0 */
		FILE *stream;
	} curl_debug_config;

public:
	/**
	 * \brief
	 *
	 * \param
	 * \param
	 * \param
	 */
	http_request(const std::string &host, const std::string &path, HTTP_METHOD method);

	virtual ~http_request();

	// set headers
	void SetHeaders(http_params headers);

	// get headers
	http_params GetHeaders() const;

	/**
	 * \brief
	 *
	 * \param[in]
	 *
	 * \return None
	 */
	void set_debug(debug_object *debug_obj) {
		m_debug = debug_obj;
	}

	/*
	 * \brief  Append additional headers
	 *
	 * \param[in]   Header key
	 * \param[in]   Header value
	 */
	void add_header(const std::string& key, const std::string& value);

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
	 *
	 * \return  http_response
	 */
	http_response perform_request(const std::string *body, const std::string *content_type);

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
	static void curl_dump(const char *text, FILE *stream, uint8_t *ptr, size_t size, char nohex);

private:
	CURL         *m_curl;
	std::string   m_uri;
	HTTP_METHOD   m_method;
	http_params   m_header_params;
	http_params   m_query_params;
	int           m_timeout;
	bool          m_follow_redirects;
	http_request_info  m_last_request;
	upload_object m_upload_obj;

	debug_object *m_debug;
};

class http_req_base : public http_request {
public:
	http_req_base(const std::string &host, const std::string &path, HTTP_METHOD method);
	virtual ~http_req_base();

	/**
	 * \brief
	 *
	 * \param[in]
	 * \param[in]
	 *
	 * \return none
	 */
	virtual void jwt_set_key(const uint8_t *key, size_t len) final;

	/**
	 * \brief
	 *
	 * \param[in]
	 * \param[in]
	 *
	 * \return none
	 */
	virtual void jwt_add_grant(const std::string &key, const std::string &value) final;

	/**
	 * \brief
	 *
	 * \return None
	 */
	virtual http_response perform() final;

protected:
	std::shared_ptr<jwt>         m_jwt;

	std::shared_ptr<std::string> m_data;
	std::string                  m_content_type;

	const uint8_t               *m_key;
	size_t                       m_len;
};

/**
 * \brief
 */
class http_req_get : public http_req_base {
public:
	explicit http_req_get(const std::string &host, const std::string &path);

	virtual ~http_req_get();
public:

private:

};

/**
 * \brief
 */
class http_req_post : public http_req_base {
public:
	explicit http_req_post(const std::string &host, const std::string &path, const std::string &data);

	virtual ~http_req_post();
public:
	void set_body();
};

/**
 * \class
 *
 * \brief
 */
class http_req_put : public http_req_base {
public:
	explicit http_req_put(const std::string &host, const std::string &path, const std::string &data);

	virtual ~http_req_put();
public:
	void set_body();
};

/**
 * \class
 *
 * \brief
 */
class http_req_del : public http_req_base {
public:
	explicit http_req_del(const std::string &host, const std::string &path);

	virtual ~http_req_del();
public:
	void set_body();
};

