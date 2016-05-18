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

#include <restpp/http_process.hpp>
#include <memory>
#include <sstream>
#include <iostream>

// --------------------------------------------------------------
// Implemenation of class http_request
// --------------------------------------------------------------

http_request::http_request(const std::string &host, const std::string &path, HTTP_METHOD method) :
	  m_method(method)
	, m_debug(nullptr)
{
	m_curl = curl_easy_init();
	if (!m_curl) {
		throw std::runtime_error("Couldn't initialize curl handle");
	}

	switch (method) {
	case HTTP_METHOD_GET:
		break;
	case HTTP_METHOD_PUT:
		curl_easy_setopt(m_curl, CURLOPT_PUT, 1L);
		break;
	case HTTP_METHOD_POST:
		curl_easy_setopt(m_curl, CURLOPT_POST, 1L);
		break;
	case HTTP_METHOD_DELETE: {
		/** we want HTTP DELETE */
		const char *http_delete = "DELETE";
		/** set HTTP DELETE METHOD */
		curl_easy_setopt(m_curl, CURLOPT_CUSTOMREQUEST, http_delete);
		break;
	}
	default:
		curl_easy_cleanup(m_curl);
		throw std::runtime_error("Invalid HTTP method");
	}

	m_uri.clear();
	m_uri.append(host);
	m_uri.append(path);
}

http_request::~http_request()
{
	curl_easy_cleanup(m_curl);
}

void http_request::add_header(const std::string &key, const std::string &value)
{
	m_header_params[key] = value;
}

void http_request::SetHeaders(http_params headers)
{
	m_header_params = headers;
}

http_params http_request::GetHeaders() const
{
	return m_header_params;
}

void http_request::add_query(const std::string &key, const std::string &value)
{
	m_query_params[key] = value;
}

http_response http_request::perform_request(const std::string *body, const std::string *content_type)
{
	http_response    ret = {};
	std::string      headerString;
	CURLcode         res = CURLE_OK;
	std::string      query;
	curl_slist      *headerList = NULL;
	curl_debug_config debug_cfg;

	/** Set http query if any */
	for (auto it : m_query_params) {
		if (query.empty())
			query += "?";
		else
			query += "&";

		auto encode = [&query, this](const char *str, int len) {
			char *enc = curl_easy_escape(m_curl, str, len);
			query += enc;
		};

		encode(it.first.c_str(), it.first.size());
		query += "=";
		encode(it.second.c_str(), it.second.size());
	}

	if (!query.empty()) {
		m_uri.append(query);
	}

	/** set query URL */
	curl_easy_setopt(m_curl, CURLOPT_URL, m_uri.c_str());
	/** set callback function */
	curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, write_callback);
	/** set data object to pass to callback function */
	curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &ret);
	/** set the header callback function */
	curl_easy_setopt(m_curl, CURLOPT_HEADERFUNCTION, header_callback);
	/** callback object for headers */
	curl_easy_setopt(m_curl, CURLOPT_HEADERDATA, &ret);
	/** set http headers */

	if (content_type && !content_type->empty()) {
		add_header("Accept", *content_type);
	}

	try {
		for (auto it : m_header_params) {
			headerString = it.first;
			headerString += ": ";
			headerString += it.second;
			headerList = curl_slist_append(headerList, headerString.c_str());
		}
	} catch (const std::exception &e) {
		std::cerr << e.what();
	}
	curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, headerList);

	// Set body data if any
	if (body && !body->empty()) {
		if (m_method == HTTP_METHOD_PUT) {
			m_upload_obj.data = body->c_str();
			m_upload_obj.length = body->size();

			/** Now specify we want to PUT data */
			curl_easy_setopt(m_curl, CURLOPT_UPLOAD, 1L);
			/** set read callback function */
			curl_easy_setopt(m_curl, CURLOPT_READFUNCTION, read_callback);
			/** set data object to pass to callback function */
			curl_easy_setopt(m_curl, CURLOPT_READDATA, &m_upload_obj);
			/** set data size */
			curl_easy_setopt(m_curl, CURLOPT_INFILESIZE, static_cast<int64_t>(m_upload_obj.length));
		} else if (m_method == HTTP_METHOD_POST) {
			curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, body->c_str());
			curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE, body->size());
		}
	}

	//write_lock lock;
	// Set debug
	if (m_debug) {
		m_debug->file_lock.lock();
		debug_cfg.stream = m_debug->file;
		fprintf(m_debug->file, "== Request Start ==\n");
		debug_cfg.trace_ascii = 1; /* enable ascii tracing */
		curl_easy_setopt(m_curl, CURLOPT_DEBUGFUNCTION, curl_trace);
		curl_easy_setopt(m_curl, CURLOPT_DEBUGDATA, &debug_cfg);

		/* the DEBUGFUNCTION has no effect until we enable VERBOSE */
		curl_easy_setopt(m_curl, CURLOPT_VERBOSE, 1L);
	}

	// set timeout
	if (m_timeout) {
		curl_easy_setopt(m_curl, CURLOPT_TIMEOUT, m_timeout);
		// dont want to get a sig alarm on timeout
		curl_easy_setopt(m_curl, CURLOPT_NOSIGNAL, 1);
	}

	// set follow redirect
	if (m_follow_redirects == true) {
		curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1L);
	}

	res = curl_easy_perform(m_curl);

	if (res != CURLE_OK) {
		if (res == CURLE_OPERATION_TIMEDOUT) {
			ret.code = res;
			ret.body = "Operation Timeout.";
		} else {
			ret.body = "Failed to query.";
			ret.code = -1;
		}
	} else {
		int64_t http_code = 0;
		curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &http_code);
		ret.code = static_cast<int>(http_code);
	}

	curl_easy_getinfo(m_curl, CURLINFO_TOTAL_TIME, &m_last_request.totalTime);
	curl_easy_getinfo(m_curl, CURLINFO_NAMELOOKUP_TIME, &m_last_request.nameLookupTime);
	curl_easy_getinfo(m_curl, CURLINFO_CONNECT_TIME, &m_last_request.connectTime);
	curl_easy_getinfo(m_curl, CURLINFO_APPCONNECT_TIME, &m_last_request.appConnectTime);
	curl_easy_getinfo(m_curl, CURLINFO_PRETRANSFER_TIME, &m_last_request.preTransferTime);
	curl_easy_getinfo(m_curl, CURLINFO_STARTTRANSFER_TIME, &m_last_request.startTransferTime);
	curl_easy_getinfo(m_curl, CURLINFO_REDIRECT_TIME, &m_last_request.redirectTime);
	curl_easy_getinfo(m_curl, CURLINFO_REDIRECT_COUNT, &m_last_request.redirectCount);
	// free header list
	curl_slist_free_all(headerList);
	// reset curl handle
	curl_easy_reset(m_curl);

	if (m_debug) {
		fprintf(m_debug->file, "== Request end ==\n\n");
		m_debug->file_lock.unlock();
	}
	return ret;
}

size_t http_request::write_callback(void *data, size_t size, size_t nmemb, void *userdata)
{
	http_response *r;
	r = reinterpret_cast<http_response *>(userdata);
	r->body.append(reinterpret_cast<char *>(data), size * nmemb);

	return (size * nmemb);
}

size_t http_request::header_callback(void *data, size_t size, size_t nmemb, void *userdata)
{
	http_response *r;
	r = reinterpret_cast<http_response *>(userdata);
	std::string header(reinterpret_cast<char *>(data), size * nmemb);
	size_t seperator = header.find_first_of(":");
	if ( std::string::npos == seperator ) {
		// roll with non seperated headers...
		trim(header);
		if (0 == header.length()) {
			return (size * nmemb);  // blank line;
		}
		r->headers[header] = "present";
	} else {
		std::string key = header.substr(0, seperator);
		trim(key);
		std::string value = header.substr(seperator + 1);
		trim(value);
		r->headers[key] = value;
	}

	return (size * nmemb);
}

size_t http_request::read_callback(void *data, size_t size, size_t nmemb, void *userdata)
{
	/** get upload struct */
	upload_object *u;
	u = reinterpret_cast<upload_object *>(userdata);

	/** set correct sizes */
	size_t curl_size = size * nmemb;
	size_t copy_size = (u->length < curl_size) ? u->length : curl_size;
	/** copy data to buffer */
	std::memcpy(data, u->data, copy_size);
	/** decrement length and increment data pointer */
	u->length -= copy_size;
	u->data += copy_size;
	/** return copied size */
	return copy_size;
}

int http_request::curl_trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{
	curl_debug_config *config = (curl_debug_config *)userp;
	const char *text;

	switch (type) {
	case CURLINFO_TEXT:
		fprintf(config->stream, "== Info: %s", data);
	default: /* in case a new one is introduced to shock us */
		return 0;

	case CURLINFO_HEADER_OUT:
		text = "=> Send header";
		break;
	case CURLINFO_DATA_OUT:
		text = "=> Send data";
		break;
	case CURLINFO_SSL_DATA_OUT:
		text = "=> Send SSL data";
		break;
	case CURLINFO_HEADER_IN:
		text = "<= Recv header";
		break;
	case CURLINFO_DATA_IN:
		text = "<= Recv data";
		break;
	case CURLINFO_SSL_DATA_IN:
		text = "<= Recv SSL data";
		break;
	}

	curl_dump(text, config->stream, (uint8_t *)data, size, config->trace_ascii);
	return 0;
}

void http_request::curl_dump(const char *text, FILE *stream, uint8_t *ptr, size_t size, char nohex)
{
	unsigned int width=0x10;

	if(nohex)
		/* without the hex output, we can fit more on screen */
		width = 0x80;

	fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n", text, (long)size, (long)size);

	for(size_t i = 0; i < size; i += width) {

		//fprintf(stream, "%4.4lx: ", (long)i);
		fprintf(stream, "   ");
		if(!nohex) {
			/* hex not disabled, show it */
			for(size_t c = 0; c < width; c++) {
				if (i + c < size)
					fprintf(stream, "%02x ", ptr[i + c]);
				else
					fputs("   ", stream);
			}
		}

		for(size_t c = 0; (c < width) && (i + c < size); c++) {
			/* check for 0D0A; if found, skip past and start a new line of output */
			if(nohex && (i + c + 1 < size) && ptr[i + c]==0x0D && ptr[i + c + 1] == 0x0A) {
				i += (c + 2 - width);
				break;
			}
			fprintf(stream, "%c", (ptr[i + c] >= 0x20) && (ptr[i + c] < 0x80) ? ptr[i + c] : '.');
			/* check again for 0D0A, to avoid an extra \n if it's at width */
			if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D && ptr[i + c + 2] == 0x0A) {
				i += (c + 3 - width);
				break;
			}
		}
		fputc('\n', stream); /* newline */
	}
	fflush(stream);
}

// --------------------------------------------------------------
// Implemenation of class http_req_base
// --------------------------------------------------------------

http_req_base::http_req_base(const std::string &host, const std::string &path, HTTP_METHOD method) :
	  http_request(host, path, method)
	, m_jwt(nullptr)
{

}

http_req_base::~http_req_base()
{
	m_jwt.reset();
}

http_response http_req_base::perform()
{
	if (m_jwt) {
		std::stringstream stamp;
		stamp << std::time(nullptr);
		m_jwt->add_grant("timestamp", stamp.str());

		std::string sign("Bearer ");
		m_jwt->sign(sign, m_key, m_len);
		add_header("Authorization", sign);
	}

	http_response response = perform_request(m_data.get(), &m_content_type);

	return response;
}

void http_req_base::jwt_set_key(const uint8_t *key, size_t len)
{
	m_jwt = std::make_shared<jwt>(JWT_ALG_HS256);
	m_key = key;
	m_len = len;
}

void http_req_base::jwt_add_grant(const std::string &key, const std::string &value)
{
	if (!m_jwt) {
		throw std::runtime_error("JWT not initialized. Issue set_jwt_key first");
	} else {
		m_jwt->add_grant(key, value);
	}
}

// --------------------------------------------------------------
// Implemenation of class http_req_get
// --------------------------------------------------------------

http_req_get::http_req_get(const std::string &host, const std::string &path) :
	http_req_base(host, path, HTTP_METHOD_GET)
{

}

http_req_get::~http_req_get()
{

}

// --------------------------------------------------------------
// Implemenation of class http_req_post
// --------------------------------------------------------------
http_req_post::http_req_post(const std::string &host, const std::string &path, const std::string &data) :
	http_req_base(host, path, HTTP_METHOD_POST)
{
	m_data = std::make_shared<std::string>(data);
}

http_req_post::~http_req_post()
{

}

// --------------------------------------------------------------
// Implemenation of class http_req_put
// --------------------------------------------------------------
http_req_put::http_req_put(const std::string &host, const std::string &path, const std::string &data) :
	http_req_base(host, path, HTTP_METHOD_PUT)
{
	m_data = std::make_shared<std::string>(data);
}

http_req_put::~http_req_put()
{

}

// --------------------------------------------------------------
// Implemenation of class http_req_del
// --------------------------------------------------------------
http_req_del::http_req_del(const std::string &host, const std::string &path) :
	http_req_base(host, path, HTTP_METHOD_DELETE)
{
}

http_req_del::~http_req_del()
{

}

