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

#include <sstream>
#include <iostream>
#include <iomanip>

// --------------------------------------------------------------
// Implemenation of class http_request
// --------------------------------------------------------------
http_request::http_request(const http_request::ops &ops, const std::string &host, const std::string &path, HTTP_METHOD method) :
	  method_(method)
	, http_log_(nullptr)
	, ops_(ops)
{

	try {
		init_curl();
	} catch (...) {
		throw;
	}

	uri_.clear();
	uri_.append(host);
	if (!path.empty()) {
		uri_.append(path);
	}
}

http_request::http_request(const http_request &rhs)
{
	uri_           = rhs.uri_;
	method_        = rhs.method_;
	header_params_ = rhs.header_params_;
	query_params_  = rhs.query_params_;
	last_request_  = rhs.last_request_;
	upload_obj_    = rhs.upload_obj_;
	http_log_      = rhs.http_log_;

	try {
		init_curl();
	} catch (...) {
		throw;
	}

}

http_request::~http_request()
{
	curl_easy_reset(curl_);
	curl_easy_cleanup(curl_);
}

void http_request::init_curl()
{
	curl_ = curl_easy_init();
	if (!curl_) {
		throw std::runtime_error("Couldn't initialize curl handle");
	}

	switch (method_) {
	case HTTP_METHOD_GET:
		break;
	case HTTP_METHOD_PUT:
		curl_easy_setopt(curl_, CURLOPT_PUT, 1L);
		break;
	case HTTP_METHOD_POST:
		curl_easy_setopt(curl_, CURLOPT_POST, 1L);
		break;
	case HTTP_METHOD_DELETE:
		curl_easy_setopt(curl_, CURLOPT_CUSTOMREQUEST, "DELETE");
		break;
	case HTTP_METHOD_HEAD:
		curl_easy_setopt(curl_, CURLOPT_NOBODY, 1);
		break;
	default:
		curl_easy_cleanup(curl_);
		throw std::runtime_error("Invalid HTTP method");
	}

	curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, ops_.verify_peer ? 1L : 0L);
	curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, ops_.verify_host ? 1L : 0L);
	curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, ops_.follow_redirects ? 1L : 0L);
}

void http_request::add_header(const std::string &key, const std::string &value)
{
	header_params_[key] = value;
}

void http_request::del_header(const std::string &key)
{
	if (header_params_.find(key) != header_params_.end()) {
		header_params_.erase(key);
	}
}

void http_request::set_headers(http_params headers)
{
	header_params_ = headers;
}

http_params http_request::get_headers() const
{
	return header_params_;
}

void http_request::add_query(const std::string &key, const std::string &value)
{
	query_params_[key] = value;
}

http_res http_request::perform(const std::string *body, const std::string *content_type)
{
	http_res          ret;
	std::string       headerString;
	CURLcode          res = CURLE_OK;
	std::string       query;
	curl_slist       *headerList = NULL;

	/** Set http query if any */
	for (auto it : query_params_) {
		if (query.empty())
			query += "?";
		else
			query += "&";

		auto encode = [&query, this](const char *str, int len) {
			char *enc = curl_easy_escape(curl_, str, len);
			query += enc;
		};

		encode(it.first.c_str(), it.first.size());
		query += "=";
		encode(it.second.c_str(), it.second.size());
	}

	if (!query.empty()) {
		uri_.append(query);
	}

	curl_easy_setopt(curl_, CURLOPT_URL, uri_.c_str());
//	curl_easy_setopt(curl_, CURLOPT_HEADER, 1);

	curl_easy_setopt(curl_, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(curl_, CURLOPT_HEADERDATA, &ret);

	if (content_type && !content_type->empty()) {
		add_header("Accept", *content_type);
	}

	for (auto it : header_params_) {
		headerString = it.first;
		headerString += ": ";
		headerString += it.second;
		headerList = curl_slist_append(headerList, headerString.c_str());
	}

	curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headerList);

	// Set body data if any
	if (body && !body->empty()) {
		if (method_ == HTTP_METHOD_PUT) {
			upload_obj_.data = body->c_str();
			upload_obj_.length = body->size();

			curl_easy_setopt(curl_, CURLOPT_UPLOAD, 1L);
			curl_easy_setopt(curl_, CURLOPT_READFUNCTION, read_callback);
			curl_easy_setopt(curl_, CURLOPT_READDATA, &upload_obj_);
			curl_easy_setopt(curl_, CURLOPT_INFILESIZE, static_cast<int64_t>(upload_obj_.length));
		} else if (method_ == HTTP_METHOD_POST) {
			curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, body->c_str());
			curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, body->size());
		}  else if (method_ == HTTP_METHOD_DELETE) {
			curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, body->c_str());
		}
	}

	curl_easy_setopt(curl_, CURLOPT_VERBOSE, http_log_ ? 1L : 0L);

	if (http_log_) {
		curl_easy_setopt(curl_, CURLOPT_DEBUGFUNCTION, curl_trace);
		curl_easy_setopt(curl_, CURLOPT_DEBUGDATA, this);
	}

	// don't send a sig alarm on timeout
	curl_easy_setopt(curl_, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl_, CURLOPT_TIMEOUT, ops_.timeout);

	FILE *wr_file = nullptr;

	if (method_ != HTTP_METHOD_HEAD) {
		if (ops_.save_to.empty()) {
			curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_callback);
			curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &ret);
		} else {
			wr_file = fopen(ops_.save_to.c_str(), "wb");
			curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, NULL);
			curl_easy_setopt(curl_, CURLOPT_WRITEDATA, wr_file);
		}
	}

	res = curl_easy_perform(curl_);

	if (wr_file) {
		fclose(wr_file);
	}

	if (res != CURLE_OK) {
		curl_slist_free_all(headerList);
		throw http_req_failure(curl_easy_strerror(res), res);
	} else {
		int64_t http_code = 0;
		curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
		ret.code = static_cast<http_status>(http_code);

		curl_slist_free_all(headerList);
	}

	return ret;
}

size_t http_request::write_callback(void *data, size_t size, size_t nmemb, void *userdata)
{
	http_res *r;
	r = reinterpret_cast<http_res *>(userdata);
	r->body.append(reinterpret_cast<char *>(data), size * nmemb);

	return (size * nmemb);
}

size_t http_request::header_callback(void *data, size_t size, size_t nmemb, void *userdata)
{
	http_res *r;
	r = reinterpret_cast<http_res *>(userdata);
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
	http_upload_object *u;
	u = reinterpret_cast<http_upload_object *>(userdata);

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
	(void)handle;

	http_request *obj = reinterpret_cast<http_request *>(userp);

	if (obj->http_log_) {
		const char *text;

		switch (type) {
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
		case CURLINFO_TEXT: {
			std::stringstream stream;
			stream << "== Info: " << data;
			obj->http_log_(stream);
		}
		default: /* in case a new one is introduced to shock us */
			return 0;
		}

		obj->curl_dump(text, reinterpret_cast<uint8_t *>(data), size);
	}

	return 0;
}

void http_request::curl_dump(const char *text, uint8_t *ptr, size_t size)
{
	std::stringstream stream;
	char nohex = 1;
	unsigned int width=0xFFF;

	//if(nohex)
	/* without the hex output, we can fit more on screen */
//	width = 0xFFF;

	stream
		<< text
		<< ", "
		<< std::setw(10) << std::to_string(size)
		<< " bytes "
		<< "(0x"
		<< std::hex
		<< size << ")"
		<< std::endl;

	for (size_t i = 0; i < size; i += width) {
		stream << "   ";

		if (!nohex) {
			/* hex not disabled, show it */
			/* show hex to the left */
			for (size_t c = 0; c < width; c++) {
				if (i + c < size)
					stream << std::setw(2) << std::hex << ptr[i + c];
				else
					stream << "   ";
			}
		}

		/* show data on the right */
		for(size_t c = 0; (c < width) && (i + c < size); c++) {
			/* check for 0D0A; if found, skip past and start a new line of output */
			if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D && ptr[i + c + 1] == 0x0A) {
				i += (c + 2 - width);
				break;
			}

			char ch = (ptr[i + c] >= 0x20) && (ptr[i + c] < 0x80) ? ptr[i + c] : '.';

			stream << ch;

			/* check again for 0D0A, to avoid an extra \n if it's at width */
			if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D && ptr[i + c + 2] == 0x0A) {
				i += (c + 3 - width);
				break;
			}
		}
		stream << std::endl;
	}

	http_log_(stream);
}

http_req_base::http_req_base(const http_req_base &rhs) :
	  http_request(rhs)
{
	data_ = rhs.data_;
	content_type_ = rhs.content_type_;
}

// --------------------------------------------------------------
// Implemenation of class http_req_base
// --------------------------------------------------------------
http_req_base::http_req_base(const http_request::ops &ops, const std::string &host, const std::string &path, HTTP_METHOD method) :
	http_request(ops, host, path, method)
	, timestamp_(timestamp_str_ms())
{ }

http_req_base::~http_req_base()
{
//	jwt_.reset();
}

http_res http_req_base::perform()
{
	http_res response;

	try {
		response = http_request::perform(data_.get(), &content_type_);
	} catch (...) {
		throw;
	}

	return response;
}

// --------------------------------------------------------------
// Implemenation of class http_req_get
// --------------------------------------------------------------
http_req_get::http_req_get(const http_request::ops &ops, const std::string &host, const std::string &path) :
	http_req_base(ops, host, path, HTTP_METHOD_GET)
{

}

http_req_get::~http_req_get()
{

}

// --------------------------------------------------------------
// Implemenation of class http_req_post
// --------------------------------------------------------------
http_req_post::http_req_post(const http_request::ops &ops, const std::string &host, const std::string &path, const std::string &data) :
	http_req_base(ops, host, path, HTTP_METHOD_POST)
{
	data_ = std::make_shared<std::string>(data);
}

http_req_post::~http_req_post()
{

}

// --------------------------------------------------------------
// Implemenation of class http_req_put
// --------------------------------------------------------------
http_req_put::http_req_put(const http_request::ops &ops, const std::string &host, const std::string &path, const std::string &data) :
	http_req_base(ops, host, path, HTTP_METHOD_PUT)
{
	data_ = std::make_shared<std::string>(data);
}

http_req_put::~http_req_put()
{

}

// --------------------------------------------------------------
// Implemenation of class http_req_del
// --------------------------------------------------------------
http_req_del::http_req_del(const http_request::ops &ops, const std::string &host, const std::string &path, const std::string *data) :
	http_req_base(ops, host, path, HTTP_METHOD_DELETE)
{
	if (data_) {
		data_ = std::make_shared<std::string>(*data);
	}
}

http_req_del::~http_req_del()
{

}

