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

#include <restpp/process.hh>

#include <sstream>
#include <iostream>
#include <iomanip>

namespace restpp {

// --------------------------------------------------------------
// Implementation of class http_request
// --------------------------------------------------------------
http_request::http_request(const http_request::ops &ops, const std::string &host, const std::string &path, HTTP_METHOD method) // -V::730
	: _method(method)
	, _http_log(nullptr)
	, _ops(ops) {

	try {
		init_curl();
	} catch (...) {
		throw;
	}

	_uri.clear();
	_uri.append(host);
	if (!path.empty()) {
		_uri.append(path);
	}
}

http_request::http_request(const http_request &rhs)
	: _uri          (rhs._uri)
	, _method       (rhs._method)
	, _header_params(rhs._header_params)
	, _query_params (rhs._query_params)
	, _last_request (rhs._last_request)
	, _upload_obj   (rhs._upload_obj)
	, _http_log     (rhs._http_log)
{
	try {
		init_curl();
	} catch (...) {
		throw;
	}
}

void http_request::init_curl() {
	_curl = std::shared_ptr<CURL>(curl_easy_init(), [=](CURL *c) {
		curl_easy_reset(c);
		curl_easy_cleanup(c);
	});

//	if (!curl_) {
//		throw std::runtime_error("Couldn't initialize curl handle");
//	}

	switch (_method) {
	case HTTP_METHOD::GET:
		break;
	case HTTP_METHOD::PUT:
		curl_easy_setopt(_curl.get(), CURLOPT_PUT, 1L);
		break;
	case HTTP_METHOD::POST:
		curl_easy_setopt(_curl.get(), CURLOPT_POST, 1L);
		curl_easy_setopt(_curl.get(), CURLOPT_POSTREDIR, 1L);
		break;
	case HTTP_METHOD::DELETE:
		curl_easy_setopt(_curl.get(), CURLOPT_CUSTOMREQUEST, "DELETE");
		break;
	case HTTP_METHOD::HEAD:
		curl_easy_setopt(_curl.get(), CURLOPT_NOBODY, 1);
		break;
	default:
		throw std::runtime_error("Invalid HTTP method");
	}

	curl_easy_setopt(_curl.get(), CURLOPT_SSL_VERIFYPEER, _ops.verify_peer ? 1L : 0L);
	curl_easy_setopt(_curl.get(), CURLOPT_SSL_VERIFYHOST, _ops.verify_host ? 1L : 0L);
	curl_easy_setopt(_curl.get(), CURLOPT_FOLLOWLOCATION, _ops.follow_redirects ? 1L : 0L);
}

void http_request::add_header(const std::string &key, const std::string &value) {
	_header_params[key] = value;
}

void http_request::del_header(const std::string &key) {
	if (_header_params.find(key) != _header_params.end()) {
		_header_params.erase(key);
	}
}

void http_request::set_headers(http_params headers) {
	_header_params = headers;
}

http_params http_request::get_headers() const {
	return _header_params;
}

void http_request::add_query(const std::string &key, const std::string &value) {
	_query_params[key] = value;
}

http_res http_request::perform(const std::string *body, const std::string *content_type) {
	http_res ret;
	std::string headerString;
	CURLcode res = CURLE_OK;
	std::string query;
	curl_slist *headerList = nullptr;

	/** Set http query if any */
	for (auto &it : _query_params) {
		if (query.empty()) {
			query += "?";
		} else {
			query += "&";
		}

		auto encode = [&query, this](const char *str, int len) {
			char *enc = curl_easy_escape(_curl.get(), str, len);
			query += enc;
		};

		encode(it.first.c_str(), it.first.size());
		query += "=";
		encode(it.second.c_str(), it.second.size());
	}

	if (!query.empty()) {
		_uri.append(query);
	}

	curl_easy_setopt(_curl.get(), CURLOPT_URL, _uri.c_str());
//	curl_easy_setopt(_curl.get(), CURLOPT_HEADER, 1);

	curl_easy_setopt(_curl.get(), CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(_curl.get(), CURLOPT_HEADERDATA, &ret);

	if (content_type && !content_type->empty()) {
		add_header("Accept", *content_type);
	}

	for (auto &it : _header_params) {
		headerString = it.first;
		headerString += ": ";
		headerString += it.second;
		headerList = curl_slist_append(headerList, headerString.c_str());
	}

	curl_easy_setopt(_curl.get(), CURLOPT_HTTPHEADER, headerList);

	// Set body data if any
	if (body && !body->empty()) {
		if (_method == HTTP_METHOD::PUT) {
			_upload_obj.data = body->c_str();
			_upload_obj.length = body->size();

			curl_easy_setopt(_curl.get(), CURLOPT_UPLOAD, 1L);
			curl_easy_setopt(_curl.get(), CURLOPT_READFUNCTION, read_callback);
			curl_easy_setopt(_curl.get(), CURLOPT_READDATA, &_upload_obj);
			curl_easy_setopt(_curl.get(), CURLOPT_INFILESIZE, static_cast<int64_t>(_upload_obj.length));
		} else if (_method == HTTP_METHOD::POST) {
			curl_easy_setopt(_curl.get(), CURLOPT_POSTFIELDS, body->c_str());
			curl_easy_setopt(_curl.get(), CURLOPT_POSTFIELDSIZE, body->size());
		} else if (_method == HTTP_METHOD::DELETE) {
			curl_easy_setopt(_curl.get(), CURLOPT_POSTFIELDS, body->c_str());
		}
	}

	curl_easy_setopt(_curl.get(), CURLOPT_VERBOSE, _http_log ? 1L : 0L);

	if (_http_log) {
		curl_easy_setopt(_curl.get(), CURLOPT_DEBUGFUNCTION, curl_trace);
		curl_easy_setopt(_curl.get(), CURLOPT_DEBUGDATA, this);
	}

	// don't send a sig alarm on timeout
	curl_easy_setopt(_curl.get(), CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(_curl.get(), CURLOPT_TIMEOUT, _ops.timeout);

	std::shared_ptr<FILE> wr_file;

	if (_method != HTTP_METHOD::HEAD) {
		if (_ops.save_to.empty()) {
			curl_easy_setopt(_curl.get(), CURLOPT_WRITEFUNCTION, write_callback);
			curl_easy_setopt(_curl.get(), CURLOPT_WRITEDATA, &ret);
		} else {
			wr_file = std::shared_ptr<FILE>(fopen(_ops.save_to.c_str(), "wb"), [](FILE *f) {
				fclose(f);
			});

			curl_easy_setopt(_curl.get(), CURLOPT_WRITEFUNCTION, NULL);
			curl_easy_setopt(_curl.get(), CURLOPT_WRITEDATA, wr_file.get());
		}
	}

	res = curl_easy_perform(_curl.get());

	if (res != CURLE_OK) {
		curl_slist_free_all(headerList);
		throw http_req_failure(curl_easy_strerror(res), res);
	} else {
		int64_t http_code = 0;
		curl_easy_getinfo(_curl.get(), CURLINFO_RESPONSE_CODE, &http_code);
		ret.code = static_cast<http_status>(http_code);

		curl_slist_free_all(headerList);
	}

	return ret;
}

size_t http_request::write_callback(void *data, size_t size, size_t nmemb, void *userdata) {
	http_res *r;
	r = reinterpret_cast<http_res *>(userdata);
	auto ptr = static_cast<uint8_t *>(data);

	r->body.insert(r->body.end(), ptr, ptr + (size * nmemb));
//	r->body.append(reinterpret_cast<char *>(data), size * nmemb);

	return (size * nmemb);
}

size_t http_request::header_callback(void *data, size_t size, size_t nmemb, void *userdata) {
	http_res *r;
	r = reinterpret_cast<http_res *>(userdata);
	std::string header(reinterpret_cast<char *>(data), size * nmemb);
	size_t separator = header.find_first_of(':');
	if (std::string::npos == separator) {
		// roll with non separated headers...
		trim(header);
		if (0 == header.length()) {
			return (size * nmemb);  // blank line;
		}
		r->headers[header] = "present";
	} else {
		std::string key = header.substr(0, separator);
		trim(key);
		std::string value = header.substr(separator + 1);
		trim(value);
		r->headers[key] = value;
	}

	return (size * nmemb);
}

size_t http_request::read_callback(void *data, size_t size, size_t nmemb, void *userdata) {
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

int http_request::curl_trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp) {
	(void)handle;

	auto obj = reinterpret_cast<http_request *>(userp);

	if (obj->_http_log) {
		const char *text = nullptr;

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
			obj->_http_log(stream);
			break;
		}
		default: /* in case a new one is introduced to shock us */
			return 0;
		}

		obj->curl_dump(text, reinterpret_cast<uint8_t *>(data), size);
	}

	return 0;
}

void http_request::curl_dump(const char *text, const uint8_t *ptr, size_t size) {
	std::stringstream stream;
	uint32_t width = 0xFFF;

	stream << text << ", ";
	stream << std::setw(10);
	stream << std::to_string(size) << " bytes (0x" << std::hex << size << ")" << "\n";

	for (size_t i = 0; i < size; i += width) {
		stream << "   ";

//		if (!nohex) {
//			/* hex not disabled, show it */
//			/* show hex to the left */
//			for (size_t c = 0; c < width; c++) {
//				if (i + c < size)
//					stream << std::setw(2) << std::hex << ptr[i + c];
//				else
//					stream << "   ";
//			}
//		}

		/* show data on the right */
		for (size_t c = 0; (c < width) && (i + c < size); c++) {
			/* check for 0D0A; if found, skip past and start a new line of output */
			if ((i + c + 1 < size) && ptr[i + c] == 0x0D && ptr[i + c + 1] == 0x0A) {
				i += (c + 2 - width);
				break;
			}

			char ch = (ptr[i + c] >= 0x20) && (ptr[i + c] < 0x80) ? ptr[i + c] : '.';

			stream << ch;

			/* check again for 0D0A, to avoid an extra \n if it's at width */
			if ((i + c + 2 < size) && ptr[i + c + 1] == 0x0D && ptr[i + c + 2] == 0x0A) {
				i += (c + 3 - width);
				break;
			}
		}
		stream << "\n";
	}

	_http_log(stream);
}

http_req_base::http_req_base(const http_req_base &rhs)
	: http_request(rhs) {
	data_ = rhs.data_;
	content_type_ = rhs.content_type_;
}

// --------------------------------------------------------------
// Implementation of class http_req_base
// --------------------------------------------------------------
http_req_base::http_req_base(const http_request::ops &ops, const std::string &host, const std::string &path
                             , HTTP_METHOD method)
	: http_request(ops, host, path, method)
//	, timestamp_(timestamp_str_ms())
{}

http_res http_req_base::perform() {
	http_res response;

	try {
		response = http_request::perform(data_.get(), &content_type_);
	} catch (...) {
		throw;
	}

	return response;
}

// --------------------------------------------------------------
// Implementation of class http_req_get
// --------------------------------------------------------------
http_req_get::http_req_get(const http_request::ops &ops, const std::string &host, const std::string &path)
	: http_req_base(ops, host, path, HTTP_METHOD::GET)
{}

// --------------------------------------------------------------
// Implementation of class http_req_post
// --------------------------------------------------------------
http_req_post::http_req_post(const http_request::ops &ops, const std::string &host, const std::string &path
                             , const std::string &data)
	: http_req_base(ops, host, path, HTTP_METHOD::POST) {
	data_ = std::make_shared<std::string>(data);
}

// --------------------------------------------------------------
// Implementation of class http_req_put
// --------------------------------------------------------------
http_req_put::http_req_put(const http_request::ops &ops, const std::string &host, const std::string &path
                           , const std::string &data)
	: http_req_base(ops, host, path, HTTP_METHOD::PUT) {
	data_ = std::make_shared<std::string>(data);
}

// --------------------------------------------------------------
// Implementation of class http_req_del
// --------------------------------------------------------------
http_req_del::http_req_del(const http_request::ops &ops, const std::string &host, const std::string &path
                           , const std::string *data)
	: http_req_base(ops, host, path, HTTP_METHOD::DELETE) {
	if (data_) {
		data_ = std::make_shared<std::string>(*data);
	}
}

} // namespace restpp
