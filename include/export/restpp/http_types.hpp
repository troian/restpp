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

/**
 * \brief
 */
typedef std::map<std::string, std::string> http_params;

/**
 * \brief
 */
using http_log_cb = typename std::function<void (const std::stringstream &stream)>;

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
} http_res;

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
} http_req_info;

/**
 * \struct http_upload_object
 *
 * \brief This structure represents the payload to upload on POST requests
 *
 * \var http_upload_object::data
 *      Member 'data' contains the data to upload
 * \var http_upload_object::length
 *      Member 'length' contains the length of the data to upload
 */
typedef struct {
	const char *data;
	size_t      length;
} http_upload_object;

/**
 * \brief
 */
typedef std::shared_ptr<class http_req_base> sp_http_req;
