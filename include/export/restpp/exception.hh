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

#include <stdexcept>
#include <exception>
#include <string>

namespace restpp {

/**
 * \class  http_exception
 *
 * \brief
 */
class http_base_exception {
public:
	virtual ~http_base_exception() = default;

	virtual const std::exception &base() const = 0;
};

/**
 * \class  http_req_failure
 *
 * \brief
 */
class http_exception : public http_base_exception, public std::runtime_error {
	const std::exception &base() const override { return *this; }

public:
	explicit http_exception(const std::string &what);
};

/**
 * \class  http_req_failure
 *
 * \brief
 */
class http_req_failure : public http_exception {
	const std::exception &base() const override { return *this; }

public:
	explicit http_req_failure(const std::string &what, int err = 0);

	int error() {
		return _err;
	}

private:
	int _err;
};

} // namespace restpp
