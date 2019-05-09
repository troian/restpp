cmake_minimum_required(VERSION 3.2)

project(restpp LANGUAGES CXX)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LibCURL REQUIRED libcurl)

include(CheckCXXSourceCompiles)
include(CheckCXXSymbolExists)
include(CheckCXXCompilerFlag)
include(CheckFunctionExists)
include(CheckTypeSize)
include(CheckIncludeFiles)
include(CheckIncludeFileCXX)

check_include_file_cxx(iostream   HAVE_IOSTREAM)
check_include_file_cxx(memory     HAVE_MEMORY)
check_include_file_cxx(functional HAVE_FUNCTIONAL)
check_include_file_cxx(string     HAVE_STRING)
check_include_file_cxx(atomic     HAVE_ATOMIC)
check_include_file_cxx(mutex      HAVE_MUTEX)
check_include_file_cxx(exception  HAVE_EXCEPTION)
check_include_file_cxx(stdexcept  HAVE_STDEXCEPT)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++2a")

add_library(
	${PROJECT_NAME}
	include/export/restpp/exception.hh
	include/export/restpp/process.hh
	include/export/restpp/types.hh

	src/exception.cpp
	src/process.cpp
)

target_include_directories(
	${PROJECT_NAME}
	PUBLIC
		include/export
)

target_link_libraries(
	${PROJECT_NAME}
	PUBLIC
		libcurl.a
		gssapi_krb5
)
