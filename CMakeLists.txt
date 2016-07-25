cmake_minimum_required(VERSION 3.2)

project(restpp LANGUAGES C CXX)

include(CheckCSourceCompiles)
include(CheckCCompilerFlag)
include(CheckCXXSourceCompiles)
include(CheckCXXSymbolExists)
include(CheckCXXCompilerFlag)
include(CheckFunctionExists)
include(CheckTypeSize)
include(CheckIncludeFiles)
include(CheckIncludeFileCXX)

check_include_file_cxx(iostream HAVE_IOSTREAM)
check_include_file_cxx(memory HAVE_MEMORY)
check_include_file_cxx(functional HAVE_FUNCTIONAL)
check_include_file_cxx(string HAVE_STRING)
check_include_file_cxx(atomic HAVE_ATOMIC)
check_include_file_cxx(mutex HAVE_MUTEX)
check_include_file_cxx(exception HAVE_EXCEPTION)
check_include_file_cxx(stdexcept HAVE_STDEXCEPT)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

set(EXPORT_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/export
)

set(LIB_SOURCES
    src/http_process.cpp
    src/http_exception.cpp
	${EXPORT_INCLUDES}/restpp/http_process.hpp
	${EXPORT_INCLUDES}/restpp/http_exception.hpp
	${EXPORT_INCLUDES}/restpp/http_types.hpp
)

add_library(${PROJECT_NAME} STATIC ${LIB_SOURCES})

find_package(CURL REQUIRED)

target_include_directories(
	${PROJECT_NAME}
	PUBLIC
	${EXPORT_INCLUDES}
	${CURL_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME}
	${CURL_LIBRARIES}
	jwtpp
)
