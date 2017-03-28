#pragma once
#include <stdexcept>


struct errno_error : public std::runtime_error {
	errno_error();
	errno_error(const char* what);
	errno_error(const std::string& what);
};
