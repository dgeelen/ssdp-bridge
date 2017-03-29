#pragma once
#include <string>

// Forward declarations
struct sockaddr_in;

#define STRINGIFY_(...) #__VA_ARGS__
#define STRINGIFY(...) STRINGIFY_(__VA_ARGS__)

std::string to_string(const sockaddr_in& addr);
