#include "util.hpp"
#include <arpa/inet.h>
#include <sys/types.h>


std::string to_string(const sockaddr_in& addr) {
	char str[64] = {};
	inet_ntop(AF_INET, &addr.sin_addr, str, sizeof(str));
	return std::string(str) + ':' + std::to_string(ntohs(addr.sin_port));
}
