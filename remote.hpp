#pragma once
#include <arpa/inet.h>
#include <vector>
#include <ostream>


class Remote {
	int         m_fd;
	sockaddr_in m_addr;
	enum {
		idle,
		connecting,
		connected
	} m_state;

public:
	Remote(int fd, const sockaddr_in& addr);

	int get_fd() const;
	bool has_fd(int fd) const;
	const sockaddr_in& get_addr() const;
	int connect();
	void close();

	bool is_connecting() const;
	bool is_connected() const;

	ssize_t send(const void* data, size_t len) const;
	ssize_t recv(void* data, size_t len);

	friend std::ostream& operator<<(std::ostream& stream, const Remote& remote);
};

struct select_result {
	std::vector<Remote*> readable;
	std::vector<Remote*> writable;
	std::vector<Remote*> excepted;
};
select_result select(std::vector<Remote>& remotes);
