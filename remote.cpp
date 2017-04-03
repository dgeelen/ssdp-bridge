#include "errno_error.hpp"
#include "remote.hpp"
#include "logger.hpp"
#include "util.hpp"
#include <fcntl.h> // ::fcntl()
#include <sys/select.h> // fd_set, ::select()
#include <sys/socket.h> // ::socket()
#include <unistd.h> // ::close()
#include <cstring> // ::strlen()
#include <iomanip>
#include <ostream>
#include <sstream>

Remote::Remote(int fd, const sockaddr_in& addr)
: m_fd{fd}
, m_addr{addr}
, m_state{fd ? connected : idle}
{TRACE}

int Remote::get_fd() const {
	return m_fd;
}

bool Remote::has_fd(int fd) const {
	return m_fd == fd;
}

const sockaddr_in& Remote::get_addr() const {
	return m_addr;
}

int Remote::connect() { TRACE
	switch(m_state) {
		case connected: {
			m_state = connected;
		}; break;

		case idle: {
			log(status) << "Initiating connection to " << *this;

			if((m_fd = ::socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
				close();
				throw errno_error( "cannot create socket" );
			}

			// setup non blocking socket
			int flags = fcntl(m_fd, F_GETFL, 0);
			log(trace) << "calling ::fcntl(F_SETFL)...";
			if(::fcntl(m_fd, F_SETFL, flags|O_NONBLOCK) != 0) {
				close();
				throw errno_error( "failed to set socket to non-blocking mode" );
			}

			if(::connect(m_fd, (sockaddr*)&m_addr, sizeof(m_addr)) < 0) {
				if(errno != EINPROGRESS) {
					close();
					throw errno_error( "cannot connect socket" );
				}
			}

			log(debug) << "idle --> connecting...";
			m_state = connecting;
		}; break;

		case connecting: {
			// check if we've got signal
			log(debug) << "Checking for errors...";
			int so_error{0};
			socklen_t so_error_len{sizeof(so_error)};
			if(::getsockopt(m_fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) < 0) {
				close();
				throw errno_error( "getsockopt()" );
			}
			if(so_error != 0) {
					log(debug) << "connection to " << *this << " failed!";
					close();
					return 0; // expected error, no throw
			}

			// restore to blocking socket
			log(trace) << "calling ::fcntl(F_GETFL)...";
			int flags = fcntl(m_fd, F_GETFL, 0);
			log(trace) << "calling ::fcntl(F_SETFL)...";
			if(::fcntl(m_fd, F_SETFL, flags&~O_NONBLOCK) != 0) {
				close();
				throw errno_error( "failed to set socket to blocking mode" );
			}

			log(status) << "Establishing connection to " << *this;

			const char data[] = "ssdp-bridge-c++ v0.0.1\n";
			send(data, strlen(data));

			char buf[64] = {};
			int n = ::recv(m_fd, buf, 64, 0);
			if( n < 0 ) {
				throw errno_error( "recv() failed" );
			}
			std::stringstream raw_buf;
			for(int i = 0; i < n; ++i) {
				raw_buf << "0x"
								<< std::setw(2)
								<< std::setfill('0')
								<< std::hex
								<< int(buf[i]);
			}
			buf[n] = 0;
			char* nl = strstr(buf,"\n");
			if(nl) *nl = 0;
			if(strcmp("ssdp-bridge-python v0.0.1", buf) != 0) {
				log(error) <<"Unsupported remote server '" << buf << "' (" << n << (n?" | ":"") << raw_buf.str() << ")";
				close();
				return 0; // expected error, no throw
			}

			log(status) << "connected to " << *this << "!";
			log(debug) << "connecting --> connected...";
			m_state = connected;
		}; break;
	}

	return m_fd;
}

void Remote::close() { TRACE
	::close(m_fd);
	m_fd = 0;
	log(debug) << "??? --> idle...";
	m_state = idle;
}

bool Remote::is_connecting() const {
	return m_state == connecting;
}

bool Remote::is_connected() const {
	return m_state == connected;
}

ssize_t Remote::send(const void* data, size_t len) const { TRACE
	return ::send(m_fd, data, len, MSG_NOSIGNAL);
}

ssize_t Remote::recv(void* data, size_t len) { TRACE
	ssize_t offs(0);
	while(len-offs) {
		ssize_t r = ::recv(m_fd, (char*)data+offs, len-offs, MSG_NOSIGNAL);
		if(r < 0) {
			throw errno_error("recv failed: " + std::to_string(len) + ", " + std::to_string(offs) + ", " + std::to_string(offs+len) + ", " + std::to_string(r));
		}
		if(r == 0) {
			log(error) << "partner '" << *this << "' disconnected";
			close();
			return 0;
		}
		if(ssize_t(len) != r) {
			log(error) << "Short recv: " << (offs+r) << "/" << len;
		}
		offs += r;
	}
	return offs;
}

std::ostream& operator<<(std::ostream& stream, const Remote& remote) {
	return stream << '(' << to_string(remote.m_addr) << ')';
}

select_result select(std::vector<Remote>& remotes) { TRACE
	fd_set readfds = {};
	fd_set writefds = {};
	fd_set exceptfds = {};
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	for(const auto& remote : remotes) {
		int fd = remote.get_fd();
		if(!remote.is_connecting()) { // Connected sockets are always writable
			FD_SET(fd, &readfds);
		}
		else {
			// waiting for a connection, when this either succeeds _or_ fails the
			// socket will become writable.
			FD_SET(fd, &writefds);
		}
		FD_SET(fd, &exceptfds);
	}
	timeval timeout = {};
	timeout.tv_sec = 1;
	int n = select(FD_SETSIZE, &readfds, &writefds, &exceptfds, &timeout);
	select_result result;
	if( n > 0 ) {
		for(auto& remote : remotes) {
			if( FD_ISSET(remote.get_fd(), &readfds) ) {
				result.readable.emplace_back(&remote);
			}
			if( FD_ISSET(remote.get_fd(), &writefds) ) {
				result.writable.emplace_back(&remote);
			}
			if( FD_ISSET(remote.get_fd(), &exceptfds) ) {
				result.excepted.emplace_back(&remote);
			}
		}
	}
	return result;
}
