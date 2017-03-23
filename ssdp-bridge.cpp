#include "errno_error.hpp"
#include <algorithm>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstdio>
#include <string.h>
#include <errno.h>
#include <iomanip>
#include <thread>
#include <vector>

#define BUFSIZE 4096
#define SSDP_PORT 1900
#define SSDP_ADDR "239.255.255.250"


int join_multicast_group() {
	int fd(0);
	int option(0);

	// create a UDP socket
	if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		throw errno_error( "cannot create socket" );
	}

	// Enable SO_REUSEADDR to allow multiple instances of this application to receive copies of the multicast datagrams.
	option = 1;
	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
		throw errno_error("setsockopt(IP_MULTICAST_LOOP) failed");
	}

	// make sure IP_MULTICAST_LOOP is enabled, so that other processes on this
	// machine can hear us. Note: when running this as a dedicated docker,
	// disable this option.
	option = 0;
	if(setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &option, sizeof(option)) < 0) {
		throw errno_error("setsockopt(IP_MULTICAST_LOOP) failed");
	}

	// bind the socket to any valid IP address and a specific port
	sockaddr_in myaddr = {}; /* our address */
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(SSDP_PORT);
	if(bind(fd, reinterpret_cast<sockaddr*>(&myaddr), sizeof(myaddr)) < 0) {
		throw errno_error("bind() failed");
	}

	// Join the multicast group on the local interface. Note that this
	// IP_ADD_MEMBERSHIP option must be called for each local interface
	// over which the multicast datagrams are to be received.
	ip_mreq group = {};
	group.imr_multiaddr.s_addr = inet_addr(SSDP_ADDR);
	group.imr_interface.s_addr = htonl(INADDR_ANY);
	if( 0 != setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) ) {
		throw errno_error("setsockopt() failed");
	}

	//std::cout << "ssdp fd: " << fd << std::endl;
	return fd;
}

void do_monitor_mode(int fd) {
	unsigned char buf[BUFSIZE]; /* receive buffer */
	struct sockaddr_in remaddr; /* remote address */
	socklen_t addrlen = sizeof(remaddr); /* length of addresses */
	int recvlen; /* # bytes received */

	/* now loop, receiving data and printing what we received */
	for (;;) {
		std::cout << "waiting on port " << SSDP_PORT << "\n";
		recvlen = recvfrom(fd, buf, BUFSIZE, 0, (struct sockaddr *)&remaddr, &addrlen); printf("received %d bytes\n", recvlen);
		if(recvlen > 0) {
			buf[recvlen] = 0;
			std::cout << "received message:\n---8<---------\n"
			          << buf
			          << "--->8---------\n\n";
		}
		else {
			throw errno_error("recvfrom() failed");
		}
	} /* never exits */
}

void do_send_mode(int fd, const char* msg) {
	/* now loop, sending data */
	struct sockaddr_in dest_addr = {};
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = (in_port_t)htons(SSDP_PORT);
	//dest_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    if(inet_aton(SSDP_ADDR, &dest_addr.sin_addr) == 0) {
        throw errno_error("inet_aton() failed");
    }
	for(;;) {
		std::cout << "Now sending... ";
		int ret = sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));
		std::cout << "ok" << std::endl;
		if( ret == -1 ) {
			throw errno_error("sendto() failed");
		}
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}
}

std::string to_string(const sockaddr_in& addr) {
	char str[64] = {};
	inet_ntop(AF_INET, &addr.sin_addr, str, sizeof(str));
	return std::string(str) + ':' + std::to_string(ntohs(addr.sin_port));
}

class Remote {
	int         m_fd;
	sockaddr_in m_addr;

public:
	Remote()
	: m_fd(0)
	, m_addr{}
	{}

	Remote(int fd, const sockaddr_in& addr)
	: m_fd(fd)
	, m_addr{addr}
	{}

	bool has_fd(int fd) const {
		return m_fd == fd;
	}

	const sockaddr_in get_addr() const {
		return m_addr;
	}

	int connect() {
		if(is_connected()) return m_fd;
		std::cerr << "connecting to " << *this << std::endl;

		if((m_fd = ::socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
			m_fd = 0;
			throw errno_error( "cannot create socket" );
		}

		if(::connect(m_fd, (sockaddr*)&m_addr, sizeof(m_addr)) < 0) {
			::close(m_fd);
			m_fd = 0;
			throw errno_error( "cannot create socket" );
		}

		const char data[] = "ssdp-bridge-c++ v0.0.1\n";
		send(data, strlen(data));

		char buf[64];
		::recv(m_fd, buf, 64, 0);
		buf[63] = 0;
		char* nl = strstr(buf,"\n");
		if(nl) *nl = 0;
		if(strcmp("ssdp-bridge-python v0.0.1", buf) != 0) {
			std::stringstream ss;
			ss <<"Unsupported remote server '" << buf << "'";
			throw std::runtime_error(ss.str());
		}

		std::cerr << "connected!" << std::endl;
		return m_fd;
	}

	bool is_connected() const {
		return m_fd != 0;
	}

	ssize_t send(const void* data, size_t len) const {
		return ::send(m_fd, data, len, 0);
	}

	ssize_t recv(void* data, size_t len) const {
		ssize_t offs(0);
		while(len-offs) {
			ssize_t r = ::recv(m_fd, (char*)data+offs, len-offs, 0);
			if( r < 0) {
				throw errno_error("recv failed: " + std::to_string(len) + ", " + std::to_string(offs) + ", " + std::to_string(offs+len) + ", " + std::to_string(r));
			}
			if( r == 0) {
				throw std::runtime_error("partner disconnected");
			}
			//if(ssize_t(len) != r) {
				//std::cerr << "Short recv: " << (offs+r) << "/" << len << std::endl;
			//}
			offs += r;
		}
		return offs;
	}

	friend std::ostream& operator<<(std::ostream& stream, const Remote& remote) {
		return stream << '(' << to_string(remote.m_addr) << ')';
	}
};

template<typename T>
T select(const T& sockets) {
	fd_set readfds = {};
	fd_set writefds = {};
	fd_set exceptfds = {};
	FD_ZERO(&readfds);
	for(const auto& socket : sockets) {
		//std::cerr << "FD_SET: " << socket << std::endl;
		FD_SET(socket, &readfds);
	}
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	timeval timeout = {};
	timeout.tv_sec = 1;
	//std::cerr << "select" << std::endl;
	int n = select(FD_SETSIZE, &readfds, &writefds, &exceptfds, &timeout);
	T result;
	if( n > 0 ) {
		//std::cerr << "selected: " << n << std::endl;
		for(const auto& socket : sockets) {
			if( FD_ISSET(socket, &readfds) ) {
				//std::cerr << "FD_ISSET: " << socket << std::endl;
				result.emplace_back(socket);
			}
		}
	}
	return result;
}

////////////////////////////////////////////////////////////////////////////////

const std::string msg_notify     {"NOTIFY "};
const std::string msg_msearch    {"M-SEARCH "};
const std::string msg_200OK      {"HTTP/1.1 200 OK"};
const std::string field_location {"LOCATION: "};
bool is_ssdp_message(const unsigned char message[], size_t len) {
	if(std::mismatch(std::begin(msg_notify), std::end(msg_notify), message, message+len).first == std::end(msg_notify)) return true;
	if(std::mismatch(std::begin(msg_msearch), std::end(msg_msearch), message, message+len).first == std::end(msg_msearch)) return true;
	if(std::mismatch(std::begin(msg_200OK), std::end(msg_200OK), message, message+len).first == std::end(msg_200OK)) return true;
	return false;
}

std::string ssdp_get_location(const std::string& message) {
	std::string::size_type start = message.find(field_location);
	std::string::size_type end = message.find("\r\n", start);
	start += field_location.size();
	return message.substr(start, end-start);
}

std::string ssdp_replace_location(
	const std::string& message,
	const sockaddr_in& replacement_addr
	//const sockaddr_in& from_addr,
	//const sockaddr_in& to_addr
) {
	// isolate the location string
	std::string::size_type start = message.find(field_location);
	if(start == std::string::npos) return message;
	start += field_location.size();

	std::string::size_type end = message.find("\r\n", start);
	if(end == std::string::npos) return message;

	// Convert replacements to string
	const std::string& replacement = to_string(replacement_addr);
	//const std::string& from = to_string(from_addr);
	//const std::string& to = to_string(to_addr);

	// isolate part to replace from location string
	std::string::size_type replace_start = message.find("http://", start);
	if(replace_start == std::string::npos)
		replace_start = start;
	else
		replace_start += 7; // http
	std::string::size_type replace_end = message.find("/", replace_start);
	if(replace_end == std::string::npos)
		replace_end = end;

  //const std::string& from = message.substr(replace_start, replace_end-replace_start);
	//std::cout << "replace: '" << from << "' --> '" << replacement << "'" << std::endl;

	// replace
	return std::string(message).replace(replace_start, replace_end-replace_start, replacement);
}

////////////////////////////////////////////////////////////////////////////////

template<typename T>
void forward_ssdp_packet(int fd, T remotes) {
	unsigned char data[BUFSIZE] = {};
	size_t len = recv(fd, data+4, BUFSIZE-4, 0);

	if(!is_ssdp_message(data+4,len)) {
		data[BUFSIZE-1]=0;
		char* m = strstr((char*)data+4,"\r\n");
		if(m) *m = 0;
		std::cout << "not forwarding ssdp message to remote: '" << ((const char*)data+4) << "'\n";
		return;
	}
	//std::string ssdp_message((const char*)(data+4), len);

	for(const auto& remote : remotes) {
		std::uint32_t n = htonl(len);
		memcpy(data, &n, sizeof(n));

		//std::cerr << "forwarding " << len << " bytes to " << remote << std::endl;
		if(remote.send(data, len+sizeof(n)) < 0 ) {
			std::cerr << "error sending to " << remote << std::endl;
		}
	}
}

void handle_remote(Remote& remote, int fd) {
	std::uint32_t len(0);
	remote.recv(&len, sizeof(len));
	len = ntohl(len);
	if(len > BUFSIZE) {
		std::stringstream ss;
		ss << "Invalid length: "
		   << len
		   << " from "
		   << remote;
		throw std::runtime_error(ss.str());
	}
	unsigned char data[BUFSIZE] = {};
	remote.recv(data, len);
	//std::cerr << "replaying " << std::to_string(len) << " bytes from " << remote << std::endl;

	if(!is_ssdp_message(data,len)) {
		data[BUFSIZE-1]=0;
		char* m = strstr((char*)data,"\r\n");
		if(m) *m = 0;
		std::cout << "not replaying ssdp message from remote: '" << ((const char*)data) << "'\n";
		return;
	}
	std::string ssdp_message((const char*)(data), len);

/*
	// here we've received an captured an SSDP message from e.g. inside of a
	// docker container, sent to us from the other side of the multicast barrier.
	// We're going to re-write the location so that anyone responding to this
	// message will respond to _us_ rather than to the program on the other side.
	// So we replace the location (which should contain the address that minidlna
	// thinks is our address) with the remote server's address
	//
	// We're going to pretend that we are the source of these replayed ssdp
	// messages, but then we need to use an address that is reachable on this
	// side of the bridge, such as the one for the default route?
	const std::string& location_before = ssdp_get_location(ssdp_message);
	// XXX: somehow figure out the default interface for outgoing multicast
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms738695(v=vs.85).aspx
	// or have a way for the user to specify (might be better?)
	sockaddr_in replacement_addr = {};
	replacement_addr.sin_port = htons(8200);
	if(inet_aton("192.168.2.222", &replacement_addr.sin_addr) == 0) {
		// error
	}
	//const std::string& message = ssdp_replace_location(ssdp_message, replacement_addr); // remote.get_addr(), dest_addr);
	const std::string& message = ssdp_message;
	const std::string& location_after = ssdp_get_location(message);

	if(message.size() + 4 > BUFSIZE) {
		throw std::runtime_error("cannot forward packet after redirection: too large");
	}

	if(location_after != location_before) {
		std::cout << "redirecting: '" << location_before << "' --> '" << location_after << "'\n";
		memcpy(data+4, message.c_str(), message.size());
	}
*/

	struct sockaddr_in dest_addr = {};
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = (in_port_t)htons(SSDP_PORT);
	if(inet_aton(SSDP_ADDR, &dest_addr.sin_addr) == 0) {
		throw errno_error("inet_aton() failed");
	}

	ssize_t ret = sendto(fd, ssdp_message.c_str(), ssdp_message.size(), 0, (sockaddr*)&dest_addr, sizeof(dest_addr));
	if(ret != len) {
		throw std::runtime_error("Not all data was sent");
	}
}


int main(int argc, const char* argv[]) {
	if( argc < 2 ) {
		std::cerr << "usage: " << argv[0] << " <server> [port]" << std::endl;
		return 1;
	}

	std::string server = argv[1];
	std::string port   = argc > 2 ? argv[2] : "17113";

	int ssdp_sock(0);
	try {
		ssdp_sock = join_multicast_group();
	}
	catch( const std::exception& e ) {
		std::cerr << "Failed to join multicast group:\n"
		          << e.what()
		          << std::endl;
		return 1;
	}

	std::vector<int>    sockets = { ssdp_sock };
	std::vector<Remote> remotes;

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	inet_aton(server.c_str(), &addr.sin_addr);
	addr.sin_port = htons(std::stoi(port));
	Remote target_remote(0, addr);

	while(true) {
		try {
			if(!target_remote.is_connected()) {
				int fd = target_remote.connect();
				sockets.push_back(fd);
				remotes.push_back(target_remote);
			}
		}
		catch( const std::exception& e ) {
			std::cerr << e.what() << std::endl;
		}
		try {
			for( auto fd : select(sockets) ) {
				//std::cerr << "selected: " << fd << std::endl;
				if(fd == ssdp_sock) {
					forward_ssdp_packet(fd, remotes);
				}
				else {
					const auto& remote = std::find_if(remotes.begin(), remotes.end(), [=](const Remote& remote) { return remote.has_fd(fd); });
					if(remote != remotes.end()) {
						handle_remote(*remote, ssdp_sock);
					}
				}
			}
		}
		catch( const std::exception& e ) {
			std::cerr << "Fatal error:\n" << e.what() << std::endl;
			return 1;
		}
	}

	return 0;
}
