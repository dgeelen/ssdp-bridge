#include "errno_error.hpp"
#include "logger.hpp"
#include "util.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <errno.h>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <string.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <arpa/inet.h>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/optional.hpp>
#include <sys/socket.h>

const std::string ssdp_addr( "239.255.255.250" );
const std::string peer_list_env_var_name( "SSDP_BRIDGE_PEERS" );
enum {
	ssdp_port = 1900,
	ssdp_bridge_default_port = 17113,
	buffer_size = 4096,
};


int join_multicast_group() { TRACE
	int fd(0);
	int option(0);

	// create a UDP socket
	if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		throw errno_error( "cannot create socket" );
	}

	// Enable SO_REUSEADDR to allow multiple instances of this application to receive copies of the multicast datagrams.
	option = 1;
	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
		throw errno_error("setsockopt(SO_REUSEADDR) failed");
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
	myaddr.sin_port = htons(ssdp_port);
	if(bind(fd, reinterpret_cast<sockaddr*>(&myaddr), sizeof(myaddr)) < 0) {
		throw errno_error("bind() failed");
	}

	// Join the multicast group on the local interface. Note that this
	// IP_ADD_MEMBERSHIP option must be called for each local interface
	// over which the multicast datagrams are to be received.
	ip_mreq group = {};
	group.imr_multiaddr.s_addr = inet_addr(ssdp_addr.c_str());
	group.imr_interface.s_addr = htonl(INADDR_ANY);
	if( 0 != setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) ) {
		throw errno_error("setsockopt() failed");
	}

	log(debug) << "ssdp fd: " << fd;
	return fd;
}

std::string to_string(const sockaddr_in& addr) {
	char str[64] = {};
	inet_ntop(AF_INET, &addr.sin_addr, str, sizeof(str));
	return std::string(str) + ':' + std::to_string(ntohs(addr.sin_port));
}

class Remote {
	int         m_fd;
	sockaddr_in m_addr;
	enum {
		idle,
		connecting,
		connected
	} m_state;

public:
	Remote(int fd, const sockaddr_in& addr)
	: m_fd{fd}
	, m_addr{addr}
	, m_state{fd ? connected : idle}
	{TRACE}

	int get_fd() const {
		return m_fd;
	}

	bool has_fd(int fd) const {
		return m_fd == fd;
	}

	const sockaddr_in& get_addr() const {
		return m_addr;
	}

	int connect() { TRACE
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
				for(size_t i = 0; i < n; ++i) {
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

	void close() { TRACE
		::close(m_fd);
		m_fd = 0;
		log(debug) << "??? --> idle...";
		m_state = idle;
	}

	bool is_connecting() const {
		return m_state == connecting;
	}

	bool is_connected() const {
		return m_state == connected;
	}

	ssize_t send(const void* data, size_t len) const { TRACE
		return ::send(m_fd, data, len, MSG_NOSIGNAL);
	}

	ssize_t recv(void* data, size_t len) { TRACE
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

	friend std::ostream& operator<<(std::ostream& stream, const Remote& remote) {
		return stream << '(' << to_string(remote.m_addr) << ')';
	}
};

struct select_result {
	std::vector<Remote*> readable;
	std::vector<Remote*> writable;
	std::vector<Remote*> excepted;
};
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

////////////////////////////////////////////////////////////////////////////////

const std::string msg_notify     {"NOTIFY "};
const std::string msg_msearch    {"M-SEARCH "};
const std::string msg_200OK      {"HTTP/1.1 200 OK"};
const std::string field_location {"LOCATION: "};
bool is_ssdp_message(const unsigned char message[], size_t len) { TRACE
	if(std::mismatch(std::begin(msg_notify), std::end(msg_notify), message, message+len).first == std::end(msg_notify)) return true;
	if(std::mismatch(std::begin(msg_msearch), std::end(msg_msearch), message, message+len).first == std::end(msg_msearch)) return true;
	if(std::mismatch(std::begin(msg_200OK), std::end(msg_200OK), message, message+len).first == std::end(msg_200OK)) return true;
	return false;
}

std::string ssdp_get_location(const std::string& message) { TRACE
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
) { TRACE
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

  const std::string& from = message.substr(replace_start, replace_end-replace_start);
	log(debug) << "replace: '" << from << "' --> '" << replacement << "'";

	// replace
	return std::string(message).replace(replace_start, replace_end-replace_start, replacement);
}

////////////////////////////////////////////////////////////////////////////////

template<typename T>
void forward_ssdp_packet(int fd, T remotes) { TRACE
	unsigned char data[buffer_size] = {};
	size_t len = recv(fd, data+4, buffer_size-4, 0);

	if(!is_ssdp_message(data+4,len)) {
		data[buffer_size-1]=0;
		char* m = strstr((char*)data+4,"\r\n");
		if(m) *m = 0;
		//log(debug) << "not forwarding ssdp message to remote: '" << ((const char*)data+4) << "'\n";
		return;
	}
	//std::string ssdp_message((const char*)(data+4), len);

	for(const auto& remote : remotes) {
		if(remote.get_fd() == fd) continue;
		if(!remote.is_connected()) continue;
		std::uint32_t n = htonl(len);
		memcpy(data, &n, sizeof(n));

		log(debug) << "forwarding " << len << " bytes to " << remote;
		if(remote.send(data, len+sizeof(n)) < 0 ) {
			log(error) << "error sending to " << remote;
		}
	}
}

void handle_remote(Remote& remote, int fd) { TRACE
	std::uint32_t len(0);
	remote.recv(&len, sizeof(len));
	len = ntohl(len);
	if(len > buffer_size) {
		std::stringstream ss;
		ss << "Invalid length: "
		   << len
		   << " from "
		   << remote;
		throw std::runtime_error(ss.str());
	}
	unsigned char data[buffer_size] = {};
	remote.recv(data, len);
	log(debug) << "replaying " << std::to_string(len) << " bytes from " << remote;

	if(!is_ssdp_message(data,len)) {
		data[buffer_size-1]=0;
		char* m = strstr((char*)data,"\r\n");
		if(m) *m = 0;
		log(warn) << "not replaying ssdp message from remote: '" << ((const char*)data) << "'";
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

	if(message.size() + 4 > buffer_size) {
		throw std::runtime_error("cannot forward packet after redirection: too large");
	}

	if(location_after != location_before) {
		std::cout << "redirecting: '" << location_before << "' --> '" << location_after << "'\n";
		memcpy(data+4, message.c_str(), message.size());
	}
*/

	struct sockaddr_in dest_addr = {};
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = (in_port_t)htons(ssdp_port);
	if(inet_aton(ssdp_addr.c_str(), &dest_addr.sin_addr) == 0) {
		throw errno_error("inet_aton() failed");
	}

	ssize_t ret = sendto(fd, ssdp_message.c_str(), ssdp_message.size(), 0, (sockaddr*)&dest_addr, sizeof(dest_addr));
	if(ret != len) {
		throw std::runtime_error("Not all data was sent");
	}
}

boost::optional<Remote> parse_remote(const std::string& str) { TRACE
	std::string::size_type port_idx = str.find(':');
	std::string port = std::to_string(ssdp_bridge_default_port);
	if(port_idx != std::string::npos)
		port = str.substr(port_idx+1);
	std::string ipaddr = str.substr(0,port_idx);

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	if(!inet_aton(ipaddr.c_str(), &addr.sin_addr)) {
		log(error) << "Invalid IP address: '" << ipaddr << "'";
		return boost::none;
	}
	addr.sin_port = htons(std::stoi(port));
	if(std::to_string(ntohs(addr.sin_port)) != port) {
		log(error) << "Invalid port: '" << port << "'";
		return boost::none;
	}
	return Remote(0, addr);
}

boost::optional<std::vector<Remote>> parse_remotes_from_env() { TRACE
	std::vector<Remote> remotes;
	if(const char* addr_list = std::getenv(peer_list_env_var_name.c_str())) {
		std::string port_ = std::to_string(ssdp_bridge_default_port);
		std::vector<std::string> addrs;
		boost::split(addrs, addr_list, boost::algorithm::is_any_of(","));
		for(const auto& addr : addrs) {
			const auto& remote = parse_remote(addr);
			if(remote)
				remotes.emplace_back(*remote);
			else
				return boost::none;
		};
		log(status) << "Configuring peers from environment:";
		for(const auto& remote : remotes) {
			log(status) << "\t" << remote;
		}
	}
	return remotes;
}


int main(int argc, const char* argv[]) { TRACE
	std::vector<Remote> remotes;
	boost::optional<std::vector<Remote>> env_remotes = parse_remotes_from_env();
	if(env_remotes)
		remotes = *env_remotes;
	else
		return 1;

	log_level max_loglevel(status);
	for(int i = 1; i < argc; ++i ) {
		const std::string& arg(argv[i]);
		if( arg == "-v" ) {
			max_loglevel = log_level(max_loglevel + 1);
		}
		else {
			const auto& remote = parse_remote(arg);
			if(remote)
				remotes.emplace_back(*remote);
			else
				return 1;
		}
	}
	set_max_loglevel(max_loglevel);

	if( remotes.empty() ) {
		std::cerr << "usage: " << argv[0] << " <server-ip[:port]>" << std::endl;
		return 1;
	}

	int ssdp_sock(0);
	try {
		ssdp_sock = join_multicast_group();
	}
	catch( const std::exception& e ) {
		log(error) << "Failed to join multicast group:\n"
		           << e.what();
		return 1;
	}

	sockaddr_in addr = {};
	remotes.emplace_back(ssdp_sock, addr);
	size_t error_count{0};
	while(true) {
		for(auto& remote : remotes ) {
			if( !remote.is_connected() && !remote.is_connecting() ) {
				try {
					remote.connect();
				}
				catch( const std::exception& e ) {
					log(error) << e.what();
				}
			}
		}
		try {
			const auto& selected = select(remotes);
			for(const auto& remote : selected.writable) {
				//writeable should be sockets that are trying to connect (but have failed)
				log(trace) << "writable: " << *remote;
				remote->connect();
			}
			for(const auto& remote : selected.readable ) {
				log(trace) << "readable: " << *remote;
				if(remote->get_fd() == ssdp_sock) {
					forward_ssdp_packet(ssdp_sock, remotes);
				}
				else {
					handle_remote(*remote, ssdp_sock);
				}
			}
			error_count = 0;
		}
		catch( const std::exception& e ) {
			log(error) << e.what();
			if( ++error_count > 3 ) {
				log(error) << "Too many errors, aborting...";
				return 1;
			}
		}
	}

	return 0;
}
