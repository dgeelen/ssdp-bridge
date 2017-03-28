#pragma once
#include <cstdlib>
#include <iostream>

enum log_level {
	error,
	warn,
	status,
	debug,
	trace,
};

struct log_writer {
	log_writer(std::ostream& stream)
	: m_stream{&stream}
	{
	}

	log_writer(log_writer&& that)
	: m_stream{nullptr}
	{
		using std::swap;
		swap(m_stream, that.m_stream);
	}

	template<typename T>
	log_writer& operator<<(const T& t) {
		*m_stream << t;
		return *this;
	}

	~log_writer() {
		if(m_stream)
			*m_stream << std::endl;
	}

	std::ostream* m_stream;
};

log_writer log(log_level level);

struct trace_func {
	const char* m_msg;
	static size_t ident;
	trace_func(const char* msg);
	~trace_func();
};
#define TRACE trace_func trace_func_ ## __LINE__( __PRETTY_FUNCTION__ );

void set_max_loglevel(log_level max);
