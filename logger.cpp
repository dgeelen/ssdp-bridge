#include "logger.hpp"
#include <algorithm>
#include <iomanip>
#include <string>
#include <cassert>

const char* level_desc(log_level level) {
	switch(level) {
		case error : return "Error";
		case warn  : return "Warning";
		case status: return "Status";
		case debug : return "Debug";
		case trace : return "Trace";
	}
	assert(false);
}

namespace {
	log_level max_loglevel(status);
}

void set_max_loglevel(log_level max) {
	max_loglevel = max;
}

struct nop_buf : public std::stringbuf {} s_nop_buf;
std::ostream s_nop_stream(&s_nop_buf);

log_writer log(log_level level) {
	if(level>max_loglevel) {
		return log_writer(s_nop_stream);
	}
	if(level==status) {
		return log_writer(std::cout);
	}
	log_writer lw(std::cerr);
	std::string desc = level_desc(level);
	//std::transform(desc.begin(), desc.end(), desc.begin(), ::toupper);
	//lw << '[' << std::left << std::setw(9) << desc << "] ";
	lw << desc << ": ";
	return lw;
}

trace_func::trace_func(const char* msg)
: m_msg(msg)
{
	log(trace)
	<< std::string(2*ident, ' ')
	<< ">> "
	<< m_msg;
	++ident;
}

trace_func::~trace_func() {
	--ident;
	log(trace)
	<< std::string(2*ident, ' ')
	<< "<< "
	<< m_msg;
}

size_t trace_func::ident = 0;
