#include "errno_error.hpp"
#include <errno.h>
#include "util.hpp"
#include <string.h>
#include <cassert>
#include <vector>

#define ENOERR 0

struct errno_number_name {
	int number;
	const char* name;
};

#define TABLE_ENTRY(...) { __VA_ARGS__, #__VA_ARGS__ }
errno_number_name errno_numbers[] = {
	TABLE_ENTRY(ENOERR),
	TABLE_ENTRY(EPERM),
	TABLE_ENTRY(ENOENT),
	TABLE_ENTRY(ESRCH),
	TABLE_ENTRY(EINTR),
	TABLE_ENTRY(EIO),
	TABLE_ENTRY(ENXIO),
	TABLE_ENTRY(E2BIG),
	TABLE_ENTRY(ENOEXEC),
	TABLE_ENTRY(EBADF),
	TABLE_ENTRY(ECHILD),
	TABLE_ENTRY(EAGAIN),
	TABLE_ENTRY(ENOMEM),
	TABLE_ENTRY(EACCES),
	TABLE_ENTRY(EFAULT),
	TABLE_ENTRY(ENOTBLK),
	TABLE_ENTRY(EBUSY),
	TABLE_ENTRY(EEXIST),
	TABLE_ENTRY(EXDEV),
	TABLE_ENTRY(ENODEV),
	TABLE_ENTRY(ENOTDIR),
	TABLE_ENTRY(EISDIR),
	TABLE_ENTRY(EINVAL),
	TABLE_ENTRY(ENFILE),
	TABLE_ENTRY(EMFILE),
	TABLE_ENTRY(ENOTTY),
	TABLE_ENTRY(ETXTBSY),
	TABLE_ENTRY(EFBIG),
	TABLE_ENTRY(ENOSPC),
	TABLE_ENTRY(ESPIPE),
	TABLE_ENTRY(EROFS),
	TABLE_ENTRY(EMLINK),
	TABLE_ENTRY(EPIPE),
	TABLE_ENTRY(EDOM),
	TABLE_ENTRY(ERANGE),
	TABLE_ENTRY(EDEADLK),
	TABLE_ENTRY(ENAMETOOLONG),
	TABLE_ENTRY(ENOLCK),
	TABLE_ENTRY(ENOSYS),
	TABLE_ENTRY(ENOTEMPTY),
	TABLE_ENTRY(ELOOP),
	TABLE_ENTRY(EWOULDBLOCK),
	TABLE_ENTRY(ENOMSG),
	TABLE_ENTRY(EIDRM),
	TABLE_ENTRY(ECHRNG),
	TABLE_ENTRY(EL2NSYNC),
	TABLE_ENTRY(EL3HLT),
	TABLE_ENTRY(EL3RST),
	TABLE_ENTRY(ELNRNG),
	TABLE_ENTRY(EUNATCH),
	TABLE_ENTRY(ENOCSI),
	TABLE_ENTRY(EL2HLT),
	TABLE_ENTRY(EBADE),
	TABLE_ENTRY(EBADR),
	TABLE_ENTRY(EXFULL),
	TABLE_ENTRY(ENOANO),
	TABLE_ENTRY(EBADRQC),
	TABLE_ENTRY(EBADSLT),
	TABLE_ENTRY(EDEADLOCK),
	TABLE_ENTRY(EBFONT),
	TABLE_ENTRY(ENOSTR),
	TABLE_ENTRY(ENODATA),
	TABLE_ENTRY(ETIME),
	TABLE_ENTRY(ENOSR),
	TABLE_ENTRY(ENONET),
	TABLE_ENTRY(ENOPKG),
	TABLE_ENTRY(EREMOTE),
	TABLE_ENTRY(ENOLINK),
	TABLE_ENTRY(EADV),
	TABLE_ENTRY(ESRMNT),
	TABLE_ENTRY(ECOMM),
	TABLE_ENTRY(EPROTO),
	TABLE_ENTRY(EMULTIHOP),
	TABLE_ENTRY(EDOTDOT),
	TABLE_ENTRY(EBADMSG),
	TABLE_ENTRY(EOVERFLOW),
	TABLE_ENTRY(ENOTUNIQ),
	TABLE_ENTRY(EBADFD),
	TABLE_ENTRY(EREMCHG),
	TABLE_ENTRY(ELIBACC),
	TABLE_ENTRY(ELIBBAD),
	TABLE_ENTRY(ELIBSCN),
	TABLE_ENTRY(ELIBMAX),
	TABLE_ENTRY(ELIBEXEC),
	TABLE_ENTRY(EILSEQ),
	TABLE_ENTRY(ERESTART),
	TABLE_ENTRY(ESTRPIPE),
	TABLE_ENTRY(EUSERS),
	TABLE_ENTRY(ENOTSOCK),
	TABLE_ENTRY(EDESTADDRREQ),
	TABLE_ENTRY(EMSGSIZE),
	TABLE_ENTRY(EPROTOTYPE),
	TABLE_ENTRY(ENOPROTOOPT),
	TABLE_ENTRY(EPROTONOSUPPORT),
	TABLE_ENTRY(ESOCKTNOSUPPORT),
	TABLE_ENTRY(EOPNOTSUPP),
	TABLE_ENTRY(EPFNOSUPPORT),
	TABLE_ENTRY(EAFNOSUPPORT),
	TABLE_ENTRY(EADDRINUSE),
	TABLE_ENTRY(EADDRNOTAVAIL),
	TABLE_ENTRY(ENETDOWN),
	TABLE_ENTRY(ENETUNREACH),
	TABLE_ENTRY(ENETRESET),
	TABLE_ENTRY(ECONNABORTED),
	TABLE_ENTRY(ECONNRESET),
	TABLE_ENTRY(ENOBUFS),
	TABLE_ENTRY(EISCONN),
	TABLE_ENTRY(ENOTCONN),
	TABLE_ENTRY(ESHUTDOWN),
	TABLE_ENTRY(ETOOMANYREFS),
	TABLE_ENTRY(ETIMEDOUT),
	TABLE_ENTRY(ECONNREFUSED),
	TABLE_ENTRY(EHOSTDOWN),
	TABLE_ENTRY(EHOSTUNREACH),
	TABLE_ENTRY(EALREADY),
	TABLE_ENTRY(EINPROGRESS),
	TABLE_ENTRY(ESTALE),
	TABLE_ENTRY(EUCLEAN),
	TABLE_ENTRY(ENOTNAM),
	TABLE_ENTRY(ENAVAIL),
	TABLE_ENTRY(EISNAM),
	TABLE_ENTRY(EREMOTEIO),
	TABLE_ENTRY(EDQUOT),
	TABLE_ENTRY(ENOMEDIUM),
	TABLE_ENTRY(EMEDIUMTYPE),
	TABLE_ENTRY(ECANCELED),
	TABLE_ENTRY(ENOKEY),
	TABLE_ENTRY(EKEYEXPIRED),
	TABLE_ENTRY(EKEYREVOKED),
	TABLE_ENTRY(EKEYREJECTED),
	TABLE_ENTRY(EOWNERDEAD),
	TABLE_ENTRY(ENOTRECOVERABLE),
};
#undef TABLE_ENTRY

// ERROR CODE TABLE
// Error number 	Error Code 	Error Description
struct errno_table_entry {
	errno_table_entry()
	: name("(missing entry)")
	, description("(missing entry)")
	{}
	errno_table_entry(const char* name, const char* description)
	: name(name)
	, description(description)
	{}
	const char* name;
	const char* description;
};
std::vector<errno_table_entry> build_errno_table() {
	const size_t nr_entries = sizeof(errno_numbers)/sizeof(errno_numbers[0]);
	std::vector<errno_table_entry> errno_table(nr_entries);

	for(size_t i = 0; i < nr_entries; ++i ) {
		const auto& entry = errno_numbers[i];
		assert(entry.number >= 0 && size_t(entry.number) < nr_entries);
		errno_table[entry.number] = {entry.name, strerror(entry.number)};
	}

	return errno_table;
}
std::vector<errno_table_entry> errno_table = build_errno_table();

errno_error::errno_error()
: errno_error( nullptr )
{}

errno_error::errno_error(const char* what)
: std::runtime_error(
	(what ? std::string(what) + ": " : "" ) + "error #" + std::to_string( errno ) +
	" (" + errno_table[errno].name + "): " +
	errno_table[errno].description
	)
{}

errno_error::errno_error(const std::string& what)
: std::runtime_error(
	what + ": error #" + std::to_string( errno ) +
	" (" + errno_table[errno].name + "): " +
	errno_table[errno].description
	)
{}
