#ifndef SDKDEFS_H
#define SDKDEFS_H

// Common type declarations to reduce code verbosity.
using std::pair;
using std::string;
using std::wstring;
using std::u16string;
using std::u32string;
using std::vector;
using std::fstream;
using std::ifstream;
using std::ofstream;
using std::stringstream;
using std::ostringstream;
using std::unordered_map;

namespace fs = std::filesystem;
typedef const unsigned char* rsig_t;
typedef std::make_signed_t<std::size_t> ssize_t;

#endif // SDKDEFS_H
