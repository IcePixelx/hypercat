#pragma once

#define WIN32_LEAN_AND_MEAN // Prevent winsock2 redefinition.

#include <WinSock2.h>
#include <windows.h>
#include <thread>
#include <fstream>
#include <stdio.h>
#include <filesystem>
#include <sstream>
#include <shlobj.h>
#include <objbase.h>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <string>
#include <Psapi.h>
#include <vector>
#include <stdarg.h>
#include <intrin.h>
#include <unordered_map>
#include <codecvt>

#include "sdkdefs.h"
#include "memaddr.h"
#include "module.h"
#include "tebpeb64.h"