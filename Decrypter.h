#include <windows.h>
#include <Shlwapi.h>
#include <Shlobj.h>
#include <conio.h>
#include <Wincrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include "mem.h"
#include "base64.h"
#include "sqlite3.h"
#include "parson.h"
#include "misc.h"
#include "firefox.h"


size_t decrypt_firefox_json(char* data);