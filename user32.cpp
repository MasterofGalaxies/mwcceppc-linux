#include "common.h"
#include "rsrc-string-table.c"

extern "C" {
	int WIN_FUNC LoadStringA(void* hInstance, unsigned int uID, char* lpBuffer, int cchBufferMax) {
		DEBUG_LOG("LoadStringA %p %d %d\n", hInstance, uID, cchBufferMax);
		if (cchBufferMax == 0)
			return 0;

		int len = stpncpy(lpBuffer, string_table[uID], cchBufferMax) - lpBuffer;

		if (len == cchBufferMax) {
			--len;
			lpBuffer[len] = '\0';
		}

		DEBUG_LOG("returning: %s\n", lpBuffer);
		return len;
	}

	int WIN_FUNC MessageBoxA(void *hwnd, const char *lpText, const char *lpCaption, unsigned int uType) {
		printf("MESSAGE BOX: [%s] %s\n", lpCaption, lpText);
		fflush(stdout);
		return 1;
	}
}
