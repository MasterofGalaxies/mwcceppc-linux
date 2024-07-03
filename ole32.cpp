#include "common.h"

extern "C" {
	int WIN_FUNC CoInitialize(void *pvReserved) {
		DEBUG_LOG("CoInitialize(...)\n");
		return 0; // S_OK
	}

	struct GUID {
		unsigned int Data1;
		unsigned short Data2;
		unsigned short Data3;
		unsigned char Data4[8];
	};

	int WIN_FUNC CoCreateInstance(
		const GUID *rclsid,
		void *pUnkOuter,
		unsigned int dwClsContext,
		const GUID *riid,
		void **ppv
	) {
		DEBUG_LOG("CoCreateInstance 0x%x %p %d 0x%x %p\n", rclsid->Data1, pUnkOuter, dwClsContext, riid->Data1, *ppv);
		*ppv = 0;
		// E_POINTER is returned when ppv is NULL, which isn't true here, but returning 1 results
		// in a segfault with mwcceppc.exe when it's told to include directories that don't exist
		return 0x80004003; // E_POINTER
	}
}
