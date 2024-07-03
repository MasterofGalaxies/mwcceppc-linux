#include "common.h"

extern "C" {
	unsigned int WIN_FUNC GetFileVersionInfoSizeA(const char* lptstrFilename, unsigned int* outZero) {
		DEBUG_LOG("GetFileVersionInfoSizeA %s\n", lptstrFilename);
		if (outZero != NULL) {
			*outZero = 0;
		}
		wibo::lastError = 0;
		return 0;
	}
}
