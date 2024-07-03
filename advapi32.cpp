#include "common.h"

extern "C" {
	unsigned int WIN_FUNC RegOpenKeyExA(void *hKey, const char *lpSubKey, unsigned int ulOptions, void *samDesired, void **phkResult) {
		DEBUG_LOG("RegOpenKeyExA(key=%p, subkey=%s, ...)\n", hKey, lpSubKey);
		return 1; // screw them for now
	}
}
