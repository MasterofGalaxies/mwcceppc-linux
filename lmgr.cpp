#include "common.h"

extern "C" {
	int WIN_ENTRY lp_checkout(int a, int b, const char* c, const char* d, int e, const char* f, int* out) {
		DEBUG_LOG("lp_checkout %d %d %s %s %d %s\n", a, b, c, d, e, f);
		*out = 1234;
		return 0;
	}

	int WIN_ENTRY lp_checkin() {
		DEBUG_LOG("lp_checkin\n");
		return 0;
	}
}
