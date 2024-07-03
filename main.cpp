#include "common.h"
#include "files.h"
#include <asm/ldt.h>
#include <filesystem>
#include <memory>
#include "strutil.h"
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <vector>
#include <charconv>
#include <fcntl.h>

uint32_t wibo::lastError = 0;
char *wibo::commandLine;

extern "C" {
	void stub_abort() {
		fputs("Unimplemented function called\n", stderr);
		abort();
	}
}

struct UNICODE_STRING {
	unsigned short Length;
	unsigned short MaximumLength;
	uint16_t *Buffer;
};

// Run Time Library (RTL)
struct RTL_USER_PROCESS_PARAMETERS {
	char Reserved1[16];
	void *Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
};

// Windows Process Environment Block (PEB)
struct PEB {
	char Reserved1[2];
	char BeingDebugged;
	char Reserved2[1];
	void *Reserved3[2];
	void *Ldr;
	RTL_USER_PROCESS_PARAMETERS *ProcessParameters;
	char Reserved4[104];
	void *Reserved5[52];
	void *PostProcessInitRoutine;
	char Reserved6[128];
	void *Reserved7[1];
	unsigned int SessionId;
};

// Windows Thread Information Block (TIB)
struct TIB {
	/* 0x00 */ void *sehFrame;
	/* 0x04 */ void *stackBase;
	/* 0x08 */ void *stackLimit;
	/* 0x0C */ void *subSystemTib;
	/* 0x10 */ void *fiberData;
	/* 0x14 */ void *arbitraryDataSlot;
	/* 0x18 */ TIB *tib;
	/*      */ char pad[0x14];
	/* 0x30 */ PEB *peb;
	/*      */ char pad2[0x1000];
};

// Make this global to ease debugging
TIB tib;

extern "C" {
	extern void _mainCRTStartup();
}

int main(int argc, char **argv) {
	files::init();

	// Create TIB
	memset(&tib, 0, sizeof(tib));
	tib.tib = &tib;
	tib.peb = (PEB*)calloc(sizeof(PEB), 1);
	tib.peb->ProcessParameters = (RTL_USER_PROCESS_PARAMETERS*)calloc(sizeof(RTL_USER_PROCESS_PARAMETERS), 1);

	struct user_desc tibDesc;
	memset(&tibDesc, 0, sizeof tibDesc);
	tibDesc.entry_number = 0;
	tibDesc.base_addr = (unsigned int) &tib;
	tibDesc.limit = 0x1000;
	tibDesc.seg_32bit = 1;
	tibDesc.contents = 0; // hopefully this is ok
	tibDesc.read_exec_only = 0;
	tibDesc.limit_in_pages = 0;
	tibDesc.seg_not_present = 0;
	tibDesc.useable = 1;
	if (syscall(SYS_modify_ldt, 1, &tibDesc, sizeof tibDesc) != 0) {
		perror("Failed to modify LDT");
		return 1;
	}

	// Build a command line
	std::string cmdLine;
	for (int i = 0; i < argc; i++) {
		std::string arg;
		if (i == 0) {
			arg = files::pathToWindows(std::filesystem::absolute(argv[0]));
		} else {
			cmdLine += ' ';
			arg = argv[i];
		}
		bool needQuotes = arg.find_first_of("\\\" \t\n") != std::string::npos;
		if (needQuotes)
			cmdLine += '"';
		int backslashes = 0;
		for (const char *p = arg.c_str(); ; p++) {
			char c = *p;
			if (c == '\\') {
				backslashes++;
				continue;
			}

			// Backslashes are doubled *before quotes*
			for (int j = 0; j < backslashes; j++) {
				cmdLine += '\\';
				if (c == '\0' || c == '"')
					cmdLine += '\\';
			}
			backslashes = 0;

			if (c == '\0')
				break;
			if (c == '\"')
				cmdLine += '\\';
			cmdLine += c;
		}
		if (needQuotes)
			cmdLine += '"';
	}
	cmdLine += '\0';

	wibo::commandLine = cmdLine.data();
	DEBUG_LOG("Command line: %s\n", wibo::commandLine);

	uint16_t tibSegment = (tibDesc.entry_number << 3) | 7;
	// Invoke the damn thing
	asm(
		"movw %0, %%fs; call *%1"
		:
		: "r"(tibSegment), "r"(_mainCRTStartup)
	);
	DEBUG_LOG("We came back\n");

	return 1;
}
