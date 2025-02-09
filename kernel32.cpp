#include "common.h"
#include "files.h"
#include "handles.h"
#include <algorithm>
#include <cstdlib>
#include <ctype.h>
#include <filesystem>
#include <fnmatch.h>
#include <string>
#include "strutil.h"
#include <malloc.h>
#include <stdarg.h>
#include <system_error>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <spawn.h>
#include <vector>

typedef union _RTL_RUN_ONCE {
	PVOID Ptr;
} RTL_RUN_ONCE, *PRTL_RUN_ONCE;
typedef PRTL_RUN_ONCE LPINIT_ONCE;

#define EXCEPTION_MAXIMUM_PARAMETERS 15
typedef struct _EXCEPTION_RECORD {
	DWORD ExceptionCode;
	DWORD ExceptionFlags;
	struct _EXCEPTION_RECORD *ExceptionRecord;
	PVOID ExceptionAddress;
	DWORD NumberParameters;
	ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;
typedef void *PCONTEXT;
typedef struct _EXCEPTION_POINTERS {
	PEXCEPTION_RECORD ExceptionRecord;
	PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;
typedef LONG (*PVECTORED_EXCEPTION_HANDLER)(PEXCEPTION_POINTERS ExceptionInfo);

struct FILETIME {
	unsigned int dwLowDateTime;
	unsigned int dwHighDateTime;
};

static const uint64_t UNIX_TIME_ZERO = 11644473600LL * 10000000;
static const FILETIME defaultFiletime = {
	(unsigned int)UNIX_TIME_ZERO,
	(unsigned int)(UNIX_TIME_ZERO >> 32)
};

template<typename CharType>
struct WIN32_FIND_DATA {
	uint32_t dwFileAttributes;
	FILETIME ftCreationTime;
	FILETIME ftLastAccessTime;
	FILETIME ftLastWriteTime;
	uint32_t nFileSizeHigh;
	uint32_t nFileSizeLow;
	uint32_t dwReserved0;
	uint32_t dwReserved1;
	CharType cFileName[260];
	CharType cAlternateFileName[14];
};

static void *doAlloc(unsigned int dwBytes, bool zero) {
	if (dwBytes == 0)
		dwBytes = 1;
	void *ret = malloc(dwBytes);
	if (ret && zero) {
		memset(ret, 0, malloc_usable_size(ret));
	}
	return ret;
}

static void *doRealloc(void *mem, unsigned int dwBytes, bool zero) {
	if (dwBytes == 0)
		dwBytes = 1;
	size_t oldSize = malloc_usable_size(mem);
	void *ret = realloc(mem, dwBytes);
	size_t newSize = malloc_usable_size(ret);
	if (ret && zero && newSize > oldSize) {
		memset((char*)ret + oldSize, 0, newSize - oldSize);
	}
	return ret;
}

static int doCompareString(const std::string &a, const std::string &b, unsigned int dwCmpFlags) {
	for (size_t i = 0; ; i++) {
		if (i == a.size()) {
			if (i == b.size()) {
				return 2; // CSTR_EQUAL
			}
			return 1; // CSTR_LESS_THAN
		}
		if (i == b.size()) {
			return 3; // CSTR_GREATER_THAN
		}
		unsigned char c = a[i], d = b[i];
		if (dwCmpFlags & 1) { // NORM_IGNORECASE
			if ('a' <= c && c <= 'z') c -= 'a' - 'A';
			if ('a' <= d && d <= 'z') d -= 'a' - 'A';
		}
		if (c != d) {
			return c < d ? 1 : 3;
		}
	}
}

static int64_t getFileSize(void* hFile) {
	FILE *fp = files::fpFromHandle(hFile);
	struct stat64 st;
	fflush(fp);
	if (fstat64(fileno(fp), &st) == -1 || !S_ISREG(st.st_mode)) {
		wibo::lastError = 2; // ERROR_FILE_NOT_FOUND (?)
		return -1; // INVALID_FILE_SIZE
	}
	return st.st_size;
}

static void setLastErrorFromErrno() {
	switch (errno) {
	case 0:
		wibo::lastError = ERROR_SUCCESS;
		break;
	case EACCES:
		wibo::lastError = ERROR_ACCESS_DENIED;
		break;
	case EEXIST:
		wibo::lastError = ERROR_ALREADY_EXISTS;
		break;
	case ENOENT:
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		break;
	case ENOTDIR:
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		break;
	default:
		wibo::lastError = ERROR_NOT_SUPPORTED;
		break;
	}
}

extern "C" {
	uint32_t WIN_FUNC GetLastError() {
		DEBUG_LOG("GetLastError() -> %u\n", wibo::lastError);
		return wibo::lastError;
	}

	void WIN_FUNC SetLastError(unsigned int dwErrCode) {
		DEBUG_LOG("SetLastError(%u)\n", dwErrCode);
		wibo::lastError = dwErrCode;
	}

	PVOID WIN_FUNC AddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER handler) {
		DEBUG_LOG("STUB: AddVectoredExceptionHandler(%u, %p)\n", first, handler);
		return (PVOID)handler;
	}

	// @brief returns a pseudo handle to the current process
	void *WIN_FUNC GetCurrentProcess() {
		// pseudo handle is always returned, and is -1 (a special constant)
		return (void *) 0xFFFFFFFF;
	}

	// @brief DWORD (unsigned int) returns a process identifier of the calling process.
	unsigned int WIN_FUNC GetCurrentProcessId() {
		uint32_t pid = getpid();
		DEBUG_LOG("Current processID is: %d\n", pid);

		return pid;
	}

	unsigned int WIN_FUNC GetCurrentThreadId() {
		pthread_t thread_id;
		thread_id = pthread_self();
		DEBUG_LOG("Current thread ID is: %lu\n", thread_id);

		// Cast thread_id to unsigned int to fit a DWORD
		unsigned int u_thread_id = (unsigned int) thread_id;

		return u_thread_id;
	}

	void WIN_FUNC ExitProcess(unsigned int uExitCode) {
		DEBUG_LOG("ExitProcess %d\n", uExitCode);
		exit(uExitCode);
	}

	int WIN_FUNC GetSystemDefaultLangID() {
		DEBUG_LOG("STUB GetSystemDefaultLangID\n");
		return 0;
	}

	struct LIST_ENTRY;
	struct LIST_ENTRY {
		LIST_ENTRY *Flink;
		LIST_ENTRY *Blink;
	};

	struct CRITICAL_SECTION_DEBUG;
	struct CRITICAL_SECTION {
		CRITICAL_SECTION_DEBUG *DebugInfo;
		unsigned int LockCount;
		unsigned int RecursionCount;
		void *OwningThread;
		void *LockSemaphore;
		unsigned int SpinCount;
	};

	struct CRITICAL_SECTION_DEBUG {
		int Type;
		int CreatorBackTraceIndex;
		CRITICAL_SECTION *CriticalSection;
		LIST_ENTRY ProcessLocksList;
		unsigned int EntryCount;
		unsigned int ContentionCount;
		unsigned int Flags;
		int CreatorBackTraceIndexHigh;
		int SpareUSHORT;
	};

	void WIN_FUNC InitializeCriticalSection(CRITICAL_SECTION *param) {
		// DEBUG_LOG("InitializeCriticalSection(...)\n");
	}
	void WIN_FUNC InitializeCriticalSectionEx(CRITICAL_SECTION *param) {
		// DEBUG_LOG("InitializeCriticalSection(...)\n");
	}
	void WIN_FUNC DeleteCriticalSection(CRITICAL_SECTION *param) {
		// DEBUG_LOG("DeleteCriticalSection(...)\n");
	}
	void WIN_FUNC EnterCriticalSection(CRITICAL_SECTION *param) {
		// DEBUG_LOG("EnterCriticalSection(...)\n");
	}
	void WIN_FUNC LeaveCriticalSection(CRITICAL_SECTION *param) {
		// DEBUG_LOG("LeaveCriticalSection(...)\n");
	}

	unsigned int WIN_FUNC InitializeCriticalSectionAndSpinCount(CRITICAL_SECTION *lpCriticalSection, unsigned int dwSpinCount) {
		DEBUG_LOG("InitializeCriticalSectionAndSpinCount (%i)\n", dwSpinCount);
		// can we get away with doing nothing...?
		memset(lpCriticalSection, 0, sizeof(CRITICAL_SECTION));
		lpCriticalSection->SpinCount = dwSpinCount;

		return 1;
	}

	int WIN_FUNC InitOnceBeginInitialize(LPINIT_ONCE lpInitOnce, DWORD dwFlags, PBOOL fPending, LPVOID* lpContext) {
		DEBUG_LOG("STUB: InitOnceBeginInitialize\n");
		return 1;
	}

	void WIN_FUNC AcquireSRWLockShared(void *SRWLock) { DEBUG_LOG("STUB: AcquireSRWLockShared(%p)\n", SRWLock); }

	void WIN_FUNC ReleaseSRWLockShared(void *SRWLock) { DEBUG_LOG("STUB: ReleaseSRWLockShared(%p)\n", SRWLock); }

	void WIN_FUNC AcquireSRWLockExclusive(void *SRWLock) { DEBUG_LOG("STUB: AcquireSRWLockExclusive(%p)\n", SRWLock); }

	void WIN_FUNC ReleaseSRWLockExclusive(void *SRWLock) { DEBUG_LOG("STUB: ReleaseSRWLockExclusive(%p)\n", SRWLock); }

	int WIN_FUNC TryAcquireSRWLockExclusive(void *SRWLock) {
		DEBUG_LOG("STUB: TryAcquireSRWLockExclusive(%p)\n", SRWLock);
		return 1;
	}

	/*
	 * TLS (Thread-Local Storage)
	 */
	enum { MAX_TLS_VALUES = 100 };
	static bool tlsValuesUsed[MAX_TLS_VALUES] = { false };
	static void *tlsValues[MAX_TLS_VALUES];
	unsigned int WIN_FUNC TlsAlloc() {
		DEBUG_LOG("TlsAlloc()\n");
		for (size_t i = 0; i < MAX_TLS_VALUES; i++) {
			if (tlsValuesUsed[i] == false) {
				tlsValuesUsed[i] = true;
				tlsValues[i] = 0;
				DEBUG_LOG("...returning %d\n", i);
				return i;
			}
		}
		DEBUG_LOG("...returning nothing\n");
		wibo::lastError = 1;
		return 0xFFFFFFFF; // TLS_OUT_OF_INDEXES
	}

	unsigned int WIN_FUNC TlsFree(unsigned int dwTlsIndex) {
		DEBUG_LOG("TlsFree(%u)\n", dwTlsIndex);
		if (dwTlsIndex >= 0 && dwTlsIndex < MAX_TLS_VALUES && tlsValuesUsed[dwTlsIndex]) {
			tlsValuesUsed[dwTlsIndex] = false;
			return 1;
		} else {
			wibo::lastError = 1;
			return 0;
		}
	}

	void *WIN_FUNC TlsGetValue(unsigned int dwTlsIndex) {
		// DEBUG_LOG("TlsGetValue(%u)", dwTlsIndex);
		void *result = nullptr;
		if (dwTlsIndex >= 0 && dwTlsIndex < MAX_TLS_VALUES && tlsValuesUsed[dwTlsIndex]) {
			result = tlsValues[dwTlsIndex];
			// See https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-TlsGetValue#return-value
			wibo::lastError = ERROR_SUCCESS;
		} else {
			wibo::lastError = 1;
		}
		// DEBUG_LOG(" -> %p\n", result);
		return result;
	}

	unsigned int WIN_FUNC TlsSetValue(unsigned int dwTlsIndex, void *lpTlsValue) {
		// DEBUG_LOG("TlsSetValue(%u, %p)\n", dwTlsIndex, lpTlsValue);
		if (dwTlsIndex >= 0 && dwTlsIndex < MAX_TLS_VALUES && tlsValuesUsed[dwTlsIndex]) {
			tlsValues[dwTlsIndex] = lpTlsValue;
			return 1;
		} else {
			wibo::lastError = 1;
			return 0;
		}
	}

	/*
	 * Memory
	 */
	void *WIN_FUNC GlobalAlloc(uint32_t uFlags, size_t dwBytes) {
		// DEBUG_LOG("GlobalAlloc(flags=%x, size=%x)\n", uFlags, dwBytes);
		if (uFlags & 2) {
			// GMEM_MOVEABLE - not implemented rn
			assert(0);
			return 0;
		} else {
			// GMEM_FIXED - this is simpler
			bool zero = uFlags & 0x40; // GMEM_ZEROINT
			return doAlloc(dwBytes, zero);
		}
	}
	void *WIN_FUNC GlobalFree(void *hMem) {
		free(hMem);
		return 0;
	}

	void *WIN_FUNC GlobalReAlloc(void *hMem, size_t dwBytes, uint32_t uFlags) {
		if (uFlags & 0x80) { // GMEM_MODIFY
			assert(0);
		} else {
			bool zero = uFlags & 0x40; // GMEM_ZEROINT
			return doRealloc(hMem, dwBytes, zero);
		}
	}

	unsigned int WIN_FUNC GlobalFlags(void *hMem) {
		return 0;
	}

	/*
	 * Environment
	 */
	LPSTR WIN_FUNC GetCommandLineA() {
		DEBUG_LOG("GetCommandLineA\n");
		return wibo::commandLine;
	}

	char *WIN_FUNC GetEnvironmentStrings() {
		DEBUG_LOG("GetEnvironmentStrings\n");
		// Step 1, figure out the size of the buffer we need.
		size_t bufSize = 0;
		char **work = environ;

		while (*work) {
			bufSize += strlen(*work) + 1;
			work++;
		}
		bufSize++;

		// Step 2, actually build that buffer
		char *buffer = (char *) malloc(bufSize);
		char *ptr = buffer;
		work = environ;

		while (*work) {
			ptr = stpcpy(ptr, *work) + 1;
			work++;
		}
		*ptr = 0; // an extra null at the end

		return buffer;
	}

	uint16_t* WIN_FUNC GetEnvironmentStringsW() {
		DEBUG_LOG("GetEnvironmentStringsW\n");
		// Step 1, figure out the size of the buffer we need.
		size_t bufSizeW = 0;
		char **work = environ;

		while (*work) {
			// "hello|" -> " h e l l o|"
			bufSizeW += strlen(*work) + 1;
			work++;
		}
		bufSizeW++;

		// Step 2, actually build that buffer
		uint16_t *buffer = (uint16_t *) malloc(bufSizeW * 2);
		uint16_t *ptr = buffer;
		work = environ;

		while (*work) {
			size_t strSize = strlen(*work);
			for (size_t i = 0; i < strSize; i++) {
				*ptr++ = (*work)[i] & 0xFF;
			}
			*ptr++ = 0; // NUL terminate
			work++;
		}
		*ptr = 0; // an extra null at the end

		return buffer;
	}

	void WIN_FUNC FreeEnvironmentStringsA(char *buffer) {
		DEBUG_LOG("FreeEnvironmentStringsA\n");
		free(buffer);
	}

	/*
	 * I/O
	 */
	void *WIN_FUNC GetStdHandle(uint32_t nStdHandle) {
		DEBUG_LOG("GetStdHandle %d\n", nStdHandle);
		return files::getStdHandle(nStdHandle);
	}

	unsigned int WIN_FUNC SetStdHandle(uint32_t nStdHandle, void *hHandle) {
		DEBUG_LOG("SetStdHandle %d %p\n", nStdHandle, hHandle);
		return files::setStdHandle(nStdHandle, hHandle);
	}

	unsigned int WIN_FUNC DuplicateHandle(void *hSourceProcessHandle, void *hSourceHandle, void *hTargetProcessHandle, void **lpTargetHandle, unsigned int dwDesiredAccess, unsigned int bInheritHandle, unsigned int dwOptions) {
		DEBUG_LOG("DuplicateHandle(source=%p)\n", hSourceHandle);
		FILE *fp = files::fpFromHandle(hSourceHandle);
		if (fp == stdin || fp == stdout || fp == stderr) {
			// we never close standard handles so they are fine to duplicate
			void *handle = files::allocFpHandle(fp);
			DEBUG_LOG("-> %p\n", handle);
			*lpTargetHandle = handle;
			return 1;
		}
		// other handles are more problematic; fail for now
		printf("failed to duplicate handle\n");
		assert(0);
	}

	BOOL WIN_FUNC CloseHandle(HANDLE hObject) {
		DEBUG_LOG("CloseHandle(%p)\n", hObject);
		auto data = handles::dataFromHandle(hObject, true);
		if (data.type == handles::TYPE_FILE) {
			FILE *fp = (FILE *) data.ptr;
			if (!(fp == stdin || fp == stdout || fp == stderr)) {
				fclose(fp);
			}
		} else if (data.type == handles::TYPE_MAPPED) {
			if (data.ptr != (void *) 0x1) {
				munmap(data.ptr, data.size);
			}
		}
		return TRUE;
	}

	DWORD WIN_FUNC GetFullPathNameA(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart) {
		DEBUG_LOG("GetFullPathNameA(%s) ", lpFileName);
		std::filesystem::path absPath = std::filesystem::absolute(files::pathFromWindows(lpFileName));
		std::string absStr = files::pathToWindows(absPath);
		DEBUG_LOG("-> %s\n", absStr.c_str());

		// Enough space?
		if ((absStr.size() + 1) <= nBufferLength) {
			strcpy(lpBuffer, absStr.c_str());

			// Do we need to fill in FilePart?
			if (lpFilePart) {
				*lpFilePart = 0;
				if (!std::filesystem::is_directory(absPath)) {
					*lpFilePart = strrchr(lpBuffer, '\\');
					if (*lpFilePart)
						*lpFilePart += 1;
				}
			}

			return absStr.size();
		} else {
			return absStr.size() + 1;
		}
	}

	DWORD WIN_FUNC GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart) {
		const auto fileName = wideStringToString(lpFileName);
		DEBUG_LOG("GetFullPathNameW(%s) ", fileName.c_str());

		const auto lpFileNameA = wideStringToString(lpFileName);
		std::filesystem::path absPath = std::filesystem::absolute(files::pathFromWindows(lpFileNameA.c_str()));
		std::string absStr = files::pathToWindows(absPath);
		const auto absStrW = stringToWideString(absStr.c_str());
		DEBUG_LOG("-> %s\n", absStr.c_str());

		const auto len = wstrlen(absStrW.data());
		if (nBufferLength < len + 1) {
			return len + 1;
		}
		wstrncpy(lpBuffer, absStrW.data(), len + 1);
		assert(!lpFilePart);
		return len;
	}

	/**
	 * @brief GetShortPathNameA: Retrieves the short path form of the specified path
	 *
	 * @param[in] lpszLongPath The path string
	 * @param[out] lpszShortPath A pointer to a buffer to receive
	 * @param[in] cchBuffer The size of the buffer that lpszShortPath points to
	 * @return unsigned int
	 */
	unsigned int WIN_FUNC GetShortPathNameA(const char* lpszLongPath, char* lpszShortPath, unsigned int cchBuffer) {
		DEBUG_LOG("GetShortPathNameA(%s)...\n",lpszShortPath);
		std::filesystem::path absPath = std::filesystem::absolute(files::pathFromWindows(lpszLongPath));
		std::string absStr = files::pathToWindows(absPath);

		if (absStr.length() + 1 > cchBuffer)
		{
			return absStr.length()+1;
		}
		else
		{
			strcpy(lpszShortPath, absStr.c_str());
			return absStr.length();
		}
	}

	DWORD WIN_FUNC GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer) {
		DEBUG_LOG("GetTempPathA\n");

		if ((nBufferLength == 0) || (lpBuffer == 0)) {
			return 0;
		}

		const char* tmp_dir;
		if (!(tmp_dir = getenv("WIBO_TMP_DIR"))) {
			tmp_dir = "Z:\\tmp\\";
		}

		strcpy(lpBuffer, tmp_dir);
		return strlen(tmp_dir);
	}

	struct FindFirstFileHandle {
		std::filesystem::directory_iterator it;
		std::string pattern;
	};

	bool findNextFile(FindFirstFileHandle *handle) {
		if ((handle->it != std::filesystem::directory_iterator()) && (handle->pattern == "")) {
			// The caller (ie `FindFirstFileA`) was passed a path with a
			// trailing period (like `include/.`). This behavior doesn't seem
			// to be documented, so we treat it as an "find any file on this
			// directory".
			return true;
		}
		while (handle->it != std::filesystem::directory_iterator()) {
			std::filesystem::path path = *handle->it;
			if (fnmatch(handle->pattern.c_str(), path.filename().c_str(), 0) == 0) {
				return true;
			}
			handle->it++;
		}
		return false;
	}

	void setFindFileDataFromPath(WIN32_FIND_DATA<char>* data, const std::filesystem::path &path) {
		auto status = std::filesystem::status(path);
		uint64_t fileSize = 0;
		data->dwFileAttributes = 0;
		if (std::filesystem::is_directory(status)) {
			data->dwFileAttributes |= 0x10;
		}
		if (std::filesystem::is_regular_file(status)) {
			data->dwFileAttributes |= 0x80;
			fileSize = std::filesystem::file_size(path);
		}
		data->nFileSizeHigh = (uint32_t)(fileSize >> 32);
		data->nFileSizeLow = (uint32_t)fileSize;
		auto fileName = path.filename().string();
		assert(fileName.size() < 260);
		strcpy(data->cFileName, fileName.c_str());
		strcpy(data->cAlternateFileName, "8P3FMTFN.BAD");
	}

	void *WIN_FUNC FindFirstFileA(const char *lpFileName, WIN32_FIND_DATA<char> *lpFindFileData) {
		// This should handle wildcards too, but whatever.
		auto path = files::pathFromWindows(lpFileName);
		DEBUG_LOG("FindFirstFileA %s (%s)\n", lpFileName, path.c_str());

		lpFindFileData->ftCreationTime = defaultFiletime;
		lpFindFileData->ftLastAccessTime = defaultFiletime;
		lpFindFileData->ftLastWriteTime = defaultFiletime;

		auto status = std::filesystem::status(path);
		if (status.type() == std::filesystem::file_type::regular) {
			setFindFileDataFromPath(lpFindFileData, path);
			return (void *) 1;
		}

		// If the parent path is empty then we assume the parent path is the current directory.
		auto parent_path = path.parent_path();
		if (parent_path == "") {
			parent_path = ".";
		}

		if (!std::filesystem::exists(parent_path)) {
			wibo::lastError = ERROR_PATH_NOT_FOUND;
			return INVALID_HANDLE_VALUE;
		}

		auto *handle = new FindFirstFileHandle();

		std::filesystem::directory_iterator it(parent_path);
		handle->it = it;
		handle->pattern = path.filename().string();

		if (!findNextFile(handle)) {
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			delete handle;
			return INVALID_HANDLE_VALUE;
		}

		setFindFileDataFromPath(lpFindFileData, *handle->it++);
		return handle;
	}

	typedef enum _FINDEX_INFO_LEVELS {
		FindExInfoStandard,
		FindExInfoBasic,
		FindExInfoMaxInfoLevel
	} FINDEX_INFO_LEVELS;

	typedef enum _FINDEX_SEARCH_OPS {
		FindExSearchNameMatch,
		FindExSearchLimitToDirectories,
		FindExSearchLimitToDevices,
		FindExSearchMaxSearchOp
	} FINDEX_SEARCH_OPS;

	void *WIN_FUNC FindFirstFileExA(const char *lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, void *lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, void *lpSearchFilter, unsigned int dwAdditionalFlags) {
		assert(fInfoLevelId == FindExInfoStandard);

		auto path = files::pathFromWindows(lpFileName);
		DEBUG_LOG("FindFirstFileExA %s (%s)\n", lpFileName, path.c_str());

		return FindFirstFileA(lpFileName, (WIN32_FIND_DATA<char> *) lpFindFileData);
	}

	int WIN_FUNC FindNextFileA(void *hFindFile, WIN32_FIND_DATA<char> *lpFindFileData) {
		DEBUG_LOG("FindNextFileA(%p, %p)\n", hFindFile, lpFindFileData);
		// Special value from FindFirstFileA
		if (hFindFile == (void *) 1) {
			wibo::lastError = ERROR_NO_MORE_FILES;
			return 0;
		}

		auto *handle = (FindFirstFileHandle *) hFindFile;
		if (!findNextFile(handle)) {
			wibo::lastError = ERROR_NO_MORE_FILES;
			return 0;
		}

		setFindFileDataFromPath(lpFindFileData, *handle->it++);
		return 1;
	}

	int WIN_FUNC FindClose(void *hFindFile) {
		DEBUG_LOG("FindClose\n");
		if (hFindFile != (void *) 1) {
			delete (FindFirstFileHandle *)hFindFile;
		}
		return 1;
	}

	unsigned int WIN_FUNC GetFileAttributesA(const char *lpFileName) {
		auto path = files::pathFromWindows(lpFileName);
		DEBUG_LOG("GetFileAttributesA(%s)... (%s)\n", lpFileName, path.c_str());

		// See ole32::CoCreateInstance
		if (path == "license.dat" || endsWith(path, "/license.dat")) {
			DEBUG_LOG("MWCC license override\n");
			return 0x80; // FILE_ATTRIBUTE_NORMAL
		}

		/*
		 * MWCC likes to check whether its executable
		 * exists, and throws a warning if it doesn't.
		 */
		if (path == "mwcceppc.exe" || endsWith(path, "/mwcceppc.exe"))
			return 0x80;

		auto status = std::filesystem::status(path);

		wibo::lastError = 0;

		switch (status.type()) {
			case std::filesystem::file_type::regular:
				DEBUG_LOG("File exists\n");
				return 0x80; // FILE_ATTRIBUTE_NORMAL
			case std::filesystem::file_type::directory:
				return 0x10; // FILE_ATTRIBUTE_DIRECTORY
			case std::filesystem::file_type::not_found:
			default:
				DEBUG_LOG("File does not exist\n");
				wibo::lastError = 2; // ERROR_FILE_NOT_FOUND
				return 0xFFFFFFFF; // INVALID_FILE_ATTRIBUTES
		}
	}

	unsigned int WIN_FUNC WriteFile(void *hFile, const void *lpBuffer, unsigned int nNumberOfBytesToWrite, unsigned int *lpNumberOfBytesWritten, void *lpOverlapped) {
		DEBUG_LOG("WriteFile(%p, %d)\n", hFile, nNumberOfBytesToWrite);
		assert(!lpOverlapped);
		wibo::lastError = 0;

		FILE *fp = files::fpFromHandle(hFile);
		size_t written = fwrite(lpBuffer, 1, nNumberOfBytesToWrite, fp);
		if (lpNumberOfBytesWritten)
			*lpNumberOfBytesWritten = written;

#if 0
		printf("writing:\n");
		for (unsigned int i = 0; i < nNumberOfBytesToWrite; i++) {
			printf("%c", ((const char*)lpBuffer)[i]);
		}
		printf("\n");
#endif

		if (written == 0)
			wibo::lastError = 29; // ERROR_WRITE_FAULT

		return (written == nNumberOfBytesToWrite);
	}

	unsigned int WIN_FUNC ReadFile(void *hFile, void *lpBuffer, unsigned int nNumberOfBytesToRead, unsigned int *lpNumberOfBytesRead, void *lpOverlapped) {
		DEBUG_LOG("ReadFile %p %d\n", hFile, nNumberOfBytesToRead);
		assert(!lpOverlapped);
		wibo::lastError = 0;

		FILE *fp = files::fpFromHandle(hFile);
		size_t read = fread(lpBuffer, 1, nNumberOfBytesToRead, fp);
		*lpNumberOfBytesRead = read;
		return 1;
	}

	enum {
		CREATE_NEW = 1,
		CREATE_ALWAYS = 2,
		OPEN_EXISTING = 3,
		OPEN_ALWAYS = 4,
		TRUNCATE_EXISTING = 5,
	};
	void *WIN_FUNC CreateFileA(
			const char* lpFileName,
			unsigned int dwDesiredAccess,
			unsigned int dwShareMode,
			void *lpSecurityAttributes,
			unsigned int dwCreationDisposition,
			unsigned int dwFlagsAndAttributes,
			void *hTemplateFile) {
		std::string path = files::pathFromWindows(lpFileName);
		DEBUG_LOG("CreateFileA(filename=%s (%s), desiredAccess=0x%x, shareMode=%u, securityAttributes=%p, creationDisposition=%u, flagsAndAttributes=%u)\n",
				lpFileName, path.c_str(),
				dwDesiredAccess, dwShareMode, lpSecurityAttributes,
				dwCreationDisposition, dwFlagsAndAttributes);

		wibo::lastError = 0; // possibly overwritten later in this function

		// Based on https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#parameters
		// and this table: https://stackoverflow.com/a/14469641
		bool fileExists = (access(path.c_str(), F_OK) == 0);
		bool shouldTruncate = false;
		switch (dwCreationDisposition) {
			case CREATE_ALWAYS:
				if (fileExists) {
					wibo::lastError = 183; // ERROR_ALREADY_EXISTS
					shouldTruncate = true; // "The function overwrites the file"
					// Function succeeds
				}
				break;
			case CREATE_NEW:
				if (fileExists) {
					wibo::lastError = 80; // ERROR_FILE_EXISTS
					return INVALID_HANDLE_VALUE;
				}
				break;
			case OPEN_ALWAYS:
				if (fileExists) {
					wibo::lastError = 183; // ERROR_ALREADY_EXISTS
					// Function succeeds
				}
				break;
			case OPEN_EXISTING:
				if (!fileExists) {
					wibo::lastError = 2; // ERROR_FILE_NOT_FOUND
					return INVALID_HANDLE_VALUE;
				}
				break;
			case TRUNCATE_EXISTING:
				shouldTruncate = true;
				if (!fileExists) {
					wibo::lastError = 2; // ERROR_FILE_NOT_FOUND
					return INVALID_HANDLE_VALUE;
				}
				break;
			default:
				assert(0);
		}

		FILE *fp;
		if (dwDesiredAccess == 0x80000000) { // read
			fp = fopen(path.c_str(), "rb");
		} else if (dwDesiredAccess == 0x40000000) { // write
			if (shouldTruncate || !fileExists) {
				fp = fopen(path.c_str(), "wb");
			} else {
				// There is no way to fopen with only write permissions
				// and without truncating the file...
				fp = fopen(path.c_str(), "rb+");
			}
		} else if (dwDesiredAccess == 0xc0000000) { // read/write
			if (shouldTruncate || !fileExists) {
				fp = fopen(path.c_str(), "wb+");
			} else {
				fp = fopen(path.c_str(), "rb+");
			}
		} else {
			assert(0);
		}

		if (fp) {
			void *handle = files::allocFpHandle(fp);
			DEBUG_LOG("-> %p\n", handle);
			return handle;
		} else {
			setLastErrorFromErrno();
			return INVALID_HANDLE_VALUE;
		}
	}

	void *WIN_FUNC CreateFileW(const uint16_t *lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode,
				   void *lpSecurityAttributes, unsigned int dwCreationDisposition, unsigned int dwFlagsAndAttributes,
				   void *hTemplateFile) {
		DEBUG_LOG("CreateFileW -> ");
		const auto lpFileNameA = wideStringToString(lpFileName);
		return CreateFileA(lpFileNameA.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
				   dwFlagsAndAttributes, hTemplateFile);
	}

	void *WIN_FUNC CreateFileMappingA(
			void *hFile,
			void *lpFileMappingAttributes,
			unsigned int flProtect,
			unsigned int dwMaximumSizeHigh,
			unsigned int dwMaximumSizeLow,
			const char *lpName) {
		DEBUG_LOG("CreateFileMappingA(%p, %p, %u, %u, %u, %s)\n", hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);

		int64_t size = (int64_t) dwMaximumSizeHigh << 32 | dwMaximumSizeLow;

		void *mmapped;

		if (hFile == (void*) -1) { // INVALID_HANDLE_VALUE
			if (size == 0) {
				mmapped = (void *) 0x1;
			} else {
				mmapped = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			}
		} else {
			int fd = fileno(files::fpFromHandle(hFile));

			if (size == 0) {
				size = getFileSize(hFile);
				if (size == -1) {
					return (void*) -1;
				}
			}

			if (size == 0) {
				mmapped = (void *) 0x1;
			} else {
				mmapped = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
			}
		}

		assert(mmapped != MAP_FAILED);
		return handles::allocDataHandle({handles::TYPE_MAPPED, mmapped, (unsigned int) size});
	}

	void *WIN_FUNC MapViewOfFile(
			void *hFileMappingObject,
			unsigned int dwDesiredAccess,
			unsigned int dwFileOffsetHigh,
			unsigned int dwFileOffsetLow,
			unsigned int dwNumberOfBytesToMap) {
		DEBUG_LOG("MapViewOfFile(%p, %u, %u, %u, %u)\n", hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);

		handles::Data data = handles::dataFromHandle(hFileMappingObject, false);
		assert(data.type == handles::TYPE_MAPPED);
		return (void*)((unsigned int) data.ptr + dwFileOffsetLow);
	}

	int WIN_FUNC UnmapViewOfFile(void *lpBaseAddress) {
		DEBUG_LOG("UnmapViewOfFile(%p)\n", lpBaseAddress);
		return 1;
	}

	int WIN_FUNC DeleteFileA(const char* lpFileName) {
		std::string path = files::pathFromWindows(lpFileName);
		DEBUG_LOG("DeleteFileA %s (%s)\n", lpFileName, path.c_str());
		unlink(path.c_str());
		return 1;
	}

	DWORD WIN_FUNC SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod) {
		DEBUG_LOG("SetFilePointer(%p, %d, %d)\n", hFile, lDistanceToMove, dwMoveMethod);
		assert(!lpDistanceToMoveHigh || *lpDistanceToMoveHigh == 0);
		FILE *fp = files::fpFromHandle(hFile);
		wibo::lastError = ERROR_SUCCESS;
		int r = fseek(fp, lDistanceToMove, dwMoveMethod == 0 ? SEEK_SET : dwMoveMethod == 1 ? SEEK_CUR : SEEK_END);

		if (r < 0) {
			if (errno == EINVAL)
				wibo::lastError = ERROR_NEGATIVE_SEEK;
			else
				wibo::lastError = ERROR_INVALID_PARAMETER;
			return INVALID_SET_FILE_POINTER;
		}

		r = ftell(fp);
		assert(r >= 0);
		return r;
	}

	BOOL WIN_FUNC SetFilePointerEx(HANDLE hFile, LARGE_INTEGER lDistanceToMove, PLARGE_INTEGER lpDistanceToMoveHigh,
								   DWORD dwMoveMethod) {
		assert(!lpDistanceToMoveHigh || *lpDistanceToMoveHigh == 0);
		DEBUG_LOG("SetFilePointerEx(%p, %ld, %d)\n", hFile, lDistanceToMove, dwMoveMethod);
		FILE *fp = files::fpFromHandle(hFile);
		wibo::lastError = ERROR_SUCCESS;
		int r = fseeko64(fp, lDistanceToMove, dwMoveMethod == 0 ? SEEK_SET : dwMoveMethod == 1 ? SEEK_CUR : SEEK_END);

		if (r < 0) {
			if (errno == EINVAL)
				wibo::lastError = ERROR_NEGATIVE_SEEK;
			else
				wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}

		r = ftell(fp);
		assert(r >= 0);
		return TRUE;
	}

	int WIN_FUNC SetEndOfFile(void *hFile) {
		DEBUG_LOG("SetEndOfFile\n");
		FILE *fp = files::fpFromHandle(hFile);
		fflush(fp);
		return ftruncate(fileno(fp), ftell(fp)) == 0;
	}

	int WIN_FUNC CreateDirectoryA(const char *lpPathName, void *lpSecurityAttributes) {
		std::string path = files::pathFromWindows(lpPathName);
		DEBUG_LOG("CreateDirectoryA(%s, %p)\n", path.c_str(), lpSecurityAttributes);
		return mkdir(path.c_str(), 0755) == 0;
	}

	int WIN_FUNC RemoveDirectoryA(const char *lpPathName) {
		std::string path = files::pathFromWindows(lpPathName);
		DEBUG_LOG("RemoveDirectoryA(%s)\n", path.c_str());
		return rmdir(path.c_str()) == 0;
	}

	int WIN_FUNC SetFileAttributesA(const char *lpPathName, unsigned int dwFileAttributes) {
		std::string path = files::pathFromWindows(lpPathName);
		DEBUG_LOG("SetFileAttributesA(%s, %u)\n", path.c_str(), dwFileAttributes);
		return 1;
	}

	unsigned int WIN_FUNC GetFileSize(void *hFile, unsigned int *lpFileSizeHigh) {
		DEBUG_LOG("GetFileSize\n");
		int64_t size = getFileSize(hFile);
		if (size == -1) {
			return 0xFFFFFFFF; // INVALID_FILE_SIZE
		}
		DEBUG_LOG("-> %ld\n", size);
		if (lpFileSizeHigh != nullptr) {
			*lpFileSizeHigh = size >> 32;
		}
		return size;
	}

	/*
	 * Time
	 */
	int WIN_FUNC GetFileTime(void *hFile, FILETIME *lpCreationTime, FILETIME *lpLastAccessTime, FILETIME *lpLastWriteTime) {
		DEBUG_LOG("GetFileTime %p %p %p\n", lpCreationTime, lpLastAccessTime, lpLastWriteTime);
		if (lpCreationTime) *lpCreationTime = defaultFiletime;
		if (lpLastAccessTime) *lpLastAccessTime = defaultFiletime;
		if (lpLastWriteTime) *lpLastWriteTime = defaultFiletime;
		return 1;
	}

	struct SYSTEMTIME {
		short wYear;
		short wMonth;
		short wDayOfWeek;
		short wDay;
		short wHour;
		short wMinute;
		short wSecond;
		short wMilliseconds;
	};

	void WIN_FUNC GetSystemTime(SYSTEMTIME *lpSystemTime) {
		DEBUG_LOG("GetSystemTime\n");

		time_t t = time(NULL);
		struct tm *tm = gmtime(&t);
		assert(tm != NULL);

		lpSystemTime->wYear = tm->tm_year + 1900;
		lpSystemTime->wMonth = tm->tm_mon + 1;
		lpSystemTime->wDayOfWeek = tm->tm_wday;
		lpSystemTime->wDay = tm->tm_mday;
		lpSystemTime->wHour = tm->tm_hour;
		lpSystemTime->wMinute = tm->tm_min;
		lpSystemTime->wSecond = tm->tm_sec;
		lpSystemTime->wMilliseconds = 0;
	}

	void WIN_FUNC GetLocalTime(SYSTEMTIME *lpSystemTime) {
		DEBUG_LOG("GetLocalTime\n");

		time_t t = time(NULL);
		struct tm *tm = localtime(&t);
		assert(tm != NULL);

		lpSystemTime->wYear = tm->tm_year + 1900;
		lpSystemTime->wMonth = tm->tm_mon + 1;
		lpSystemTime->wDayOfWeek = tm->tm_wday;
		lpSystemTime->wDay = tm->tm_mday;
		lpSystemTime->wHour = tm->tm_hour;
		lpSystemTime->wMinute = tm->tm_min;
		lpSystemTime->wSecond = tm->tm_sec;
		lpSystemTime->wMilliseconds = 0;
	}

	int WIN_FUNC SystemTimeToFileTime(const SYSTEMTIME *lpSystemTime, FILETIME *lpFileTime) {
		DEBUG_LOG("SystemTimeToFileTime\n");
		*lpFileTime = defaultFiletime;
		return 1;
	}

	void WIN_FUNC GetSystemTimeAsFileTime(FILETIME *lpSystemTimeAsFileTime) {
		DEBUG_LOG("GetSystemTimeAsFileTime\n");
		*lpSystemTimeAsFileTime = defaultFiletime;
	}

	int WIN_FUNC GetTickCount() {
		DEBUG_LOG("GetTickCount\n");
		return 0;
	}

	int WIN_FUNC FileTimeToSystemTime(const FILETIME *lpFileTime, SYSTEMTIME *lpSystemTime) {
		DEBUG_LOG("FileTimeToSystemTime\n");
		lpSystemTime->wYear = 0;
		lpSystemTime->wMonth = 0;
		lpSystemTime->wDayOfWeek = 0;
		lpSystemTime->wDay = 0;
		lpSystemTime->wHour = 0;
		lpSystemTime->wMinute = 0;
		lpSystemTime->wSecond = 0;
		lpSystemTime->wMilliseconds = 0;
		return 1;
	}

	int WIN_FUNC SetFileTime(void *hFile, const FILETIME *lpCreationTime, const FILETIME *lpLastAccessTime, const FILETIME *lpLastWriteTime) {
		DEBUG_LOG("SetFileTime\n");
		return 1;
	}

	int WIN_FUNC FileTimeToLocalFileTime(const FILETIME *lpFileTime, FILETIME *lpLocalFileTime) {
		DEBUG_LOG("FileTimeToLocalFileTime\n");
		// we live on Iceland
		*lpLocalFileTime = *lpFileTime;
		return 1;
	}

	struct BY_HANDLE_FILE_INFORMATION {
		unsigned long dwFileAttributes;
		FILETIME ftCreationTime;
		FILETIME ftLastAccessTime;
		FILETIME ftLastWriteTime;
		unsigned long dwVolumeSerialNumber;
		unsigned long nFileSizeHigh;
		unsigned long nFileSizeLow;
		unsigned long nNumberOfLinks;
		unsigned long nFileIndexHigh;
		unsigned long nFileIndexLow;
	};

	int WIN_FUNC GetFileInformationByHandle(void *hFile, BY_HANDLE_FILE_INFORMATION *lpFileInformation) {
		DEBUG_LOG("GetFileInformationByHandle(%p, %p)\n", hFile, lpFileInformation);
		FILE* fp = files::fpFromHandle(hFile);
		if (fp == nullptr) {
			wibo::lastError = 6; // ERROR_INVALID_HANDLE
			return 0;
		}
		struct stat64 st{};
		if (fstat64(fileno(fp), &st)) {
			setLastErrorFromErrno();
			return 0;
		}

		if (lpFileInformation != nullptr) {
			lpFileInformation->dwFileAttributes = 0;
			if (S_ISDIR(st.st_mode)) {
				lpFileInformation->dwFileAttributes |= 0x10;
			}
			if (S_ISREG(st.st_mode)) {
				lpFileInformation->dwFileAttributes |= 0x80;
			}
			lpFileInformation->ftCreationTime = defaultFiletime;
			lpFileInformation->ftLastAccessTime = defaultFiletime;
			lpFileInformation->ftLastWriteTime = defaultFiletime;
			lpFileInformation->dwVolumeSerialNumber = 0;
			lpFileInformation->nFileSizeHigh = (unsigned long) (st.st_size >> 32);
			lpFileInformation->nFileSizeLow = (unsigned long) st.st_size;
			lpFileInformation->nNumberOfLinks = 0;
			lpFileInformation->nFileIndexHigh = 0;
			lpFileInformation->nFileIndexLow = 0;
		}
		return 1;
	}

	struct TIME_ZONE_INFORMATION {
		int Bias;
		short StandardName[32];
		SYSTEMTIME StandardDate;
		int StandardBias;
		short DaylightName[32];
		SYSTEMTIME DaylightDate;
		int DaylightBias;
	};

	int WIN_FUNC GetTimeZoneInformation(TIME_ZONE_INFORMATION *lpTimeZoneInformation) {
		DEBUG_LOG("GetTimeZoneInformation\n");
		memset(lpTimeZoneInformation, 0, sizeof(*lpTimeZoneInformation));
		return 0;
	}

	/*
	 * Console Nonsense
	 */
	int WIN_FUNC GetConsoleMode(void *hConsoleHandle, unsigned int *lpMode) {
		DEBUG_LOG("GetConsoleMode(%p)\n", hConsoleHandle);
		*lpMode = 0;
		return 1;
	}

	unsigned int WIN_FUNC SetConsoleCtrlHandler(void *HandlerRoutine, unsigned int Add) {
		DEBUG_LOG("STUB SetConsoleCtrlHandler\n");
		// This is a function that gets called when doing ^C
		// We might want to call this later (being mindful that it'll be stdcall I think)

		// For now, just pretend we did the thing
		return 1;
	}

	struct CONSOLE_SCREEN_BUFFER_INFO {
		int16_t dwSize_x;
		int16_t dwSize_y;
		int16_t dwCursorPosition_x;
		int16_t dwCursorPosition_y;
		uint16_t wAttributes;
		int16_t srWindow_left;
		int16_t srWindow_top;
		int16_t srWindow_right;
		int16_t srWindow_bottom;
		int16_t dwMaximumWindowSize_x;
		int16_t dwMaximumWindowSize_y;
	};

	unsigned int WIN_FUNC GetConsoleScreenBufferInfo(void *hConsoleOutput, CONSOLE_SCREEN_BUFFER_INFO *lpConsoleScreenBufferInfo) {
		DEBUG_LOG("GetConsoleScreenBufferInfo(%p, %p)\n", hConsoleOutput, lpConsoleScreenBufferInfo);
		// Tell a lie
		// mwcc doesn't care about anything else
		lpConsoleScreenBufferInfo->dwSize_x = 80;
		lpConsoleScreenBufferInfo->dwSize_y = 25;

		return 1;
	}

	BOOL WIN_FUNC WriteConsoleW(HANDLE hConsoleOutput, LPCWSTR lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten,
								LPVOID lpReserved) {
		DEBUG_LOG("WriteConsoleW(%p, %p, %u, %p, %p)\n", hConsoleOutput, lpBuffer, nNumberOfCharsToWrite, lpNumberOfCharsWritten,
				  lpReserved);
		const auto str = wideStringToString(lpBuffer, nNumberOfCharsToWrite);
		FILE *fp = files::fpFromHandle(hConsoleOutput);
		if (fp == stdout || fp == stderr) {
			fprintf(fp, "%s", str.c_str());
			if (lpNumberOfCharsWritten) {
				*lpNumberOfCharsWritten = nNumberOfCharsToWrite;
			}
			return TRUE;
		}
		if (lpNumberOfCharsWritten) {
			*lpNumberOfCharsWritten = 0;
		}
		return FALSE;
	}

	unsigned int WIN_FUNC GetSystemDirectoryA(char *lpBuffer, unsigned int uSize) {
		DEBUG_LOG("GetSystemDirectoryA(%p, %u)\n", lpBuffer, uSize);
		if (lpBuffer == nullptr) {
			return 0;
		}

		const char* systemDir = "C:\\Windows\\System32";
		const auto len = strlen(systemDir);

		// If the buffer is too small, return the required buffer size.
		// (Add 1 to include the NUL terminator)
		if (uSize < len + 1) {
			return len + 1;
		}

		strcpy(lpBuffer, systemDir);
		return len;
	}

	unsigned int WIN_FUNC GetWindowsDirectoryA(char *lpBuffer, unsigned int uSize) {
		DEBUG_LOG("GetWindowsDirectoryA(%p, %u)\n", lpBuffer, uSize);
		if (lpBuffer == nullptr) {
			return 0;
		}

		const char* systemDir = "C:\\Windows";
		const auto len = strlen(systemDir);

		// If the buffer is too small, return the required buffer size.
		// (Add 1 to include the NUL terminator)
		if (uSize < len + 1) {
			return len + 1;
		}

		strcpy(lpBuffer, systemDir);
		return len;
	}

	unsigned int WIN_FUNC GetCurrentDirectoryA(unsigned int uSize, char *lpBuffer) {
		DEBUG_LOG("GetCurrentDirectoryA(%u, %p)", uSize, lpBuffer);

		std::filesystem::path cwd = std::filesystem::current_path();
		std::string path = files::pathToWindows(cwd);

		// If the buffer is too small, return the required buffer size.
		// (Add 1 to include the NUL terminator)
		if (path.size() + 1 > uSize) {
			DEBUG_LOG(" !! Buffer too small: %i, %i\n", path.size() + 1, uSize);
			return path.size() + 1;
		}

		DEBUG_LOG(" -> %s\n", path.c_str());
		strcpy(lpBuffer, path.c_str());
		return path.size();
	}

	unsigned int WIN_FUNC GetCurrentDirectoryW(unsigned int uSize, uint16_t *lpBuffer) {
		DEBUG_LOG("GetCurrentDirectoryW\n");

		std::filesystem::path cwd = std::filesystem::current_path();
		std::string path = files::pathToWindows(cwd);

		assert(path.size() < uSize);
		const char *pathCstr = path.c_str();
		for (size_t i = 0; i < path.size() + 1; i++) {
			lpBuffer[i] = pathCstr[i] & 0xFF;
		}
		return path.size();
	}

	HMODULE WIN_FUNC GetModuleHandleA(LPCSTR lpModuleName) {
		DEBUG_LOG("GetModuleHandleA(%s)\n", lpModuleName);
		/*
		 * Returns a pointer to where the EXE is loaded in
		 * memory (which of course doesn't happen anymore).
		 * Nothing bad seems to happen if we return null.
		 */
		return 0;
	}

	DWORD WIN_FUNC GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize) {
		DEBUG_LOG("GetModuleFileNameA (hModule=%p, nSize=%i)\n", hModule, nSize);
		if (lpFilename == nullptr) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return 0;
		}

		const auto absPath = std::filesystem::canonical("/proc/self/exe");
		std::string path = files::pathToWindows(absPath);
		const size_t len = path.size();
		if (nSize == 0) {
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return 0;
		}

		const size_t copyLen = std::min(len, nSize - 1);
		memcpy(lpFilename, path.c_str(), copyLen);
		if (copyLen < nSize) {
			lpFilename[copyLen] = 0;
		}
		if (copyLen < len) {
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return nSize;
		}

		wibo::lastError = ERROR_SUCCESS;
		return copyLen;
	}

	void* WIN_FUNC FindResourceA(void* hModule, const char* lpName, const char* lpType) {
		DEBUG_LOG("FindResourceA %p %s %s\n", hModule, lpName, lpType);
		return (void*)0x100002;
	}

	void* WIN_FUNC LoadResource(void* hModule, void* res) {
		DEBUG_LOG("LoadResource %p %p\n", hModule, res);
		return (void*)0x100003;
	}

	void* WIN_FUNC LockResource(void* res) {
		DEBUG_LOG("LockResource %p\n", res);
		return (void*)0x100004;
	}

	unsigned int WIN_FUNC SizeofResource(void* hModule, void* res) {
		DEBUG_LOG("SizeofResource %p %p\n", hModule, res);
		return 0;
	}

	HMODULE WIN_FUNC LoadLibraryA(LPCSTR lpLibFileName) {
		DEBUG_LOG("LoadLibraryA(%s)\n", lpLibFileName);
		/*
		 * MWCC throws an error if we return null here, but nothing
		 * bad seems to happen if we return anything nonzero.
		 */
		return (void *)0x10;
	}

	BOOL WIN_FUNC FreeLibrary(HMODULE hLibModule) {
		DEBUG_LOG("FreeLibrary(%p)\n", hLibModule);
		return TRUE;
	}

	const unsigned int MAJOR_VER = 6, MINOR_VER = 2, BUILD_NUMBER = 0; // Windows 8

	unsigned int WIN_FUNC GetVersion() {
		DEBUG_LOG("GetVersion\n");
		return MAJOR_VER | MINOR_VER << 8 | 5 << 16 | BUILD_NUMBER << 24;
	}

	typedef struct {
		uint32_t dwOSVersionInfoSize;
		uint32_t dwMajorVersion;
		uint32_t dwMinorVersion;
		uint32_t dwBuildNumber;
		uint32_t dwPlatformId;
		char szCSDVersion[128];
		/**
		 * If dwOSVersionInfoSize indicates more members (i.e. we have an OSVERSIONINFOEXA):
		 * uint16_t wServicePackMajor;
		 * uint16_t wServicePackMinor;
		 * uint16_t wSuiteMask;
		 * uint8_t wProductType;
		 * uint8_t wReserved;
		 */
	} OSVERSIONINFOA;

	int WIN_FUNC GetVersionExA(OSVERSIONINFOA* lpVersionInformation) {
		DEBUG_LOG("GetVersionExA\n");
		memset(lpVersionInformation, 0, lpVersionInformation->dwOSVersionInfoSize);
		lpVersionInformation->dwMajorVersion = MAJOR_VER;
		lpVersionInformation->dwMinorVersion = MINOR_VER;
		lpVersionInformation->dwBuildNumber = BUILD_NUMBER;
		lpVersionInformation->dwPlatformId = 2;
		return 1;
	}

	void *WIN_FUNC HeapCreate(unsigned int flOptions, unsigned int dwInitialSize, unsigned int dwMaximumSize) {
		DEBUG_LOG("HeapCreate %u %u %u\n", flOptions, dwInitialSize, dwMaximumSize);
		if (flOptions & 0x00000001) {
			// HEAP_NO_SERIALIZE
		}
		if (flOptions & 0x00040000) {
			// HEAP_CREATE_ENABLE_EXECUTE
		}
		if (flOptions & 0x00000004) {
			// HEAP_GENERATE_EXCEPTIONS
		}

		// return a dummy value
		wibo::lastError = 0;
		return (void *) 0x100006;
	}

	void *WIN_FUNC VirtualAlloc(void *lpAddress, unsigned int dwSize, unsigned int flAllocationType, unsigned int flProtect) {
		DEBUG_LOG("VirtualAlloc %p %u %u %u\n",lpAddress, dwSize, flAllocationType, flProtect);
		if (flAllocationType & 0x2000 || lpAddress == NULL) { // MEM_RESERVE
			// do this for now...
			assert(lpAddress == NULL);
			void *mem = 0;
			posix_memalign(&mem, 0x1000, dwSize);
			memset(mem, 0, dwSize);

			// Windows only fences off the lower 2GB of the 32-bit address space for the private use of processes.
			assert(mem < (void*)0x80000000);

			DEBUG_LOG("-> %p\n", mem);
			return mem;
		} else {
			assert(lpAddress != NULL);
			return lpAddress;
		}
	}

	unsigned int WIN_FUNC VirtualFree(void *lpAddress, unsigned int dwSize, int dwFreeType) {
		DEBUG_LOG("VirtualFree %p %u %i\n", lpAddress, dwSize, dwFreeType);
		return 1;
	}

	unsigned int WIN_FUNC GetProcessWorkingSetSize(void *hProcess, unsigned int *lpMinimumWorkingSetSize, unsigned int *lpMaximumWorkingSetSize) {
		DEBUG_LOG("GetProcessWorkingSetSize\n");
		// A pointer to a variable that receives the minimum working set size of the specified process, in bytes.
		// The virtual memory manager attempts to keep at least this much memory resident in the process whenever the process is active.
		*lpMinimumWorkingSetSize = 32*1024*1024; // 32MB

		// A pointer to a variable that receives the maximum working set size of the specified process, in bytes.
		// The virtual memory manager attempts to keep no more than this much memory resident in the process whenever
		// the process is active when memory is in short supply.
		*lpMaximumWorkingSetSize = 128*1024*1024; // 128MB

		// If the function succeeds, the return value is nonzero.
		return 1;
	}

	unsigned int WIN_FUNC SetProcessWorkingSetSize(void *hProcess, unsigned int dwMinimumWorkingSetSize, unsigned int dwMaximumWorkingSetSize) {
		DEBUG_LOG("SetProcessWorkingSetSize: min %u, max: %u\n", dwMinimumWorkingSetSize, dwMaximumWorkingSetSize);
		return 1;
	}

	typedef struct _STARTUPINFOA {
		unsigned int   cb;
		char		  *lpReserved;
		char		  *lpDesktop;
		char		  *lpTitle;
		unsigned int   dwX;
		unsigned int   dwY;
		unsigned int   dwXSize;
		unsigned int   dwYSize;
		unsigned int   dwXCountChars;
		unsigned int   dwYCountChars;
		unsigned int   dwFillAttribute;
		unsigned int   dwFlags;
		unsigned short wShowWindow;
		unsigned short cbReserved2;
		unsigned char  lpReserved2;
		void		  *hStdInput;
		void		  *hStdOutput;
		void		  *hStdError;
	} STARTUPINFOA, *LPSTARTUPINFOA;

	void WIN_FUNC GetStartupInfoA(STARTUPINFOA *lpStartupInfo) {
		DEBUG_LOG("GetStartupInfoA\n");
		memset(lpStartupInfo, 0, sizeof(STARTUPINFOA));
	}

	typedef struct _STARTUPINFOW {
		unsigned int  cb;
		unsigned short *lpReserved;
		unsigned short *lpDesktop;
		unsigned short *lpTitle;
		unsigned int  dwX;
		unsigned int  dwY;
		unsigned int  dwXSize;
		unsigned int  dwYSize;
		unsigned int  dwXCountChars;
		unsigned int  dwYCountChars;
		unsigned int  dwFillAttribute;
		unsigned int  dwFlags;
		unsigned short wShowWindow;
		unsigned short cbReserved2;
		unsigned char lpReserved2;
		void *hStdInput;
		void *hStdOutput;
		void *hStdError;
	} STARTUPINFOW, *LPSTARTUPINFOW;

	void WIN_FUNC GetStartupInfoW(_STARTUPINFOW *lpStartupInfo) {
		DEBUG_LOG("GetStartupInfoW\n");
		memset(lpStartupInfo, 0, sizeof(_STARTUPINFOW));
	}

	BOOL WIN_FUNC SetThreadStackGuarantee(PULONG StackSizeInBytes) {
		DEBUG_LOG("STUB: SetThreadStackGuarantee(%p)\n", StackSizeInBytes);
		return TRUE;
	}

	HANDLE WIN_FUNC GetCurrentThread() {
		DEBUG_LOG("STUB: GetCurrentThread\n");
		return (HANDLE)0x100007;
	}

	HRESULT WIN_FUNC SetThreadDescription(HANDLE hThread, const void * /* PCWSTR */ lpThreadDescription) {
		DEBUG_LOG("STUB: SetThreadDescription(%p, %p)\n", hThread, lpThreadDescription);
		return S_OK;
	}

	unsigned short WIN_FUNC GetFileType(void *hFile) {
		DEBUG_LOG("GetFileType %p\n", hFile);
		return 1; // FILE_TYPE_DISK
	}

	unsigned int WIN_FUNC SetHandleCount(unsigned int uNumber) {
		DEBUG_LOG("SetHandleCount %p\n", uNumber);
		return uNumber + 10;
	}

	unsigned int WIN_FUNC GetACP() {
		DEBUG_LOG("GetACP\n");
		// return 65001;    // UTF-8
		// return 1200;     // Unicode (BMP of ISO 10646)
		return 28591;       // Latin1 (ISO/IEC 8859-1)
	}

	typedef struct _cpinfo {
		unsigned int  MaxCharSize;
		unsigned char DefaultChar[2];
		unsigned char LeadByte[12];
	} CPINFO, *LPCPINFO;

	unsigned int WIN_FUNC GetCPInfo(unsigned int codePage, CPINFO* lpCPInfo) {
		DEBUG_LOG("GetCPInfo: %u\n", codePage);
		lpCPInfo->MaxCharSize = 1;
		lpCPInfo->DefaultChar[0] = 0;
		return 1; // success
	}

	unsigned int WIN_FUNC WideCharToMultiByte(unsigned int codePage, unsigned int dwFlags, uint16_t *lpWideCharStr, int cchWideChar, char *lpMultiByteStr, int cbMultiByte, char *lpDefaultChar, unsigned int *lpUsedDefaultChar) {
		DEBUG_LOG("WideCharToMultiByte(codePage=%u, flags=%x, wcs=%p, wideChar=%d, mbs=%p, multiByte=%d, defaultChar=%p, usedDefaultChar=%p)\n", codePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

		if (cchWideChar == -1) {
			cchWideChar = wstrlen(lpWideCharStr) + 1;
		}

		if (cbMultiByte == 0) {
			return cchWideChar;
		}
		for (int i = 0; i < cchWideChar; i++) {
			lpMultiByteStr[i] = lpWideCharStr[i] & 0xFF;
		}

		return cchWideChar;
	}

	unsigned int WIN_FUNC MultiByteToWideChar(unsigned int codePage, unsigned int dwFlags, const char *lpMultiByteStr, int cbMultiByte, uint16_t *lpWideCharStr, int cchWideChar) {
		DEBUG_LOG("MultiByteToWideChar(codePage=%u, dwFlags=%u, multiByte=%d, wideChar=%d)\n", codePage, dwFlags, cbMultiByte, cchWideChar);

		if (cbMultiByte == -1) {
			cbMultiByte = strlen(lpMultiByteStr) + 1;
		}

		// assert (dwFlags == 1); // MB_PRECOMPOSED
		if (cchWideChar == 0) {
			return cbMultiByte;
		}

		assert(cbMultiByte <= cchWideChar);
		for (int i = 0; i < cbMultiByte; i++) {
			lpWideCharStr[i] = lpMultiByteStr[i] & 0xFF;
		}
		return cbMultiByte;
	}

	unsigned int WIN_FUNC GetStringTypeW(unsigned int dwInfoType, const uint16_t *lpSrcStr, int cchSrc, uint16_t *lpCharType) {
		DEBUG_LOG("GetStringTypeW (dwInfoType=%u, lpSrcStr=%p, cchSrc=%i, lpCharType=%p)\n", dwInfoType, lpSrcStr, cchSrc, lpCharType);

		assert(dwInfoType == 1); // CT_CTYPE1

		if (cchSrc < 0)
			cchSrc = wstrlen(lpSrcStr);

		for (int i = 0; i < cchSrc; i++) {
			uint16_t c = lpSrcStr[i];
			assert(c < 256);

			bool upper = ('A' <= c && c <= 'Z');
			bool lower = ('a' <= c && c <= 'z');
			bool alpha = (lower || upper);
			bool digit = ('0' <= c && c <= '9');
			bool space = (c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\f' || c == '\v');
			bool blank = (c == ' ' || c == '\t');
			bool hex = (digit || ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f'));
			bool cntrl = (c < 0x20 || c == 127);
			bool punct = (!cntrl && !digit && !alpha);
			lpCharType[i] = (upper ? 1 : 0) | (lower ? 2 : 0) | (digit ? 4 : 0) | (space ? 8 : 0) | (punct ? 0x10 : 0) | (cntrl ? 0x20 : 0) | (blank ? 0x40 : 0) | (hex ? 0x80 : 0) | (alpha ? 0x100 : 0);
		}

		return 1;
	}

	unsigned int WIN_FUNC FreeEnvironmentStringsW(void *penv) {
		DEBUG_LOG("FreeEnvironmentStringsW: %p\n", penv);
		free(penv);
		return 1;
	}

	unsigned int WIN_FUNC IsProcessorFeaturePresent(unsigned int processorFeature) {
		DEBUG_LOG("IsProcessorFeaturePresent: %u\n", processorFeature);

		if (processorFeature == 0) // PF_FLOATING_POINT_PRECISION_ERRATA
			return 1;
		if (processorFeature == 10) // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
			return 1;
		if (processorFeature == 23) // PF_FASTFAIL_AVAILABLE (__fastfail() supported)
			return 1;

		// sure.. we have that feature...
		DEBUG_LOG("  IsProcessorFeaturePresent: we don't know about feature %u, lying...\n", processorFeature);
		return 1;
	}

	void *WIN_FUNC HeapAlloc(void *hHeap, unsigned int dwFlags, size_t dwBytes) {
		DEBUG_LOG("HeapAlloc(heap=%p, flags=%x, bytes=%u) ", hHeap, dwFlags, dwBytes);

		void *mem = doAlloc(dwBytes, dwFlags & 8);
		DEBUG_LOG("-> %p\n", mem);
		return mem;
	}

	void *WIN_FUNC HeapReAlloc(void *hHeap, unsigned int dwFlags, void *lpMem, size_t dwBytes) {
		DEBUG_LOG("HeapReAlloc(heap=%p, flags=%x, mem=%p, bytes=%u) ", hHeap, dwFlags, lpMem, dwBytes);
		void *ret = doRealloc(lpMem, dwBytes, dwFlags & 8);
		DEBUG_LOG("-> %p\n", ret);
		return ret;
	}

	unsigned int WIN_FUNC HeapSize(void *hHeap, unsigned int dwFlags, void *lpMem) {
		DEBUG_LOG("HeapSize(heap=%p, flags=%x, mem=%p)\n", hHeap, dwFlags, lpMem);
		return malloc_usable_size(lpMem);
	}

	void *WIN_FUNC GetProcessHeap() {
		DEBUG_LOG("GetProcessHeap\n");
		return (void *) 0x100006;
	}

	int WIN_FUNC HeapSetInformation(void *HeapHandle, int HeapInformationClass, void *HeapInformation, size_t HeapInformationLength) {
		DEBUG_LOG("HeapSetInformation %p %d\n", HeapHandle, HeapInformationClass);
		return 1;
	}

	unsigned int WIN_FUNC HeapFree(void *hHeap, unsigned int dwFlags, void *lpMem) {
		DEBUG_LOG("HeapFree(heap=%p, flags=%x, mem=%p)\n", hHeap, dwFlags, lpMem);
		free(lpMem);
		return 1;
	}

	unsigned int WIN_FUNC FormatMessageA(unsigned int dwFlags, void *lpSource, unsigned int dwMessageId,
										 unsigned int dwLanguageId, char *lpBuffer, unsigned int nSize, va_list *argument) {

		DEBUG_LOG("FormatMessageA: flags: %u, message id: %u\n", dwFlags, dwMessageId);

		if (dwFlags & 0x00000100) {
			// FORMAT_MESSAGE_ALLOCATE_BUFFER
		} else if (dwFlags & 0x00002000) {
			// FORMAT_MESSAGE_ARGUMENT_ARRAY
		} else if (dwFlags & 0x00000800) {
			// FORMAT_MESSAGE_FROM_HMODULE
		} else if (dwFlags & 0x00000400) {
			// FORMAT_MESSAGE_FROM_STRING
		} else if (dwFlags & 0x00001000) {
			// FORMAT_MESSAGE_FROM_SYSTEM
			std::string message = std::system_category().message(dwMessageId);
			size_t length = message.length();
			strcpy(lpBuffer, message.c_str());
			return length;
		} else if (dwFlags & 0x00000200) {
			// FORMAT_MESSAGE_IGNORE_INSERTS
		} else {
			// unhandled?
		}

		*lpBuffer = '\0';
		return 0;
	}

	int WIN_FUNC GetComputerNameA(char *lpBuffer, unsigned int *nSize) {
		DEBUG_LOG("GetComputerNameA\n");
		if (*nSize < 9)
			return 0;
		strcpy(lpBuffer, "COMPNAME");
		*nSize = 8;
		return 1;
	}

	void *WIN_FUNC EncodePointer(void *Ptr) {
		return Ptr;
	}

	void *WIN_FUNC DecodePointer(void *Ptr) {
		return Ptr;
	}

	BOOL WIN_FUNC SetDllDirectoryA(LPCSTR lpPathName) {
		DEBUG_LOG("STUB: SetDllDirectoryA(%s)\n", lpPathName);
		return TRUE;
	}

	int WIN_FUNC CompareStringA(int Locale, unsigned int dwCmpFlags, const char *lpString1, int cchCount1, const char *lpString2, int cchCount2) {
		if (cchCount1 < 0)
			cchCount1 = strlen(lpString1);
		if (cchCount2 < 0)
			cchCount2 = strlen(lpString2);
		std::string str1(lpString1, lpString1 + cchCount1);
		std::string str2(lpString2, lpString2 + cchCount2);

		DEBUG_LOG("CompareStringA: '%s' vs '%s' (%u)\n", str1.c_str(), str2.c_str(), dwCmpFlags);
		return doCompareString(str1, str2, dwCmpFlags);
	}

	int WIN_FUNC CompareStringW(int Locale, unsigned int dwCmpFlags, const uint16_t *lpString1, int cchCount1, const uint16_t *lpString2, int cchCount2) {
		std::string str1 = wideStringToString(lpString1, cchCount1);
		std::string str2 = wideStringToString(lpString2, cchCount2);

		DEBUG_LOG("CompareStringW: '%s' vs '%s' (%u)\n", str1.c_str(), str2.c_str(), dwCmpFlags);
		return doCompareString(str1, str2, dwCmpFlags);
	}

	int WIN_FUNC IsValidCodePage(unsigned int CodePage) {
		DEBUG_LOG("IsValidCodePage: %u\n", CodePage);
		// Returns a nonzero value if the code page is valid, or 0 if the code page is invalid.
		return 1;
	}

	int WIN_FUNC IsValidLocale(unsigned int Locale, unsigned int dwFlags) {
		DEBUG_LOG("IsValidLocale: %u %u\n", Locale, dwFlags);
		// Yep, this locale is both supported (dwFlags=1) and installed (dwFlags=2)
		return 1;
	}

	std::string str_for_LCType(int LCType) {
		// https://www.pinvoke.net/default.aspx/Enums/LCType.html
		if (LCType == 4100) { // LOCALE_IDEFAULTANSICODEPAGE
			// Latin1; ref GetACP
			return "28591";
		}
		if (LCType == 4097) { // LOCALE_SENGLANGUAGE
			return "Lang";
		}
		if (LCType == 4098) { // LOCALE_SENGCOUNTRY
			return "Country";
		}
		if (LCType == 0x1) { // LOCALE_ILANGUAGE
			return "0001";
		}
		if (LCType == 0x15) { // LOCALE_SINTLSYMBOL
			return "Currency";
		}
		if (LCType == 0x14) { // LOCALE_SCURRENCY
			return "sCurrency";
		}
		if (LCType == 0x16) { // LOCALE_SMONDECIMALSEP
			return ".";
		}
		if (LCType == 0x17) { // LOCALE_SMONTHOUSANDSEP
			return ",";
		}
		if (LCType == 0x18) { // LOCALE_SMONGROUPING
			return ";";
		}
		if (LCType == 0x50) { // LOCALE_SPOSITIVESIGN
			return "";
		}
		if (LCType == 0x51) { // LOCALE_SNEGATIVESIGN
			return "-";
		}
		if (LCType == 0x1A) { // LOCALE_IINTLCURRDIGITS
			return "2";
		}
		if (LCType == 0x19) { // LOCALE_ICURRDIGITS
			return "2";
		}

		DEBUG_LOG("STUB: LCType 0x%X not implemented\n", LCType);
		return "";
	}

	int WIN_FUNC GetLocaleInfoA(unsigned int Locale, int LCType, LPSTR lpLCData, int cchData) {
		DEBUG_LOG("GetLocaleInfoA %d %d\n", Locale, LCType);
		std::string ret = str_for_LCType(LCType);
		size_t len = ret.size() + 1;

		if (!cchData) {
			return len;
		} else {
			assert(len <= (size_t) cchData);
			memcpy(lpLCData, ret.c_str(), len);
			return 1;
		}
	}

	int WIN_FUNC GetLocaleInfoW(unsigned int Locale, int LCType, LPWSTR lpLCData, int cchData) {
		DEBUG_LOG("GetLocaleInfoW %d %d\n", Locale, LCType);
		std::string info = str_for_LCType(LCType);
		auto ret = stringToWideString(info.c_str());
		size_t len = ret.size();

		if (!cchData) {
			return len;
		} else {
			assert(len <= (size_t) cchData);
			memcpy(lpLCData, ret.data(), len * sizeof(*ret.data()));
			return 1;
		}
	}

	int WIN_FUNC EnumSystemLocalesA(void (*callback)(char *lpLocaleString), int dwFlags) {
		DEBUG_LOG("EnumSystemLocalesA %p %i\n", callback, dwFlags);
		// e.g. something like:
		// callback("en_US");
		// callback("ja_JP");
		return 1;
	}

	int WIN_FUNC GetUserDefaultLCID() {
		DEBUG_LOG("GetUserDefaultLCID\n");
		return 1;
	}

	BOOL WIN_FUNC IsDBCSLeadByte(BYTE TestChar) {
		DEBUG_LOG("IsDBCSLeadByte(%u)\n", TestChar);
		return FALSE; // We're not multibyte (yet?)
	}

	int WIN_FUNC LCMapStringW(int Locale, unsigned int dwMapFlags, const uint16_t* lpSrcStr, int cchSrc, uint16_t* lpDestStr, int cchDest) {
		DEBUG_LOG("LCMapStringW: (locale=%i, flags=%u, src=%p, dest=%p)\n", Locale, dwMapFlags, cchSrc, cchDest);
		if (cchSrc < 0) {
			cchSrc = wstrlen(lpSrcStr) + 1;
		}
		// DEBUG_LOG("lpSrcStr: %s\n", lpSrcStr);
		return 1; // success
	}

	int WIN_FUNC LCMapStringA(int Locale, unsigned int dwMapFlags, const char* lpSrcStr, int cchSrc, char* lpDestStr, int cchDest) {
		DEBUG_LOG("LCMapStringA: (locale=%i, flags=%u, src=%p, dest=%p)\n", Locale, dwMapFlags, cchSrc, cchDest);
		if (cchSrc < 0) {
			cchSrc = strlen(lpSrcStr) + 1;
		}
		// DEBUG_LOG("lpSrcStr: %s\n", lpSrcStr);
		return 0; // fail
	}

	DWORD WIN_FUNC GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) {
		DEBUG_LOG("GetEnvironmentVariableA: %s\n", lpName);
		const char *value = getenv(lpName);
		if (!value) {
			return 0;
		}
		unsigned int len = strlen(value);
		if (nSize == 0) {
			return len + 1;
		}
		if (nSize < len) {
			return len;
		}
		memcpy(lpBuffer, value, len + 1);
		return len;
	}

	unsigned int WIN_FUNC SetEnvironmentVariableA(const char *lpName, const char *lpValue) {
		DEBUG_LOG("SetEnvironmentVariableA: %s=%s\n", lpName, lpValue);
		return setenv(lpName, lpValue, 1 /* OVERWRITE */);
	}

	DWORD WIN_FUNC GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize) {
		DEBUG_LOG("GetEnvironmentVariableW: %s\n", wideStringToString(lpName).c_str());
		const char *value = getenv(wideStringToString(lpName).c_str());
		if (!value) {
			return 0;
		}
		auto wideValue = stringToWideString(value);
		const auto len = wideValue.size();
		if (nSize < len) {
			return len;
		}
		wstrncpy(lpBuffer, wideValue.data(), len);
		return len - 1;
	}

	unsigned int WIN_FUNC QueryPerformanceCounter(unsigned long int *lpPerformanceCount) {
		DEBUG_LOG("QueryPerformanceCounter\n");
		*lpPerformanceCount = 0;
		return 1;
	}

	int WIN_FUNC QueryPerformanceFrequency(uint64_t *lpFrequency) {
		*lpFrequency = 1;
		return 1;
	}

	unsigned int WIN_FUNC IsDebuggerPresent() {
		DEBUG_LOG("IsDebuggerPresent\n");
		// If the current process is not running in the context of a debugger, the return value is zero.
		return 0;
	}

	void *WIN_FUNC SetUnhandledExceptionFilter(void *lpTopLevelExceptionFilter) {
		DEBUG_LOG("SetUnhandledExceptionFilter: %p\n", lpTopLevelExceptionFilter);
		return (void *)0x100008;
	}

	unsigned int WIN_FUNC UnhandledExceptionFilter(void *ExceptionInfo) {
		DEBUG_LOG("UnhandledExceptionFilter: %p\n", ExceptionInfo);
		return 1; // EXCEPTION_EXECUTE_HANDLER
	}

	struct SINGLE_LIST_ENTRY
	{
		SINGLE_LIST_ENTRY *Next;
	};

	struct SLIST_HEADER
	{
		union
		{
			unsigned long Alignment;
			struct
			{
				SINGLE_LIST_ENTRY Next;
				int Depth;
				int Sequence;
			};
		};
	};

	void WIN_FUNC InitializeSListHead(SLIST_HEADER *ListHead) {
		DEBUG_LOG("InitializeSListHead\n");
		// All list items must be aligned on a MEMORY_ALLOCATION_ALIGNMENT boundary.
		posix_memalign((void**)&ListHead, 16, sizeof(SLIST_HEADER));
		memset(ListHead, 0, sizeof(SLIST_HEADER));
	}

	void WIN_FUNC RtlUnwind(void *TargetFrame, void *TargetIp, EXCEPTION_RECORD *ExceptionRecord, void *ReturnValue) {
		DEBUG_LOG("RtlUnwind %p %p %p %p\n", TargetFrame, TargetIp, ExceptionRecord, ReturnValue);
		DEBUG_LOG("WARNING: Silently returning from RtlUnwind - exception handlers and clean up code may not be run");
	}

	int WIN_FUNC InterlockedIncrement(int *Addend) {
		return *Addend += 1;
	}

	int WIN_FUNC InterlockedDecrement(int *Addend) {
		return *Addend -= 1;
	}

	int WIN_FUNC InterlockedExchange(int *Target, int Value) {
		int initial = *Target;
		*Target = Value;
		return initial;
	}

	// These are effectively a copy/paste of the Tls* functions
	enum { MAX_FLS_VALUES = 100 };
	static bool flsValuesUsed[MAX_FLS_VALUES] = { false };
	static void *flsValues[MAX_FLS_VALUES];
	int WIN_FUNC FlsAlloc(void *lpCallback) {
		DEBUG_LOG("FlsAlloc (lpCallback: %x)\n", lpCallback);
		// If the function succeeds, the return value is an FLS index initialized to zero.
		for (size_t i = 0; i < MAX_FLS_VALUES; i++) {
			if (flsValuesUsed[i] == false) {
				flsValuesUsed[i] = true;
				flsValues[i] = 0;
				DEBUG_LOG("...returning %d\n", i);
				return i;
			}
		}
		DEBUG_LOG("...returning nothing\n");
		wibo::lastError = 1;
		return 0xFFFFFFFF; // FLS_OUT_OF_INDEXES
	}

	unsigned int WIN_FUNC FlsFree(unsigned int dwFlsIndex) {
		DEBUG_LOG("FlsFree(%u)\n", dwFlsIndex);
		if (dwFlsIndex >= 0 && dwFlsIndex < MAX_FLS_VALUES && flsValuesUsed[dwFlsIndex]) {
			flsValuesUsed[dwFlsIndex] = false;
			return 1;
		} else {
			wibo::lastError = 1;
			return 0;
		}
	}

	void *WIN_FUNC FlsGetValue(unsigned int dwFlsIndex) {
		// DEBUG_LOG("FlsGetValue(%u)", dwFlsIndex);
		void *result = nullptr;
		if (dwFlsIndex >= 0 && dwFlsIndex < MAX_FLS_VALUES && flsValuesUsed[dwFlsIndex]) {
			result = flsValues[dwFlsIndex];
			// See https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsgetvalue
			wibo::lastError = ERROR_SUCCESS;
		} else {
			wibo::lastError = 1;
		}
		// DEBUG_LOG(" -> %p\n", result);
		return result;
	}

	unsigned int WIN_FUNC FlsSetValue(unsigned int dwFlsIndex, void *lpFlsData) {
		// DEBUG_LOG("FlsSetValue(%u, %p)\n", dwFlsIndex, lpFlsData);
		if (dwFlsIndex >= 0 && dwFlsIndex < MAX_FLS_VALUES && flsValuesUsed[dwFlsIndex]) {
			flsValues[dwFlsIndex] = lpFlsData;
			return 1;
		} else {
			wibo::lastError = 1;
			return 0;
		}
	}

	BOOL WIN_FUNC GetOverlappedResult(void *hFile, void *lpOverlapped, int *lpNumberOfBytesTransferred, BOOL bWait) {
		// DEBUG_LOG("GetOverlappedResult(%p, %p, %p, %u)\n", hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait);
		return 1;
	}

}
