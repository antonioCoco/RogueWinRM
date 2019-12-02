#define SECURITY_WIN32 

#pragma once
#include <security.h>
#include <schannel.h>

#pragma comment (lib, "Secur32.Lib")

class LocalNegotiator
{
public:
	LocalNegotiator();
	int handleType1(char* ntlmBytes, int len);
	int handleType3(char* ntlmBytes, int len);
	char* returnType2(unsigned long*);
	PCtxtHandle phContext;
	int authResult;

private:
	CredHandle hCred;
	SecBufferDesc secClientBufferDesc, secServerBufferDesc;
	SecBuffer secClientBuffer, secServerBuffer;
};

