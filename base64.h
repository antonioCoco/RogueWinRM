#pragma once
char* base64_encode(const unsigned char*, size_t, size_t*);
unsigned char* base64_decode(const char*, size_t, size_t*);
void build_decoding_table();
void base64_cleanup();