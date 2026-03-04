#pragma once

#include <vector>
#include <string>

#include <stdint.h>

using byte_vec = std::vector<unsigned char>;
using string = std::string;

#define PORT 4444
#define IP "127.0.0.1"

#define IV_SIZE 16
#define SALT_SIZE 16
#define SESSION_KEY_SIZE 32
#define HMAC_SIZE 32
#define HASH_SIZE 32
//#define DH_KEY_SIZE 256
#define SIGN_KEY_SIZE 256
#define NONCE_SIZE 16
#define CMD_SIZE 3
#define U32_SIZE sizeof(uint32_t)
#define DH_KEY_SIZE 2048  // FFDHE2048 produces 2048-bit keys

#define LOG "LOG"
#define CRT "CRT"
#define DEL "DEL"
#define GET "GET"
#define ERR "ERR"
#define SGN "SGN"
#define ACK "ACK"
#define CHG "CHG"
#define PRT "PRT"
#define PBK "PBK"
#define VRF "VRF"