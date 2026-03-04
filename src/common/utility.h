#pragma once

#include <openssl/evp.h>

#include "types.h"
#define ERR_CHECK(x) if(x) return false
#define ERR_CHECK_MSG(x, msg) if(x) { printf(msg); return false; }

bool read_msg(int sock, byte_vec& out);
bool write_msg(int sock, const byte_vec& data);
bool sendSecure(int sock, byte_vec& c_nonce, byte_vec& s_nonce, const byte_vec& key, const byte_vec& mac, byte_vec& cmd, byte_vec& data);
bool recvSecure(int sock, byte_vec& c_nonce, byte_vec& s_nonce, const byte_vec& key, const byte_vec& mac, byte_vec& cmd, byte_vec& data);

bool generateDhPair(EVP_PKEY** dh_key);
bool extractDhPubKeyDer(EVP_PKEY* dh_keypair, byte_vec& pubkey);
bool getDhSharedKey(EVP_PKEY* our_keypair, const byte_vec& peer_pubkey_der, byte_vec& shared_key);
bool deriveKeys(const byte_vec& shared_key, byte_vec& c_key, byte_vec& s_key, byte_vec& c_mac, byte_vec& s_mac, const byte_vec& salt);

//for server
bool serverSignature(EVP_PKEY* priv_key, const byte_vec& data, byte_vec& signature);
bool cbcEncrypt(const byte_vec& key, const byte_vec& iv, const byte_vec& plaintext, byte_vec& ciphertext);
bool hmacCompute(const byte_vec& key, const byte_vec& data, byte_vec& hmac);

//for client
bool serverVerify(const byte_vec& data, const byte_vec& signature, EVP_PKEY* s_pub_key);
bool cbcDecrypt(const byte_vec& key, const byte_vec& iv, const byte_vec& ciphertext, byte_vec& plaintext);

