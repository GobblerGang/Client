#pragma once

#include <string>
#include <vector>
#include <tuple>
#include "keys/Ed25519Key.h"
#include "keys/X25519Key.h"

class KeyGeneration {
public:
    static std::vector<uint8_t> derive_master_key(const std::string& password, const std::vector<uint8_t>& salt);

    static std::pair<
        std::pair<Ed25519PrivateKey*, Ed25519PublicKey*>,
        std::pair<X25519PrivateKey*, X25519PublicKey*>
    > generate_identity_keypair();

    static std::vector<uint8_t> generate_kek();

    static std::tuple<X25519PrivateKey *, X25519PublicKey *, std::vector<uint8_t>>
    generate_signed_prekey(EVP_PKEY *identity_key);
};
