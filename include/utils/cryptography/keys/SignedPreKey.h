//
// Created by Ruairi on 05/06/2025.
//

#ifndef SIGNEDPREKEY_H
#define SIGNEDPREKEY_H
#include <vector>

#include "X25519Key.h"

struct SignedPreKey {
    std::unique_ptr<X25519PrivateKey> private_key;
    std::unique_ptr<X25519PublicKey> public_key;
    std::vector<uint8_t> signature;
};
#endif //SIGNEDPREKEY_H
