//
// Created by Ruairi on 05/06/2025.
//

#ifndef IDENTITYKEYPAIRS_H
#define IDENTITYKEYPAIRS_H
#include <memory>

#include "Ed25519Key.h"
#include "X25519Key.h"


struct  IdentityKeyPairs {
    std::unique_ptr<Ed25519PrivateKey> ed25519_private;
    std::unique_ptr<Ed25519PublicKey> ed25519_public;
    std::unique_ptr<X25519PrivateKey> x25519_private;
    std::unique_ptr<X25519PublicKey> x25519_public;
};
#endif //IDENTITYKEYPAIRS_H
