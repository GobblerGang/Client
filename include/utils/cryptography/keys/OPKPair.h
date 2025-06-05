#pragma once
#include "X25519Key.h"

struct OPKPair {
    X25519PrivateKey private_key;
    X25519PublicKey public_key;
};