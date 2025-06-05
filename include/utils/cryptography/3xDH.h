#pragma once

#include <vector>
#include <openssl/evp.h>

namespace ThreeXDH {

std::vector<uint8_t> perform_3xdh_sender(
    EVP_PKEY* identity_private,
    EVP_PKEY* ephemeral_private,
    EVP_PKEY* recipient_identity_public,
    EVP_PKEY* recipient_signed_prekey_public,
    EVP_PKEY* recipient_one_time_prekey_public = nullptr
);

std::vector<uint8_t> perform_3xdh_recipient(
    EVP_PKEY* identity_private,
    EVP_PKEY* signed_prekey_private,
    EVP_PKEY* sender_identity_public,
    EVP_PKEY* sender_ephemeral_public,
    EVP_PKEY* one_time_prekey_private = nullptr
);

}
