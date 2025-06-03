// #include "Auth.h"
// #include "database/db_instance.h"
// #include <random>
// #include "utils/CryptoUtils.h"
// #include "utils/VaultManager.h"
// #include "utils/Ed25519Key.h"
// #include "utils/X25519Key.h"
//
// Auth::SignUpResult Auth::signup(const std::string& username, const std::string& email, const std::string& password) {
//     if (usernameExists(username)) {
//         return { false, "Username already exists" };
//     }
//
//     if (emailExists(email)) {
//         return { false, "Email already registered" };
//     }
//
//     if (password.empty()) {
//         return { false, "Password is required" };
//     }
//
//     std::vector<uint8_t> salt(16);
//     std::generate(salt.begin(), salt.end(), std::rand);
//
//     std::vector<uint8_t> masterKey = CryptoUtils::derive_master_key(password, salt);
//     std::vector<uint8_t> kek;
//         // generateKEK(); not implemented yet
//
//     auto [identityPriv, identityPub] = CryptoUtils::generate_identity_keypair();
//     auto [spkPriv, spkPub, spkSig] = CryptoUtils::generate_signed_prekey(identityPriv);
//     std::vector<uint8_t> opks;
//
//     std::string vault = VaultManager::generate_user_vault(identityPriv, identityPub, spkPriv, spkPub, spkSig, salt, kek, opks);
//
//     auto uuidOpt = requestUUIDFromServer();
//     if (!uuidOpt.has_value()) {
//         return { false, "Error communicating with the server" };
//     }
//
//     std::string encryptedKEK = encryptKEK(kek, masterKey, uuidOpt.value());
//
//     auto user = createUser(username, email, vault, uuidOpt.value(), encryptedKEK);
//     if (!user.has_value()) {
//         return { false, "Failed to create user" };
//     }
//
//     return { true, "Registration successful! Please login." };
// }
//
// bool Auth::usernameExists(const std::string& username) {
//     auto users = db().get_all<User>(where(c(&User::username) == username));
//     return !users.empty();
// }
//
// bool Auth::emailExists(const std::string& email) {
//     auto users = db().get_all<User>(where(c(&User::email) == email));
//     return !users.empty();
// }
//
// std::optional<std::string> Auth::requestUUIDFromServer() {
//     // Simulate successful server request
//     return "generated-uuid-1234";
// }
//
//
// std::optional<std::string> Auth::createUser(
//     const std::string& username,
//     const std::string& email,
//     const std::string& vault,
//     const std::string& userUUID,
//     const std::string& encryptedKEK
// ) {
//     try {
//         User user;
//         user.username = username;
//         user.email = email;
//         user.vault = vault;
//         user.uuid = userUUID;
//         user.kek = encryptedKEK;
//         db().insert(user);
//         return userUUID;
//     } catch (...) {
//         return std::nullopt;
//     }
// }
