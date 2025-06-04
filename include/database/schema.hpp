#include "models.h"
#include "sqlite_orm/sqlite_orm.h"

using namespace sqlite_orm;

inline auto initStorage(const std::string& path = "database.sqlite") {
    return make_storage(path,

        make_table("users",
            make_column("id", &UserLocal::id, primary_key().autoincrement()),
            make_column("uuid", &UserLocal::uuid, unique(), not_null()),
            make_column("username", &UserLocal::username, unique(), not_null()),
            make_column("email", &UserLocal::email, unique(), not_null()),
            
            // Ed25519 identity key fields
            make_column("ed25519_identity_key_public", &UserLocal::ed25519_identity_key_public),
            make_column("ed25519_identity_key_private_enc", &UserLocal::ed25519_identity_key_private_enc),
            make_column("ed25519_identity_key_private_nonce", &UserLocal::ed25519_identity_key_private_nonce),
            
            // X25519 identity key fields
            make_column("x25519_identity_key_public", &UserLocal::x25519_identity_key_public),
            make_column("x25519_identity_key_private_enc", &UserLocal::x25519_identity_key_private_enc),
            make_column("x25519_identity_key_private_nonce", &UserLocal::x25519_identity_key_private_nonce),
            
            // Salt and signed prekey fields
            make_column("salt", &UserLocal::salt),
            make_column("signed_prekey_public", &UserLocal::signed_prekey_public),
            make_column("signed_prekey_signature", &UserLocal::signed_prekey_signature),
            make_column("signed_prekey_private_enc", &UserLocal::signed_prekey_private_enc),
            make_column("signed_prekey_private_nonce", &UserLocal::signed_prekey_private_nonce),
            
            // One-time prekeys as JSON
            make_column("opks_json", &UserLocal::opks_json)
        ),

        make_table("keks",
            make_column("id", &KEKLocal::id, primary_key().autoincrement()),
            make_column("enc_kek", &KEKLocal::enc_kek, not_null()),
            make_column("kek_nonce", &KEKLocal::kek_nonce, not_null()),
            make_column("updated_at", &KEKLocal::updated_at, not_null()),
            make_column("user_id", &KEKLocal::user_id, not_null()),
            foreign_key(&KEKLocal::user_id).references(&UserLocal::id)
        )
    );
}