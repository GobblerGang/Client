#include "models.h"
#include "sqlite_orm/sqlite_orm.h"

using namespace sqlite_orm;

inline auto initStorage(const std::string& path = "database.sqlite") {
    return make_storage(path,

        make_table("users",
            make_column("id", &User::id, primary_key().autoincrement()),
            make_column("uuid", &User::uuid, unique(), not_null()),
            make_column("username", &User::username, unique(), not_null()),
            make_column("email", &User::email, unique(), not_null()),
            
            // Ed25519 identity key fields
            make_column("ed25519_identity_key_public", &User::ed25519_identity_key_public),
            make_column("ed25519_identity_key_private_enc", &User::ed25519_identity_key_private_enc),
            make_column("ed25519_identity_key_private_nonce", &User::ed25519_identity_key_private_nonce),
            
            // X25519 identity key fields
            make_column("x25519_identity_key_public", &User::x25519_identity_key_public),
            make_column("x25519_identity_key_private_enc", &User::x25519_identity_key_private_enc),
            make_column("x25519_identity_key_private_nonce", &User::x25519_identity_key_private_nonce),
            
            // Salt and signed prekey fields
            make_column("salt", &User::salt),
            make_column("signed_prekey_public", &User::signed_prekey_public),
            make_column("signed_prekey_signature", &User::signed_prekey_signature),
            make_column("signed_prekey_private_enc", &User::signed_prekey_private_enc),
            make_column("signed_prekey_private_nonce", &User::signed_prekey_private_nonce),
            
            // One-time prekeys as JSON
            make_column("opks_json", &User::opks_json)
        ),

        make_table("keks",
            make_column("id", &KEK::id, primary_key().autoincrement()),
            make_column("enc_kek", &KEK::enc_kek, not_null()),
            make_column("kek_nonce", &KEK::kek_nonce, not_null()),
            make_column("updated_at", &KEK::updated_at, not_null()),
            make_column("user_id", &KEK::user_id, not_null()),
            foreign_key(&KEK::user_id).references(&User::id)
        )
    );
}