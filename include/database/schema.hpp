#include "models.h"
#include "sqlite_orm/sqlite_orm.h"

using namespace sqlite_orm;

inline auto initStorage(const std::string& path = "database.sqlite") {
    return make_storage(path,

        make_table("users",
            make_column("id", &UserModel::id, primary_key().autoincrement()),
            make_column("uuid", &UserModel::uuid, unique(), not_null()),
            make_column("username", &UserModel::username, unique(), not_null()),
            make_column("email", &UserModel::email, unique(), not_null()),
            
            // Ed25519 identity key fields
            make_column("ed25519_identity_key_public", &UserModel::ed25519_identity_key_public),
            make_column("ed25519_identity_key_private_enc", &UserModel::ed25519_identity_key_private_enc),
            make_column("ed25519_identity_key_private_nonce", &UserModel::ed25519_identity_key_private_nonce),
            
            // X25519 identity key fields
            make_column("x25519_identity_key_public", &UserModel::x25519_identity_key_public),
            make_column("x25519_identity_key_private_enc", &UserModel::x25519_identity_key_private_enc),
            make_column("x25519_identity_key_private_nonce", &UserModel::x25519_identity_key_private_nonce),
            
            // Salt and signed prekey fields
            make_column("salt", &UserModel::salt),
            make_column("signed_prekey_public", &UserModel::signed_prekey_public),
            make_column("signed_prekey_signature", &UserModel::signed_prekey_signature),
            make_column("signed_prekey_private_enc", &UserModel::signed_prekey_private_enc),
            make_column("signed_prekey_private_nonce", &UserModel::signed_prekey_private_nonce),
            
            // One-time prekeys as JSON
            make_column("opks_json", &UserModel::opks_json)
        ),

        make_table("keks",
            make_column("id", &KEKModel::id, primary_key().autoincrement()),
            make_column("enc_kek", &KEKModel::enc_kek, not_null()),
            make_column("kek_nonce", &KEKModel::kek_nonce, not_null()),
            make_column("updated_at", &KEKModel::updated_at, not_null()),
            make_column("user_id", &KEKModel::user_id, not_null()),
            foreign_key(&KEKModel::user_id).references(&UserModel::id)
        )
    );
}