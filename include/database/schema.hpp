#include "models/UserModelORM.h"
#include "models/KEKModel.h"
#include "sqlite_orm/sqlite_orm.h"

using namespace sqlite_orm;

inline auto initStorage(const std::string& path = "database.sqlite") {
    return make_storage(path,

        make_table("users",
            make_column("id", &UserModelORM::id, primary_key().autoincrement()),
            make_column("uuid", &UserModelORM::uuid, unique(), not_null()),
            make_column("username", &UserModelORM::username, unique(), not_null()),
            make_column("email", &UserModelORM::email, unique(), not_null()),

            // Ed25519 identity key fields
            make_column("ed25519_identity_key_public", &UserModelORM::ed25519_identity_key_public),
            make_column("ed25519_identity_key_private_enc", &UserModelORM::ed25519_identity_key_private_enc),
            make_column("ed25519_identity_key_private_nonce", &UserModelORM::ed25519_identity_key_private_nonce),

            // X25519 identity key fields
            make_column("x25519_identity_key_public", &UserModelORM::x25519_identity_key_public),
            make_column("x25519_identity_key_private_enc", &UserModelORM::x25519_identity_key_private_enc),
            make_column("x25519_identity_key_private_nonce", &UserModelORM::x25519_identity_key_private_nonce),

            // Salt and signed prekey fields
            make_column("salt", &UserModelORM::salt),
            make_column("signed_prekey_public", &UserModelORM::signed_prekey_public),
            make_column("signed_prekey_signature", &UserModelORM::signed_prekey_signature),
            make_column("signed_prekey_private_enc", &UserModelORM::signed_prekey_private_enc),
            make_column("signed_prekey_private_nonce", &UserModelORM::signed_prekey_private_nonce),

            // One-time prekeys as JSON
            make_column("opks_json", &UserModelORM::opks_json)
        ),

        make_table("keks",
            make_column("id", &KEKModel::id, primary_key().autoincrement()),
            make_column("enc_kek", &KEKModel::enc_kek_cyphertext, not_null()),
            make_column("kek_nonce", &KEKModel::nonce, not_null()),
            make_column("updated_at", &KEKModel::updated_at, not_null()),
            make_column("user_id", &KEKModel::user_id, not_null()),
            foreign_key(&KEKModel::user_id).references(&UserModelORM::id)
        )
    );
}