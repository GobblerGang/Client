#pragma once
#include "schema.hpp"

inline auto& db() {
    static auto storage = initStorage("database.sqlite");
    static bool initialized = []{
        storage.sync_schema(); // This creates tables if they don't exist
        return true;
    }();
    return storage;
}
