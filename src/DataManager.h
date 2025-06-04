//
// Created by Ruairi on 04/06/2025.
//

#ifndef DATAMANAGER_H
#define DATAMANAGER_H
#include <string>
#include <nlohmann/json.hpp>

// Base class for data management
class DataManager {
public:
    DataManager() = default;

    virtual ~DataManager() = default;
protected:
    virtual nlohmann::json save() = 0;
    virtual void load(const std::string& identifier) = 0;
};



#endif //DATAMANAGER_H
