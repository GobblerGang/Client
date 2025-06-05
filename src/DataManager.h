#ifndef DATAMANAGER_H
#define DATAMANAGER_H
#include <string>
#include <nlohmann/json.hpp>

// Base class for data management
class DataManager {
public:
    // #Default Constructor
    DataManager() = default;

    // #Virtual Destructor
    virtual ~DataManager() = default;
protected:
    // #Pure Virtual Function Declaration (returns by value)
    virtual nlohmann::json save() = 0;
    // #Pure Virtual Function Declaration (call by const reference)
    virtual void load(const std::string& identifier) = 0;
};



#endif //DATAMANAGER_H
