#ifndef DATAMANAGER_H
#define DATAMANAGER_H
#include <string>
#include <nlohmann/json.hpp>

// Base class for data management
class DataManager {
public:
    // #Default Constructor
    // Initializes a new DataManager instance with default values
    DataManager() = default;

    // #Virtual Destructor
    // Ensures proper cleanup of derived class resources when deleting through base pointer
    virtual ~DataManager() = default;

protected:
    // #Pure Virtual Function Declaration (returns by value)
    // Saves the current state of the data manager to a JSON object
    virtual nlohmann::json save() = 0;

    // #Pure Virtual Function Declaration (call by const reference)
    // Loads data from the specified identifier
    virtual void load(const std::string& identifier) = 0;
};

#endif //DATAMANAGER_H
