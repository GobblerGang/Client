#ifndef DATAMANAGER_H
#define DATAMANAGER_H
#include <string>
#include <nlohmann/json.hpp>

// Abstract base class for data management
// This class cannot be instantiated directly due to pure virtual functions
class DataManager {
public:
    // #Default Constructor
    // Initializes a new DataManager instance with default values
    DataManager() = default;

    // #Virtual Destructor
    // Ensures proper cleanup of derived class resources when deleted through base pointer
    virtual ~DataManager() = default;

    // #Pure Virtual Function Declaration (returns by value)
    // Must be implemented by derived classes to save data to JSON format
    virtual nlohmann::json save() = 0;

    // #Pure Virtual Function Declaration (call by const reference)
    // Must be implemented by derived classes to load data from identifier
    virtual void load(const std::string& identifier) = 0;
};

#endif //DATAMANAGER_H
