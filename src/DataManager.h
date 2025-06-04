//
// Created by Ruairi on 04/06/2025.
//

#ifndef DATAMANAGER_H
#define DATAMANAGER_H
#include <string>


class DataManager {
public:
    DataManager() = default;

    virtual ~DataManager() = default;

    virtual std::string upload() const = 0;
    virtual void get(const std::string& identifier) = 0;
};



#endif //DATAMANAGER_H
