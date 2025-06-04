//
// Created by Ruairi on 04/06/2025.
//

#ifndef CONFIG_H
#include <string>

class Config {
public:
    static Config& get_instance();
    const std::string& server_url() const;

private:
    Config();
    std::string server_url_;
};
#define CONFIG_H

#endif //CONFIG_H
