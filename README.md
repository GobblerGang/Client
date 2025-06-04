# Dev Setup

## Prerequisites
- CMake 3.27 or higher
- Qt 6.4 or higher
- OpenSSL
- SQLite3
- Argon2 library

## Windows Setup (CLion)
1. Clone the repository
2. Open the repository in CLion
3. Install dependencies using vcpkg:
   vcpkg install argon2 openssl sqlite3

4. Navigate to File → Settings → Build, Execution, Deployment → CMake
5. In the "CMake options" field, add:\
   `-DQt6_DIR="path/to/Qt6/6.4.3/msvc2019_64/lib/cmake/Qt6" -DCMAKE_TOOLCHAIN_FILE="path/to/vcpkg/scripts/buildsystems/vcpkg.cmake"`

Example:\
`-DQt6_DIR="C:/Qt/6.4.3/msvc2019_64/lib/cmake/Qt6" -DCMAKE_TOOLCHAIN_FILE="C:/vcpkg/scripts/buildsystems/vcpkg.cmake"`

6. Click "Apply" and then "OK"
7. Build and run the project

## macOS Setup (CLion)
1. Clone the repository
2. Install dependencies using Homebrew:
   brew install qt openssl sqlite argon2

3. Open the repository in CLion
4. Navigate to CLion → Preferences → Build, Execution, Deployment → CMake
5. In the "CMake options" field, add:\
   `-DQt6_DIR="/usr/local/opt/qt/lib/cmake/Qt6" -DCMAKE_PREFIX_PATH="/usr/local/opt/qt"`

6. Click "Apply" and then "OK"
7. Build and run the project

## Additional Configuration
For both platforms, you may need to create a `local_config.cmake` file in the project root for machine-specific paths with contents like:\
`set(Qt6_DIR "path/to/qt/cmake")
set(OpenSSL_ROOT_DIR "path/to/openssl")`

### Server URL Configuration
You must create a `config.json` file and place it in your `cmake-build-debug` directory.  
This file should contain your server URL in the following format:
```json
{
  "server_url": "https://your-server-url.com"
}
```
The application will read this file to determine which server to connect to.

## Troubleshooting
- If you get Qt not found errors, verify your Qt installation path
- For OpenSSL issues, ensure it's installed and the path is correct
- For Argon2 problems, verify it's installed via vcpkg (Windows) or Homebrew (macOS)
