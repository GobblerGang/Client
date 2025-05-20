# Dev Setup
1. Clone the repository
2. Open the repository in CLion
3. Navigate to File → Settings → Build, Execution, Deployment → CMake
4. In the "CMake options" field, add:
   ```
   -DQt6_DIR="path/to/Qt6/folder" -DCMAKE_PREFIX_PATH="path/to/mingw_64/folder"
   ```
5. Click "Apply" and then "OK"
   