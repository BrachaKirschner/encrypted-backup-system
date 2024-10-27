# Client-Server Backup System
## Description
This project is a client-server backup system. 
The server listens for connections from clients and stores the files that the clients send.
I developed this project for the Programming defensive systems (20937) course at the Open University.

## Demo Video
The demo video is available [here](https://youtu.be/fK1mC_cp8Zc).

## Configuration
### Client
- Developed in visual studio 2022
- Written in ISO C++17

#### External Libraries:
#### 1. [Boost 1_86_0](https://www.boost.org/)
##### Installation:
- Download the boost library from the official website
- Extract it to a directory of your choice (e.g., `D:\boost_1_86_0`).
##### Compilation:
- Open **CMD** as an administrator in the Boost folder.
- ```bash
   bootstrap.bat
   b2 link=static runtime-link=static
    ```
- Add the `D:\boost_1_86_0` directory to the project's include directories.
#### Configuration:
- Open your project in Visual Studio.
- Add the main boost directory (e.g., `D:\boost_1_86_0`) to 
  **project->properties->C/C++->General->Additional Include Directories**.
- Add the path of the `stage\lib` folder in the boost directory (e.g., `D:\boost_1_86_0\stage\lib`) to 
  **project->properties->Linker->General->Additional Library Directories**.

#### 2. [Crypto++](https://www.cryptopp.com/)
##### installation:
- Download the Crypto++ library from the official website
- Extract it to a directory of your choice (e.g., `D:\cryptopp`).
##### Compilation:
- Open cryptest.sln in Visual Studio (double-click on it or from `File->Open->Project/Solution`).
- Build the project in `Build->Build Solution` (or press Ctrl+Shift+B).
##### Configuration:
- Add the main boost directory (e.g., `D:\cryptopp`) to 
  **project->properties->C/C++->General->Additional Include Directories**.
- Add the path of the file cryptlib.lib in the Crypto++ directory (e.g., `D:\cryptopp\Win32\Output\Debug\cryptlib.lib`) 
  to **project->properties->Linker->Input->Additional Dependencies**.
- Ensure that the runtime environment of **your project** is set to static in
  **project->properties->C/C++->Code Generation->Runtime Library->Multi-threaded Debug (/MTd)**.

### Server
- Developed in PyCharm 2024.2.1
- Written in Python 3.12
- No external libraries are required.