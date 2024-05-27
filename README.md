### target

Windows API 测试demo， 启动web服务器调用windows API，以及测试集成常用开源三方库。


### prerequires

windows CMD
```
git clone https://github.com/microsoft/vcpkg
cd vcpkg

./bootstrap-vcpkg.bat

./vcpkg install boost:x64-windows-static
./vcpkg install jsoncpp:x64-windows
./vcpkg integrate install
```

### build
powershell
```
mkdir build
cd build

cmake -DCMAKE_TOOLCHAIN_FILE=$pathtovcpkg/scripts/buildsystems/vcpkg.cmake -DBoost_INCLUDE_DIR=$pathtovcpkg/installed/x64-windows-static/include ../
cmake --build . --config Release
```

### run
server
```
.\demo.exe 0.0.0.0 80
```

client
```
curl -X POST http://$ip/winlogon -d '{"username":"xxxx", "domain":"xxxx", "password":"xxxx"}'
```