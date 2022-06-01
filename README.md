# demo-libelectronic-id
A project to develop eID Easy fork [https://github.com/eideasy/libelectronic-id](https://github.com/eideasy/libelectronic-id)

## Build environment setup
See: [https://github.com/web-eid/web-eid-app#build-environment-setup](https://github.com/web-eid/web-eid-app#build-environment-setup)

Our demo-libelectronic-id project has pretty much the same dependencies as web-eid, so we can use the same setup.

### Building and testing in Windows

Use _Powershell_ to run the following commands to build the project.

``cd build ``

Now in the build folder:
- Run _CMake_:

      cmake -A x64  "-DCMAKE_TOOLCHAIN_FILE=c:/vcpkg/scripts/buildsystems/vcpkg.cmake"

- Run the build

      cmake --build . 