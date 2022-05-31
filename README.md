# play-libelectronic-id
A project to play around with [https://github.com/web-eid/libelectronic-id](https://github.com/web-eid/libelectronic-id)

## Build environment setup
See: [https://github.com/web-eid/web-eid-app#build-environment-setup](https://github.com/web-eid/web-eid-app#build-environment-setup)

## Building
```shell
cd build
cmake .. # optionally with -DCMAKE_BUILD_TYPE=Debug
cmake --build . # optionally with VERBOSE=1
```

You can then run the built app:
```shell
./play_libelectronic_id
```