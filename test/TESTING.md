# Integration tests

## How?

```
mkdir build
cd build 
cmake -G "Visual Studio 15 2017 Win64" ../
cmake --build . --target ALL_BUILD --config Debug
cd ..\test
yarn install 
yarn node src\run_tests.js
```

To run just one test. Change `src\run_tests.js` to set `run_one_test` and test paramets like you need. And run it as `node src\run_tests.js`


To just create test environment without automaticaly launching updater use `node src\run_test_env.js`. 

It will generate files and start servers. 

Updater then can be started from IDE as: 

```--base-url "https://localhost/" --version "0.11.9-preview.1" --exec "C:\\work\\repos\\a-files-updater\\build\\Debug\\slobs-updater.exe" --cwd "C:\\work\\repos\\a-files-updater\\test\\testfiles" --app-dir "C:\\work\\repos\\a-files-updater\\test\\testfiles\\initial" --force-temp```

## What?

This test prepare a test environment and run a debug build of updater to test what updater can handle common usecases. 
* It crates 3 folder and generate some files in each folder such as it represent (A) some slobs instalation (B) some update on the server (C) what result should be. 
* Then it start local https server what will emulate update server. Actually it will be two servers. 
* * First just http server to host files from update folder (B) . `http://localhost:8443`
* * Second server is a proxy that should recieve request from updater and forward it to first server or do something to emulate real life bad connection. `https://localhost:443`
* And start the updater with option that it will use folder (A) and local proxy server `https://localhost:443`.
* After updater finishes then test script will compare updated folder (A) with folder (C) to check if all files was updated as expected.  

It also test `failed usecases` in which something block/interupt update. And in that case content of folder 1 should not be changed. 
