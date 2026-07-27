# How to build
As easy as: 
```
set PATH=%PATH%;C:\Program Files\7-Zip\

ci\localization_prepare_binaries.cmd

cmake -H"." -B"build" -G"Visual Studio 17 2022" -DCMAKE_BUILD_TYPE=RelWithDebInfo -A x64 -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static -DCMAKE_INSTALL_PREFIX="%CD%/build/distribute/a-file-updater"

cmake --build build --target install --config RelWithDebInfo
```
##
This project depends on a few third party libraries, all provided by vcpkg (see `vcpkg.json`):

* OpenSSL 3.x
* zlib
* Boost 1.91.x (compiled: iostreams, system, locale; header-only: asio, beast, algorithm)

These libraries are installed automatically by vcpkg during the CMake configure step (manifest mode), so you need a vcpkg checkout — set `VCPKG_ROOT` to it (or pass the toolchain path explicitly as shown above).

In order to build, point CMake at a vcpkg checkout via `VCPKG_ROOT` (or pass `-DCMAKE_TOOLCHAIN_FILE` directly) as shown above, then run cmake however you want.
A C++17 conformant compiler is required. Outside of that, as long as the dependencies are met and compatible, you can use whatever compiler you want.

## Localization

Boost.locale lib with a gettext format used for a localization. 
mo files included in exe by windows resources. 
### Commands 

`ci\localization_prepare_binaries.cmd` - prepares mo files with current translation 

`ci\localization_set_translations.cmd` - update po files with current strings from source code 

### Add new language 

* Add new lang code into `ci\localization_get_tools.cmd` and run `ci\localization_set_translations.cmd`
* Translate lines inside `locale\NEW_LANG\LC_MESSAGES\messages.po`
* Add new mo file to `resources\slobs-updater.rc`
* Add it to `locales_resources` map inside `get_messages_callback()`
* Prepare binaries `ci\localization_prepare_binaries.cmd`
* Make a new build 
* Do not forget to commit `locale\NEW_LANG\LC_MESSAGES\messages.po`
* to test `set LANG=fr_FR`