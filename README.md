# About

`a-files-updater` is the **Streamlabs Desktop auto-updater** — a Windows C++ application (`slobs-updater.exe`) that handles updating Streamlabs Desktop (SLOBS).

# How this works
**Core flow:**
1. **Launched by the main app** (not directly by users) with CLI parameters specifying the current version, app directory, and executables to run
2. **Prompts the user** to accept or defer the update (shows version/changelog details from a JSON file)
3. **Checks for blocking processes** — if apps are using the virtual webcam driver or otherwise locking files, it shows them and lets the user close them or force-kill them
4. **Checks disk space** — warns if less than 2GB is free before downloading
5. **Downloads files** — multi-threaded downloader with a real-time progress bar showing files done, total count, and MB/s bandwidth
6. **Installs packages** — can download and silently run installers (e.g., VC++ Redistributable) as prerequisites
7. **Copies updated files** — replaces the old app files
8. **Secures the graphics hook directory** — hardens permissions on `%ProgramData%\obs-studio-hook` after every update (see below)
9. **Uses trusted update storage** — stages downloads and rollback copies below an Administrators-owned `%ProgramData%\slobs-updater` directory and verifies its owner, DACL, reparse status, and ancestors before every run
10. **Launches the updated app** — or falls back to launching the old app if the update failed

**Notable details:**
- Built with C++17, uses Boost (locale, iostreams, asio, beast), OpenSSL, and zlib
- Localized into ~25 languages via Boost.locale + gettext `.po` files embedded as Windows resources
- Has a custom Win32 GUI with Streamlabs dark-theme styling (dark background, teal/green accent color)
- Supports both interactive and non-interactive (silent/automated) modes
- Includes crash reporting (`crash-reporter.cc`) and an error state file for the parent app to inspect
- DPI-aware — responds to `WM_DPICHANGED` and scales all UI elements accordingly
- Removes the current updater run after normal completion, prunes abandoned payload runs after 24 hours while skipping active runs, and makes failed-rollback originals eligible for pruning after 7 days

# How to build
As easy as: 
```
set PATH=%PATH%;C:\Program Files\7-Zip\

ci\localization_prepare_binaries.cmd

cmake -H"." -B"build" -G"Visual Studio 17 2022" -DCMAKE_BUILD_TYPE=RelWithDebInfo -A x64 -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static -DCMAKE_INSTALL_PREFIX="%CD%/build/distribute/a-file-updater"

cmake --build build --target install --config RelWithDebInfo
```
## Dependencies
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

### How to run tests

See [How to run Tests](test/TESTING.md)
