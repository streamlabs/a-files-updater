# Integration tests

## How?

```
mkdir build
cd build 
cmake -G "Visual Studio 17 2022" ../
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

## Graphics hook directory

The repair of `%ProgramData%\obs-studio-hook` is covered in two places, both of
which need an **elevated terminal** - the repair takes ownership and rewrites
DACLs, so tests that set up its inputs have to as well.

### Unit level: `hook-dir-tests.exe`

Builds from the same `src/hook-permissions.cc` the updater ships and drives it
against scratch directories, so the shapes a real machine only produces
occasionally can be built on purpose: a directory owned by a standard user, a
hook held open by a running process, a junction where the directory should be,
an untrusted parent, an install directory nobody should publish from.

```
cmake --build build --target hook-dir-tests --config Debug
build\Debug\hook-dir-tests.exe
```

The scratch root defaults to `%ProgramData%\slobs-hook-tests`, beside the real
hook directory rather than under `%TEMP%`. That is not arbitrary: the trust
check walks every ancestor to the drive root, and anything below a user-owned
directory reports `AncestorUntrusted` whatever the repair did. Pass
`--scratch <path>` to move it, keeping that in mind.

One case is skipped by default, because `C:\` is not ours to re-permission:

```
powershell -File test\native\mount-test-volume.ps1        # mounts a scratch VHD
build\Debug\hook-dir-tests.exe --volume-root X:\
powershell -File test\native\mount-test-volume.ps1 -Remove
```

It puts the default drive-root ACE on that volume with its inherit-only flag
stripped - the shape that made every path on a real machine fail the chain
check - and asserts the repair still goes through.

### Flow level: the integration pack

Two scenarios in `run_tests.js` run the whole updater against a scratch hook
directory, passed with `--hook-dir` so the machine's real one is never touched.
`--hook-dir` refuses an override reached through anything but Administrators,
so `hook_dir.js` locks down the scratch tree's ancestors before the updater
ever sees the path - only the leaf itself is left the way each scenario needs it:

* `hookDirTest` - the directory is left owned by the current user and writable
  by `BUILTIN\Users`; the updater should quarantine it, harden it, and report
  nothing.
* `hookDirBlocked` - the pack's blocker is copied in as `graphics-hook64.dll`
  and launched, so its running image holds the file open exactly as a hooked
  game does. The update should still finish, and `HookQuarantineBlocked` should
  arrive at the crash report emulator.

Set `hookPrompt` to `'0'` to check that the repair still runs and reports with
the dialog withdrawn. Interactive runs (`runAsInteractive = 1`) show the dialog
with the holder named in it; closing the holder should clear it within a second.

Without elevation these scenarios fail with a message rather than passing
quietly. Each quarantine also queues its directory for deletion at the next
reboot; cleanup deletes them first, so those entries become no-ops, but
`PendingFileRenameOperations` collects one per quarantine until you reboot.

Not covered yet: the newest-wins arbitration between our payload and a hook
another OBS-derived app published, which needs two DLLs carrying different
version resources.
