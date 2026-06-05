REM zlib and openssl are provided by vcpkg now (see vcpkg.json). Only boost is
REM still fetched as a prebuilt archive; it moves to vcpkg in a follow-up.
set WORK_DIR=%CD%
set BOOST_DIST_NAME=boost-vc143-1_79_0-bin
set DEPS_DIST_URI=https://s3-us-west-2.amazonaws.com/streamlabs-obs-updater-deps

mkdir "%DEPS_LOCAL_PATH%"
cd "%DEPS_LOCAL_PATH%"

curl -kLO "%DEPS_DIST_URI%/%BOOST_DIST_NAME%.7z" -f --retry 5

7z x "%BOOST_DIST_NAME%.7z" -oboost -y

cd %WORK_DIR%