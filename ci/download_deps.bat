set WORK_DIR=%CD%
set ZLIB_DIST_NAME=zlib-1.2.11-static-mt
set OPENSSL_DIST_NAME=openssl-1.1.1c-x64
set BOOST_DIST_NAME=boost-vc143-1_79_0-bin
set DEPS_DIST_URI=https://s3-us-west-2.amazonaws.com/streamlabs-obs-updater-deps

mkdir "%DEPS_LOCAL_PATH%"
cd "%DEPS_LOCAL_PATH%"

curl -kLO "%DEPS_DIST_URI%/%ZLIB_DIST_NAME%.7z" -f --retry 5
curl -kLO "%DEPS_DIST_URI%/%OPENSSL_DIST_NAME%.7z" -f --retry 5
curl -kLO "%DEPS_DIST_URI%/%BOOST_DIST_NAME%.7z" -f --retry 5

7z x "%ZLIB_DIST_NAME%.7z" -ozlib -y 
7z x "%OPENSSL_DIST_NAME%.7z" -oopenssl -y
7z x "%BOOST_DIST_NAME%.7z" -oboost -y

cd %WORK_DIR%