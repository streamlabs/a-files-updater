REM download gettext tools from https://mlocati.github.io/articles/gettext-iconv-windows.html

set GETTEXT_URL=https://github.com/mlocati/gettext-iconv-windows/releases/download/v0.21-v1.16/gettext0.21-iconv1.16-static-64.zip
set GETTEXT_DIR=gettext_dist
if not exist build mkdir build
cd build

if exist %GETTEXT_DIR%\ (
    echo "get text tools already installed"
) else (
    curl -kLO %GETTEXT_URL% -f --retry 5 -C -
    7z x gettext0.21-iconv1.16-static-64.zip -aoa -o%GETTEXT_DIR%
)

cd ..

set locales_list="ar_SA","cs_CZ","da_DK","de_DE","en_US","es_ES","fr_FR","hu_HU","id_ID","it_IT","ja_JP","ko_KR","mk_MK","nl_NL","pl_PL","pt_BR","pt_PT","ru_RU","sk_SK","sl_SI","sv_SE","th_TH","tr_TR","vi_VN","zh_CN","zh_TW"
set GETTEXT_BIN=build\%GETTEXT_DIR%\bin\
