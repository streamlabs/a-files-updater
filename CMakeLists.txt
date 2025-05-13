cmake_minimum_required(VERSION 3.17)
cmake_policy(SET CMP0074 NEW)
cmake_policy(SET CMP0076 NEW)

project(slobs-updater)

set(CMAKE_MODULE_PATH
	${CMAKE_MODULE_PATH}
	"${slobs-updater_SOURCE_DIR}/cmake"
)
set(SENTRY_PROJECT_ID "1390326")
set(SENTRY_PROJECT_KEY "7492ebea21f54618a550163938dc164d")

if(DEFINED ENV{RELEASE_VERSION} AND NOT "$ENV{RELEASE_VERSION}" STREQUAL "")
	set(RELEASE_VERSION "$ENV{RELEASE_VERSION}")
	string(REGEX MATCH "([0-9]+)\.([0-9]+)\.([0-9]+)" version_numbers ${RELEASE_VERSION})
	set(RELEASE_VERSION_DOTS "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3}")
	string(APPEND RELEASE_VERSION_DOTS ".0")
	string(REPLACE "." "," RELEASE_VERSION_COMMA "${RELEASE_VERSION_DOTS}")
else()
	set(RELEASE_VERSION "0.0.0-dev")
	set(RELEASE_VERSION_DOTS "0.0.0.0")
	set(RELEASE_VERSION_COMMA "0,0,0,0")
endif()

set(ZLIB_ROOT ${CMAKE_DEPS_DIR}/zlib)
set(OPENSSL_ROOT_DIR ${CMAKE_DEPS_DIR}/openssl)
set(BOOST_ROOT ${CMAKE_DEPS_DIR}/boost)

# set(OPENSSL_USE_STATIC_LIBS TRUE)
# set(OPENSSL_MSVC_STATIC_RT TRUE)
# find_package(OpenSSL REQUIRED )
# message(STATUS "${OPENSSL_LIBRARIES}")
set(OPENSSL_LIBRARIES ${OPENSSL_ROOT_DIR}/lib/libssl.lib ${OPENSSL_ROOT_DIR}/lib/libcrypto.lib)

option(USE_STREAMLABS_RESOURCE "Embed and use the streamlabs resource file in the resulting executable" ON)

include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.hpp
    DOWNLOAD_NO_EXTRACT TRUE
    DOWNLOAD_DIR ${CMAKE_BINARY_DIR}/_deps/nlohmann_json
)
FetchContent_MakeAvailable(nlohmann_json)

find_package(ZLIB REQUIRED)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_STATIC_RUNTIME ON)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME ON)
set(Boost_DEBUG OFF)
set(Boost_RELEASE ON)

find_package(Boost
	1.79.0 EXACT
	REQUIRED
	COMPONENTS
	iostreams
	system
	date_time
	locale
)
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})

include(cppcheck)

cppcheck(EXCLUDE "")

file(GLOB_RECURSE SRC_FILES ${PROJECT_SOURCE_DIR}/src/*.cc ${PROJECT_SOURCE_DIR}/src/*/*.c ${PROJECT_SOURCE_DIR}/src/*/*.cpp)
file(GLOB_RECURSE HEADER_FILES ${PROJECT_SOURCE_DIR}/src/*.h ${PROJECT_SOURCE_DIR}/src/*.hpp)

add_executable(slobs-updater WIN32 ${SRC_FILES} ${HEADER_FILES})

if(USE_STREAMLABS_RESOURCE)
	target_sources(slobs-updater PUBLIC resources/slobs-updater.rc)
endif()

target_compile_options(slobs-updater
	PRIVATE
	$<IF:$<CONFIG:Debug>,-MTd,-MT>
	-W3 -Zi
	-bigobj
)

target_link_options(slobs-updater
	PRIVATE
	/DEBUG
)

set_property(TARGET slobs-updater PROPERTY CXX_STANDARD 17)
set_property(TARGET slobs-updater PROPERTY CXX_STANDARD_REQUIRED ON)

target_include_directories(slobs-updater
	PRIVATE src/argtable
	PRIVATE src/fmt
	PRIVATE ${CMAKE_BINARY_DIR}/_deps/nlohmann_json
	SYSTEM PUBLIC ${OPENSSL_ROOT_DIR}/include
)

target_link_libraries(slobs-updater
	comctl32
	Psapi
	Version
	Boost::boost
	Boost::iostreams
	Boost::locale
	Boost::system
	Boost::date_time
	${OPENSSL_LIBRARIES}
	ZLIB::ZLIB

	# -MANIFESTUAC:level=requireAdministrator
)

# OpenSSL needs us to link against libraries it depends
# on in order to be runtime agnostic
target_link_libraries(slobs-updater Crypt32)

target_compile_definitions(slobs-updater
	PRIVATE
	-D_WIN32_WINNT=0x600
	-DWINVER=0x600
	-DNOMINMAX
	-DWIN32_LEAN_AND_MEAN
	-DUNICODE
	-D_UNICODE
	-DBOOST_IOSTREAMS_NO_LIB
	-DSENTRY_PROJECT_ID="${SENTRY_PROJECT_ID}"
	-DSENTRY_PROJECT_KEY="${SENTRY_PROJECT_KEY}"
	-DRELEASE_VERSION="${RELEASE_VERSION}"

	# It might be worth removing this eventually
	-D_CRT_SECURE_NO_WARNINGS

	# This can be removed with Boost 1.68.0 I believe
	-D_SILENCE_FPOS_SEEKPOS_DEPRECATION_WARNING
	-D_SILENCE_CXX17_ALLOCATOR_VOID_DEPRECATION_WARNING
)

configure_file("${slobs-updater_SOURCE_DIR}/resources/slobs-updater.exe.in" "${slobs-updater_SOURCE_DIR}/resources/slobs-updater.exe.manifest" @ONLY)
configure_file("${slobs-updater_SOURCE_DIR}/resources/slobs-updater.rc.in" "${slobs-updater_SOURCE_DIR}/resources/slobs-updater.rc" @ONLY)

include(FetchContent)

# Compare current linked libs with prev
FetchContent_Declare(deps_checker URL "https://raw.githubusercontent.com/stream-labs/obs-studio-node/staging/dependency_checker/check_dependencies.cmd" DOWNLOAD_NO_EXTRACT true)
FetchContent_MakeAvailable(deps_checker)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${deps_checker_SOURCE_DIR}/check_dependencies.cmd $<TARGET_FILE:slobs-updater> ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR} $<CONFIG>)

find_program(WIN_MT "mt.exe")

if(NOT WIN_MT)
	message(FATAL_ERROR "Failed to find mt.exe to embed manifest")
endif()

cppcheck_add_project(slobs-updater)

add_custom_command(
	TARGET slobs-updater
	POST_BUILD
	COMMAND
	"${WIN_MT}"
	-manifest "${slobs-updater_SOURCE_DIR}/resources/slobs-updater.exe.manifest"
	-outputresource:"$<TARGET_FILE:slobs-updater>"
)

# Install
install(FILES $<TARGET_PDB_FILE:slobs-updater> DESTINATION ${CMAKE_INSTALL_PREFIX} OPTIONAL)

install(FILES $<TARGET_FILE:slobs-updater> DESTINATION ${CMAKE_INSTALL_PREFIX})
