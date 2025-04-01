cmake_minimum_required(VERSION 3.6.0)
project(miraclcrypto)

set(JNI_DIR ${CMAKE_SOURCE_DIR}/src/main/jni)
set(CRYPTO_DIR ${JNI_DIR}/crypto)
set(CRYPTO_LIB_DIR ${CRYPTO_DIR}/lib/${ANDROID_ABI})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories(${CRYPTO_DIR}/include)
link_directories(${CRYPTO_DIR}/lib/${ANDROID_ABI}/)

add_library(amcl_core STATIC IMPORTED)
set_target_properties(amcl_core PROPERTIES IMPORTED_LOCATION ${CRYPTO_LIB_DIR}/libamcl_core.a)

add_library(amcl_curve_BN254CX STATIC IMPORTED)
set_target_properties(amcl_curve_BN254CX PROPERTIES IMPORTED_LOCATION ${CRYPTO_LIB_DIR}/libamcl_curve_BN254CX.a)

add_library(amcl_pairing_BN254CX STATIC IMPORTED)
set_target_properties(amcl_pairing_BN254CX PROPERTIES IMPORTED_LOCATION ${CRYPTO_LIB_DIR}/libamcl_pairing_BN254CX.a)

add_library(amcl_mpin_BN254CX STATIC IMPORTED)
set_target_properties(amcl_mpin_BN254CX PROPERTIES IMPORTED_LOCATION ${CRYPTO_LIB_DIR}/libamcl_mpin_BN254CX.a)

add_library(${PROJECT_NAME} SHARED ${CMAKE_SOURCE_DIR}/src/main/cpp/crypto.c)

find_library(log-lib log)
find_library(android android)

target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,-z,max-page-size=16384")

target_link_libraries(${PROJECT_NAME}

        amcl_mpin_BN254CX
        amcl_core
        amcl_curve_BN254CX
        amcl_pairing_BN254CX

        ${android}
        ${log-lib}
        )
