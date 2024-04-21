# This file is part of the mkcheck project.
# Licensing information can be found in the LICENSE file.
# (C) 2017 Nandor Licker. All rights reserved.

cmake_minimum_required(VERSION 3.5)
project(mkcheck CXX)
include(CTest)

find_package(Boost COMPONENTS system filesystem program_options REQUIRED)


add_executable(mkcheck
    mkcheck/fd.cpp
    mkcheck/mkcheck.cpp
    mkcheck/syscall.cpp
    mkcheck/proc.cpp
    mkcheck/trace.cpp
    mkcheck/util.cpp
)
target_compile_features(mkcheck PUBLIC cxx_std_17)
set_target_properties(mkcheck PROPERTIES CXX_STANDARD_REQUIRED ON)
set_target_properties(mkcheck PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(mkcheck
  ${Boost_LIBRARIES}
)

add_test(NAME make COMMAND make -C ${PROJECT_SOURCE_DIR}/test/make test MKCHECK=$<TARGET_FILE:mkcheck> TOPDIR=${PROJECT_SOURCE_DIR})
add_test(NAME parallel COMMAND make -C ${PROJECT_SOURCE_DIR}/test/parallel test MKCHECK=$<TARGET_FILE:mkcheck> TOPDIR=${PROJECT_SOURCE_DIR})


