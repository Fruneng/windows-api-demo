cmake_minimum_required(VERSION 3.10)

set(SOURCE
    main.cc
    executor.cc
)

add_executable(demo ${SOURCE})
set_target_properties(
  demo
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
             LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
             ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)


include(CMakeLists.win.txt)

# boost beast(system)
if(WIN32)
  set(Boost_LIB_PREFIX "")
  set(Boost_COMPILER -vc143)
endif()
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.74.0 REQUIRED system thread)
include_directories(${Boost_INCLUDE_DIR})
target_link_libraries(demo Boost::system Boost::thread)

# jsoncpp
find_package(jsoncpp CONFIG REQUIRED)
target_link_libraries(demo JsonCpp::JsonCpp)