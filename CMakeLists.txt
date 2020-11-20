# cmake

cmake_minimum_required(VERSION 3.12)

project(cjwt)

include(cmake/build.cmake)
add_subdirectory(third-party)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
find_package(LuaJit REQUIRED)
find_package(jansson REQUIRED)

set(CMAKE_SHARED_LIBRARY_PREFIX "")
add_library(${PROJECT_NAME} SHARED)
target_sources(${PROJECT_NAME} PRIVATE cjwt.c)
target_include_directories(${PROJECT_NAME} PRIVATE
  ${LUAJIT_INCLUDE_DIRS}
  )
target_link_libraries(${PROJECT_NAME} PRIVATE
  jwt
  ${LUAJIT_LIBRARIES}
  jansson::jansson
  )
