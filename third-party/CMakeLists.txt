# third-party cmake

find_package(Git REQUIRED)

execute_process(COMMAND ${GIT_EXECUTABLE} submodule init)
execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --recursive)

set(JANSSON_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(JANSSON_INSTALL_DIR ${CMAKE_BINARY_DIR})
execute_process(
  COMMAND ${CMAKE_COMMAND} -DJANSSON_BUILD_DOCS=OFF -DCMAKE_INSTALL_PREFIX=${JANSSON_INSTALL_DIR} ${CMAKE_CURRENT_LIST_DIR}/jansson
  WORKING_DIRECTORY ${JANSSON_BUILD_DIR}
  )
execute_process(
  COMMAND ${CMAKE_COMMAND} --build . --target install
  WORKING_DIRECTORY ${JANSSON_BUILD_DIR}
  )


list(APPEND CMAKE_PREFIX_PATH ${JANSSON_INSTALL_DIR})
option(BUILD_SHARED_LIBS OFF)
set(CMAKE_C_FLAGS "-fPIC")
add_subdirectory(libjwt)
