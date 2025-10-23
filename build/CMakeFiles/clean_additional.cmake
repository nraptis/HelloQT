# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles/hello-qt-tests_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/hello-qt-tests_autogen.dir/ParseCache.txt"
  "CMakeFiles/hello-qt_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/hello-qt_autogen.dir/ParseCache.txt"
  "hello-qt-tests_autogen"
  "hello-qt_autogen"
  )
endif()
