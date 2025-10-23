cmake_minimum_required(VERSION 3.16)
project(hello_qt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

add_executable(hello-qt src/main.cpp)
target_link_libraries(hello-qt PRIVATE Qt6::Widgets)



# -------------- tests --------------
enable_testing()
find_package(Qt6 REQUIRED COMPONENTS Test) # Qt5? use Qt5 instead

add_executable(hello-qt-tests
    tests/test_example.cpp
    tests/test_example.h
)
target_link_libraries(hello-qt-tests PRIVATE Qt6::Test)

# register with CTest
add_test(NAME hello-qt-tests COMMAND hello-qt-tests)
