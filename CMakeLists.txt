cmake_minimum_required(VERSION 3.14)

project(SimbaDecoder VERSION 1.0)

# Установка стандарта C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Добавление исходных файлов
set(SOURCES
    SimbaDecoder.cpp
    parser.cpp
)

# Создание исполняемого файла
add_executable(simba_decoder ${SOURCES})

# Включение директорий заголовочных файлов
target_include_directories(simba_decoder PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Добавление флагов компиляции
target_compile_options(simba_decoder PRIVATE -Wall -Wextra -Wpedantic)

# Установка цели
install(TARGETS simba_decoder DESTINATION bin)
