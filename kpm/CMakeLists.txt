cmake_minimum_required(VERSION 3.10)
project(rt_kpm C)
set(CMAKE_C_STANDARD 11)
add_library(rt_kpm SHARED rt_kpm.c)
