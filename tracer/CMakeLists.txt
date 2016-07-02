project(tracer)
cmake_minimum_required(VERSION 2.8)

find_path(PIN_ROOT_DIR
  NAMES source/include/pin/pin.H
  PATHS $ENV{PIN_ROOT_DIR}
  DOC "Pin's root directory"
)

if(PIN_ROOT_DIR)
  message(STATUS "PIN_ROOT_DIR: ${PIN_ROOT_DIR}")
else()
  message(FATAL_ERROR
    "\nPin not found!\n"
  )
endif()

set(PIN_VERSION_SCRIPT ${PIN_ROOT_DIR}/source/include/pin/pintool.ver)

if(DEFINED ARCH)
  if (ARCH STREQUAL "intel64")
    set(PIN_CPU_ARCH "intel64")
    set(PIN_CPU_ARCH_LONG "intel64")
    set(BIONIC_ARCH "x86_64")
  else()
    set(PIN_CPU_ARCH "ia32")
    set(PIN_CPU_ARCH_LONG "ia32")
    set(BIONIC_ARCH "x86")
  endif()
else()
  set(PIN_CPU_ARCH "intel64")
  set(PIN_CPU_ARCH_LONG "intel64")
  set(BIONIC_ARCH "x86_64")
endif()

if (PIN_CPU_ARCH STREQUAL "intel64")
  message(STATUS "64 bit build")
else()
  message(STATUS "32 bit build")
endif()

list(APPEND PIN_DEFS
  __PIN__=1
  PIN_CRT=1
  BIGARRAY_MULTIPLIER=1
  )

if(PIN_CPU_ARCH STREQUAL "intel64")
  list(APPEND PIN_DEFS
    TARGET_IA32E)
else()
  list(APPEND PIN_DEFS
    TARGET_IA32)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
else()
  list(APPEND PIN_DEFS
    TARGET_LINUX)

  if (PIN_CPU_ARCH STREQUAL "intel64")
      list(APPEND PIN_DEFS
        HOST_IA32E)
      set(PIN_COMPILE_FLAGS "-Wall -Wno-unknown-pragmas -fPIC -O3 -fno-stack-protector \
                            -fno-exceptions -funwind-tables -fasynchronous-unwind-tables -fno-strict-aliasing \
                            -fno-rtti -fabi-version=2")
      set(PIN_LINK_FLAGS "")
    else()
      list(APPEND PIN_DEFS
        HOST_IA32)
      set(PIN_COMPILE_FLAGS "-Wall -Wno-unknown-pragmas -fPIC -O3 -fno-stack-protector \
                            -fno-exceptions -funwind-tables -fasynchronous-unwind-tables -fno-strict-aliasing \
                            -fno-rtti -fabi-version=2 -m32")
      set(PIN_LINK_FLAGS "-shared -Wl,--hash-style=sysv ${PIN_ROOT_DIR}/${PIN_CPU_ARCH}/runtime/pincrt/crtbeginS.o \
                          -Wl,-Bsymbolic -Wl,--version-script=${PIN_VERSION_SCRIPT}
                          -fabi-version=2 ${PIN_ROOT_DIR}/${PIN_CPU_ARCH}/runtime/pincrt/crtendS.o")
    endif()
endif()

set(PIN_INCLUDE_DIRS
  ${PIN_ROOT_DIR}/source/include/pin
  ${PIN_ROOT_DIR}/source/include/pin/gen
  ${PIN_ROOT_DIR}/extras/components/include
  ${PIN_ROOT_DIR}/extras/stlport/include
  ${PIN_ROOT_DIR}/extras/libstdc++/include
  ${PIN_ROOT_DIR}/extras/crt/include
  ${PIN_ROOT_DIR}/extras/crt/include/arch-${BIONIC_ARCH}
  ${PIN_ROOT_DIR}/extras/crt/include/kernel/uapi
  ${PIN_ROOT_DIR}/extras/crt/include/kernel/uapi/asm-x86
  ${PIN_ROOT_DIR}/extras/xed-${PIN_CPU_ARCH}/include
  )

set(PIN_LIB_DIRS
  ${PIN_ROOT_DIR}/${PIN_CPU_ARCH}/runtime/pincrt
  ${PIN_ROOT_DIR}/${PIN_CPU_ARCH}/lib
  ${PIN_ROOT_DIR}/${PIN_CPU_ARCH}/lib-ext
  ${PIN_ROOT_DIR}/extras/xed-{PIN_CPU_ARCH}/lib
  )

set(PIN_LINK_LIBS
  pin xed pin3dwarf dl-dynamic stlport-dynamic m-dynamic c-dyamic
  )

set(INCLUDE_DIRS
  ${PIN_INCLUDE_DIRS}
  .
  )

include_directories(${INCLUDE_DIRS})
aux_source_directory(. SRC_LIST)

add_library(${PROJECT_NAME} SHARED ${SRC_LIST})
set_target_properties(${PROJECT_NAME} PROPERTIES
  COMPILE_DEFINITIONS "${PIN_DEFS}"
  COMPILE_FLAGS "${PIN_COMPILE_FLAGS}"
  LINK_FLAGS "${PIN_LINK_FLAGS}"
  )
