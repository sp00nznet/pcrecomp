# pcrecomp_gen_sources(<target> [DIR <dir>] [OPTIONS <opt>...])
#
# Adds the generated C under <dir> (default src/recomp/gen) to <target> and
# compiles it unoptimised: /Od (MSVC, clang-cl) or -O0 (gcc, clang), with
# warnings off. The host and runtime keep the build type's flags. Optimising
# the huge recomp_*.c files is most of a build (Shogo: ~25 min at /O2 against
# ~1 min at /Od) and buys little, since the lifted code is register-global
# heavy. -DPCRECOMP_GEN_OPT=ON compiles them with the build type's flags
# instead. OPTIONS are added to the generated files only. The list of files is
# left in PCRECOMP_GEN_SOURCES.
#
#   include(${PCRECOMP}/cmake/pcrecomp_gen.cmake)
#   pcrecomp_gen_sources(mygame)
option(PCRECOMP_GEN_OPT "optimise the generated C (slow to compile)" OFF)

function(pcrecomp_gen_sources target)
  cmake_parse_arguments(G "" "DIR" "OPTIONS" ${ARGN})
  if(NOT G_DIR)
    set(G_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/recomp/gen")
  endif()
  file(GLOB_RECURSE srcs CONFIGURE_DEPENDS "${G_DIR}/*.c")
  list(FILTER srcs EXCLUDE REGEX "/recomp_part\\.c$")   # a part DLL's table (pcrecomp_gen_parts)
  if(NOT srcs)
    message(FATAL_ERROR "${G_DIR} has no generated C -- run the lift first")
  endif()
  if(MSVC)
    set(opts /w)
    if(NOT PCRECOMP_GEN_OPT)
      list(APPEND opts /Od)   # /Od overrides the build type's /O2 (D9025 is expected)
    endif()
  else()
    set(opts -w)
    if(NOT PCRECOMP_GEN_OPT)
      list(APPEND opts -O0)
    endif()
  endif()
  list(APPEND opts ${G_OPTIONS})
  target_sources(${target} PRIVATE ${srcs})
  set_source_files_properties(${srcs} PROPERTIES COMPILE_OPTIONS "${opts}")
  set(PCRECOMP_GEN_SOURCES "${srcs}" PARENT_SCOPE)
  list(LENGTH srcs n)
  message(STATUS "pcrecomp: ${target}: ${n} generated sources, options ${opts}")
endfunction()

# pcrecomp_gen_parts(<exe target> [DIR <dir>] [BASE <addr>] [OPTIONS <opt>...])
#
# The same generated C, but each module's directory under <dir> (one per
# lifted image, with drive32's recomp_part.c) becomes its own DLL,
# <target>_<module>.dll, next to the exe. The exe keeps the runtime and an
# empty main table; native32 loads the parts on its first lookup
# (RECOMP_PARTS) and searches their tables. One image of a large lift
# (Windows 98's shell: ~450 MB) fails CreateProcess; parts load where the
# address space has room. The parts import the exe's globals (RECOMP_PART:
# recomp_types.h's RECOMP_HOSTDATA), so the exe exports all its symbols.
# Direct calls stay inside a module; calls between modules go through the
# dispatch, as they do in one image. <target>_parts builds the exe and all.
function(pcrecomp_gen_parts target)
  cmake_parse_arguments(G "" "DIR;BASE" "OPTIONS" ${ARGN})
  if(NOT G_DIR)
    set(G_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/recomp/gen")
  endif()
  if(MSVC)
    set(opts /w)
    if(NOT PCRECOMP_GEN_OPT)
      list(APPEND opts /Od)
    endif()
  else()
    set(opts -w -O0)
  endif()
  list(APPEND opts ${G_OPTIONS})
  set_target_properties(${target} PROPERTIES ENABLE_EXPORTS ON WINDOWS_EXPORT_ALL_SYMBOLS ON)
  set(empty "${CMAKE_CURRENT_BINARY_DIR}/${target}_parts.c")
  file(WRITE "${empty}" "/* pcrecomp_gen_parts: the tables are the parts' own */\n#include \"recomp_types.h\"\nconst recomp_dispatch_entry_t recomp_dispatch_table[1];\nconst uint32_t recomp_dispatch_count = 0;\n")
  target_sources(${target} PRIVATE "${empty}")
  file(GLOB parts CONFIGURE_DEPENDS "${G_DIR}/*/recomp_part.c")
  get_target_property(incs ${target} INCLUDE_DIRECTORIES)
  get_target_property(defs ${target} COMPILE_DEFINITIONS)
  set(names "")
  foreach(p ${parts})
    get_filename_component(d "${p}" DIRECTORY)
    get_filename_component(m "${d}" NAME)
    file(GLOB srcs CONFIGURE_DEPENDS "${d}/*.c")
    set(lib ${target}_${m})
    add_library(${lib} SHARED ${srcs})
    set_source_files_properties(${srcs} PROPERTIES COMPILE_OPTIONS "${opts}")
    target_include_directories(${lib} PRIVATE ${G_DIR} ${incs})
    target_compile_definitions(${lib} PRIVATE ${defs} RECOMP_PART)
    target_link_libraries(${lib} PRIVATE ${target})
    set_target_properties(${lib} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:${target}>")
    if(G_BASE AND MSVC)
      # BASE: the parts' preferred bases, one after another from there, each as
      # big as its C (the /Od image comes out a little smaller). ASLR would put
      # them where the guest's own images want to load (Win98's shdocvw wants
      # 0x77C60000, just where 32-bit DLLs land).
      target_link_options(${lib} PRIVATE /BASE:${G_BASE} /DYNAMICBASE:NO /FIXED:NO /LARGEADDRESSAWARE)
      set(bytes 0)
      foreach(f ${srcs})
        file(SIZE "${f}" sz)
        math(EXPR bytes "${bytes} + ${sz}")
      endforeach()
      math(EXPR G_BASE "((${G_BASE} + ${bytes} + 0x1000000) | 0xFFFFF) + 1" OUTPUT_FORMAT HEXADECIMAL)
    endif()
    list(APPEND names "${lib}.dll")
    list(APPEND libs ${lib})
  endforeach()
  add_custom_target(${target}_parts DEPENDS ${target} ${libs})
  list(JOIN names "," joined)
  target_compile_definitions(${target} PRIVATE "RECOMP_PARTS=\"${joined}\"")
  list(LENGTH parts n)
  message(STATUS "pcrecomp: ${target}: ${n} part DLLs, options ${opts}")
endfunction()
