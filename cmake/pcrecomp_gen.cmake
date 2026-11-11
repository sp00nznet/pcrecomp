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
