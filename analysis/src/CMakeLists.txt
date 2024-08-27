add_llvm_library( libpetal MODULE
  utility.cpp
  kdfi.cpp
  pta.cpp
  simple_set.cpp
  indcall.cpp
  module_duplicator.cpp
  knobs.cpp
  DEPENDS
  PLUGIN_TOOL
  opt
)

target_compile_features(libpetal PRIVATE cxx_range_for cxx_auto_type)

target_link_libraries( libpetal )
