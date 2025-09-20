#ifndef VH_VERSION_HPP
#define VH_VERSION_HPP

#define VH_VERSION_MAJOR 0
#define VH_VERSION_MINOR 0
#define VH_VERSION_PATCH 1

#define VH_TO_VERSION(major, minor, patch) \
  ((major) * 10000 + (minor) * 100 + (patch))
#define VH_VERSION                            \
  VH_TO_VERSION(VH_VERSION_MAJOR, \
                            VH_VERSION_MINOR, \
                            VH_VERSION_PATCH)

#endif  // VH_VERSION_HPP