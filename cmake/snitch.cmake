
include(FetchContent)
if (TARGET snitch::snitch)
    return()
endif()

include(FetchContent)
FetchContent_Declare(
    snitch
    GIT_REPOSITORY https://github.com/snitch-org/snitch.git
    GIT_TAG        v1.3.2
)   

FetchContent_MakeAvailable(snitch)
