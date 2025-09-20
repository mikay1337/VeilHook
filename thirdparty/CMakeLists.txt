

include(FetchContent)



FetchContent_Declare(
    Zydis System
    GIT_REPOSITORY "https://github.com/zyantific/zydis"
    GIT_TAG        v4.1.0
)
FetchContent_MakeAvailable(Zydis)