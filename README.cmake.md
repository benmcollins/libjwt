Build Instructions for CMake
============================

1. Generate build tree.

        mkdir out
        cd out
        cmake -G "Ninja" -DBUILD_TESTS=1 ..

    NOTE: If you prefer, substitute "Unix Makefiles" or other cmake build generator.

2. Build all.

        ninja

    NOTE: If using different build tool, `cmake --build .` will work.

3. Run tests.

        ninja check

    NOTE: If using different build tool, `cmake --build . --target check` will work.

