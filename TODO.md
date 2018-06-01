# TODO left for this branch
 * Test and ensure releases are displayed correctl (displaying the tag version number, etc)



# Final PR commit msg:

Adds the build info to the binary at buildtime via buildtime variables. This is shown by `./glauth --version`.

Example output:
```
GLauth
Non-release build from branch feature/buildversion

Build time: 20180531_181011Z
Commit: 07ba631c2fd0050f375655ad7c44f862e0e6640c
```



Also includes some minor repo cleanups like Makefile optimization
