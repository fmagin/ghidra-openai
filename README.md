# Ghidra Extension in Kotlin using IntelliJ IDEA

> Write a Ghidra Extension without using Java or Eclipse!

## Setup

* Hit `Use this template` at the top of the repo on GitHub
* Clone the new repo to your development machine
* Add the line `GHIDRA_INSTALL_DIR=/path/to/your/ghidra_10.1_PUBLIC/` to `$HOME/.gradle/gradle.properties`
* Open IntelliJ, create a new `Project from Existing Sources...` and select the `build.gradle`
  * If you are using the [Kotlin Jupyter Plugin](https://github.com/GhidraJupyter/ghidra-jupyter-kotlin) uncomment the line in the `dependencies` block in the `build.gradle`
* Wait for IntelliJ to finish indexing and fetching dependencies, hit the build button, and then run Ghidra


## Features

* Gradle Config that works out of the box with IntelliJ
* IntelliJ IDEA Run Configuration for debugging of the extension
  * If you have are using the [Kotlin Jupyter Plugin](https://github.com/GhidraJupyter/ghidra-jupyter-kotlin) you can also set breakpoints in the script file!
* GitHub CI files that
  * make sure the extension at least builds for each PR
  * will automatically build a release and publish it on GitHub if a commit is tagged with a version matching `vX.X.X`, e.g. `v1.2.3`/`v1.2.0` (`v1.2` doesn't work!)
  

## Additional Development Tips

These aspects can not be included in the repo files itself, but make development smoother.

### Thread Breakpoints

Make sure that you use breakpoints that only suspend the thread, and not everything.
This means that the breakpoint will only suspend the thread that is currently running the analysis or the script,
and the GUI will keep working.
  * Set a breakpoint, right-click the icon, and in the `Suspend` line select `Thread` instead of `All`
  * IntelliJ IDEA will suggest making this the default, click this too


### Use Scripts and the Jupyter Kernel to prototype ideas

With the [Kotlin Jupyter Plugin](https://github.com/GhidraJupyter/ghidra-jupyter-kotlin) you can test your new ideas first.
IntelliJ IDEA can do hot reloading of classes, but this has limits and then still requires a Ghidra restart,
which takes an annoying amount of time. The QT Console is fairly basic, but the Jupyter Notebook uses nearly the same
code analysis engine as IntelliJ itself.

### Automatic conversion to Kotlin

* pasting Java code into a Kotlin file you will get the suggestion for this to be converted and then pasted
* right-click `.java` file in the Project Tree there is an action at the very bottom to convert the entire file


## Issues

If any step in this process doesn't work as described in the README, please open an issue on GitHub.
I have only tested this on Linux so there might be some aspects that work differently on macOS or Windows, though these
should be minor.


### Known issues

#### Ghidra looks even worse than usual when run via IDE

The run configuration only includes the class loader VM option, and none of the others that are usually set by the
Ghidra launch script, which include OpenGL settings and Font Anti Aliasing, because this depends on the OS.

Generate the VM options for your system:
```sh
cd $GHIDRA_INSTALL_DIR
java -cp ./support/LaunchSupport.jar LaunchSupport ./support/.. -vmargs
```

and then [edit the run configuration](https://www.jetbrains.com/help/idea/run-debug-configuration.html) and add them.
