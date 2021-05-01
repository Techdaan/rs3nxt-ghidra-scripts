# rs3nxt-ghidra-scripts
Ghidra scripts to help reverse-engineer RS3's NXT client. Currently one huge messy file that performs a few simple operations such as creating/setting up a few data structures, and finding some methods in the binary.

This has only been tested on win64 binaries. MacOS and Linux binaries will not work due to different calling conventions.

# Extending the script
Fork and PR away! Please open-source all your changes to comply with the license, and to contribute to the scene.

# Usage
Simply copy the contents of the files from `/src/main/java/...` into Ghidra's script editor. They should work standalone. 