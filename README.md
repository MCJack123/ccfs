# ccfs
FUSE filesystem for ComputerCraft using the [CraftOS-PC raw mode protocol](https://www.craftos-pc.cc/docs/rawmode) over WebSockets.

## Compiling
Requires Poco and libfuse, with a C++14 compliant compiler.

`make` should do the trick on Linux systems. Some tweaking may be necessary for some systems (e.g. changing GCC to Clang).

## Usage
Make sure a raw mode server is running on the target computer before using. [CraftOS-PC Remote](https://remote.craftos-pc.cc) hosts a WebSocket pipe server for this purpose, as well as a ready-made server program. An easy way to set this up is to connect with the CraftOS-PC extension for VS Code - this allows one-click & paste activation of the server.

To mount: `./ccfs <URL to WebSocket server> <mount point> [options]`