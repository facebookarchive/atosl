# atosl

__atosl__ is a partial replacement for Apple's atos tool for converting
addresses within a binary file to symbols.

## Why

The primary benefit of atosl is its ability to run on other platforms.
atosl has been tested on Linux but will likely run on any platform that
libdwarf is available for.

## Requirements

[libdwarf](https://aur.archlinux.org/packages/libdwarf/) - This library
does the heavily lifting of parsing the DWARF debugging data within the
binaries.

### Install Dependencies on OS X

#### Install Homebrew

```sh
ruby -e "$(curl -fsSL https://raw.github.com/mxcl/homebrew/go)"
```

#### Install Dependencies

```sh
brew install binutils
brew install https://gist.github.com/zlandau/7550479/raw/f72753f6a59f6a3fadf9a2e2952a9f6846c15a8d/libdwarf.rb
```

#### Update config.mk.local

```sh
echo "LDFLAGS += -L$(dirname $(brew list binutils| grep libiberty.a))" >> config.mk.local
```

## Usage

atosl currently supports debug (DSYM) files and DYLIB with debug symbols

```
$ atosl -o SomeApp.app.dSYM/Contents/Resources/DWARF/SomeApp --load-address 0x3c00 0x12345 0x55555
-[AwesomenessContainer parseAwesomeness:error:] (in SomeApp) (AwesomenessContainer.m:400)
-[LamenessEliminator destroyLameness] (in SomeApp) (LamenessEliminator.m:204)
```

Note that there are two methods of symbol lookup. The default method
looks through the DWARF complication units. If you use the --globals
option it instead reads from the .debug_pubnames section. You should try
both options to see which one you find most reliable and fastest.

## Limitations and differences

* Doesn't display function parameters in the symbols
  * This could be added, it just wasn't deemed worth the cycles
* Only supports ARM

## Future Work

* Speed improvements
  * Some of the libdwarf routines are implemented without too much concern for
    performance.
* Add support for more architectures
  * There's nothing particularly architecture-specific other than having to map
    between an architecture name and its identifier so we can find them in the
    Mach binary
* Caching, caching, caching
* Reduce cases were atosl output differs from atos (for whatever reason)
* Port to a version of libdwarf that is still supported

## License

BSD License

For atosl software

Copyright (c) 2013, Facebook, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

 * Neither the name Facebook nor the names of its contributors may be used to
   endorse or promote products derived from this software without specific
   prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
