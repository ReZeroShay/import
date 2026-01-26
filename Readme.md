
# fadec
### Target Minimal Configuration
* x86-64 only(**-DFADEC_ARCHMODE=only64**)
* Decoder enabled
* Formatting moudle removed(**format.c** excluded)
* Both encoder disabled

### Required for Compilation/Build
* Python3.9 or newer

executes the `parseinstrs.py` script to generate instruction tables(fadec-*-public.inc and fadec-*-private.inc).

### Using official CMake(Recommended)
1. Get the source code

2. Edit CMakeLists.txt of fadec for minimal size **(option)**

`fadec_component(NAME decode SOURCES decode.c format.c HEADERS fadec.h)`

Change it to remove `format.c`:

`fadec_component(NAME decode SOURCES decode.c HEADERS fadec.h)`

3. Add `add_subdirectory(fadec)` to your CMakeLists.txt

4. Configure and build

```
mkdir build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DFADEC_ARCHMODE=only64 \
  -DFADEC_ENCODE=OFF \
  -DFADEC_ENCODE2=OFF

cmake --build . --config Release
```



### Example usage

```C
#include "fadec.h"
#include <stdio.h>

int main() {
    unsigned char code[] = {0x48, 0x89, 0xE5};  // mov rbp, rsp
    FdInstr instr;
    size_t len = fd_decode(code, sizeof(code), 64, 0, &instr);
    if (len > 0) {
        printf("Instruction length: %zu\n", len);
        printf("Instruction type: %d\n", instr.type);
        // See fadec.h for more fields in FdInstr
    }
    return 0;
}

```

### Notes
* Removing `format.c` means you cannot call `fd_format()`



# bddisasm
### Minimal bddisasm decoder Configuration
* x86-64 only(**-DFADEC_ARCHMODE=only64**)
* Decoder enabled
* Formatting moudle removed
* Both encoder disabled


### Using official CMake(Recommended)
1. Get the source code

3. Add `add_subdirectory(bddisasm)` to your CMakeLists.txt

4. Configure and build

```Bash
mkdir build && cd build
cmake .. \
  -DBDD_INCLUDE_TOOL=OFF \              # 不构建 disasmtool
  -DBDD_INCLUDE_TESTS=OFF \             # 不构建测试
  -DBDD_INCLUDE_FUZZERS=OFF \           # 不构建 fuzzer
  -DBDD_INCLUDE_ISAGENERATOR_X86=OFF \  # 不需要指令表生成器
  -DBDD_NO_MNEMONIC=ON \                # 【关键】排除所有助记符字符串和格式化功能
  -DBDD_LTO=ON \                        # 启用链接时优化，进一步减小体积
  -DCMAKE_BUILD_TYPE=Release            # Release 模式

cmake --build . --config Release
```



### Example usage

```C
#include "fadec.h"
#include <stdio.h>

int main() {
    unsigned char code[] = {0x48, 0x89, 0xE5};  // mov rbp, rsp
    FdInstr instr;
    size_t len = fd_decode(code, sizeof(code), 64, 0, &instr);
    if (len > 0) {
        printf("Instruction length: %zu\n", len);
        printf("Instruction type: %d\n", instr.type);
        // See fadec.h for more fields in FdInstr
    }
    return 0;
}

```

### Notes
* Removing `format.c` means you cannot call `fd_format()`
