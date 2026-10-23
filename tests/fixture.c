/* A tiny PE32 DLL with known exports, built with mingw-w64 for dumpPE tests */
__declspec(dllexport) int pe_test_add(int a, int b) { return a + b; }
__declspec(dllexport) int pe_test_sub(int a, int b) { return a - b; }
__declspec(dllexport) int pe_test_mul(int a, int b) { return a * b; }
