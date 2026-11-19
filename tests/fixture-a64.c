/* Tiny AArch64 Windows PE with no libc, used by tests/relocs.sh.
 * The .data section holds pointers (to data and to functions), so the linker
 * emits IMAGE_REL_BASED_DIR64 base relocations for them. */
int value_a = 1;
int value_b = 2;
int value_c = 3;

static int add2(int a, int b) { return a + b; }

int *ptr_a = &value_a;                  /* DIR64 */
int *ptr_b = &value_b;                  /* DIR64 */
int *table[3] = { &value_a, &value_b, &value_c }; /* three DIR64 */
int (*fn_add)(int, int) = add2;         /* DIR64 */

int mainCRTStartup(void)
{
    return *ptr_a + *ptr_b + *table[2] + fn_add(0, 0);
}
