#include "wabrix_shared_memory.h"

/*
 * Compile this translation unit with a C11 compiler to validate the public
 * shared-memory header independently of the Rust crate:
 *
 *   cc -std=c11 -Wall -Wextra -Werror -I abi -c abi/layout_check.c
 */
