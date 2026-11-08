#include "wabrix_shared_memory.h"

/*
 * Run C/Rust numeric consistency, C layout checks, and Rust compile-time layout
 * assertions from the SDK root with:
 *
 *   ./abi/check_abi.sh
 *
 * To validate only the C header:
 *
 *   cc -std=c11 -Wall -Wextra -Werror -I abi -fsyntax-only abi/layout_check.c
 */
