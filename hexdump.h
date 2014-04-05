#ifndef HEXDUMP_H__
#define HEXDUMP_H__

#include <stdio.h>
#include <sys/types.h>

int hexdump(FILE *fp, int unitsize, off_t offset, const void *begin, const void *end);

#endif /* HEXDUMP_H__ */
