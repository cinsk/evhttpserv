#include <stdint.h>
#include <ctype.h>

#include "hexdump.h"


int
hexdump(FILE *fp, int unitsize, off_t offset, const void *begin, const void *end)
{
  const char *address = (const char *)begin;

  int written = 0;
  char linebuf[20];
  char *lineptr;
  int canonical = (unitsize == 1);

  if (unitsize != 1 && unitsize != 2 && unitsize != 4 && unitsize != 8)
    return -1;


  while (address < (char *)end) {
    if (written % 16 == 0) {
      if (offset != (off_t)-1)
        fprintf(fp, "%08lx", (unsigned long)(offset + written));
      else
        fprintf(fp, "%08lx", (unsigned long)address);

      if (canonical) {
        lineptr = linebuf;
        *lineptr++ = '|';
      }
    }

    if (written % 8 == 0)
      fprintf(fp, " ");

    switch (unitsize) {
    case 1:
      {
        unsigned char *p = (unsigned char *)address;
        fprintf(fp, " %0*x", unitsize * 2, *p);
        if (canonical) {
          if (isprint((unsigned char)*p))
            *lineptr++ = *p;
          else
            *lineptr++ = '.';
        }
      }
      break;
    case 2:
      {
        uint16_t *p = (uint16_t *)address;
        fprintf(fp, " %0*hx", unitsize * 2, *p);
      }
      break;
    case 4:
      {
        uint32_t *p = (uint32_t *)address;
        fprintf(fp, " %0*x", unitsize * 2, *p);
      }
      break;
    case 8:
      {
        uint64_t *p = (uint64_t *)address;
        fprintf(fp, " %0*lx", unitsize * 2, (unsigned long)*p);
      }
      break;
    default:
      break;
    }
    address += unitsize;

    if (written % 16 == 16 - unitsize) {
      if (canonical) {
        *lineptr++ = '\0';
        fprintf(fp, " %s|\n", linebuf);
      }
      else
        fprintf(fp, "\n");
    }

    written += unitsize;
  }

  if (written % 16 != 0) {
    if (canonical) {
      *lineptr++ = '\0';
      fprintf(fp, " %*s%s|\n", (16 - (written % 16)) * 3, " ", linebuf);
    }
    else
      fprintf(fp, "\n");
  }
  return written;
}


#ifdef TEST_HEXDUMP
int
main(int argc, char *argv[])
{
  char buf[1024];

  // hexdump(stdout, buf, buf + 1021, 0, 0,
  // HD_OFFSET | HD_CANONICAL | HD_ONEBYTE);
  hexdump(stderr, 1, 0, buf, buf + 1021);
  hexdump(stderr, 2, 0, buf, buf + 1021);
  hexdump(stderr, 4, 0, buf, buf + 1021);
  hexdump(stderr, 8, 0, buf, buf + 1021);

  return 0;
}
#endif  /* TEST_HEXDUMP */
