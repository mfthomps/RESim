
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>

#define ET_EXEC 2
#define EM_386  3
#define EV_CURRENT 1
#define CI_NIDENT 16

typedef struct _CGC32_hdr {
   uint8_t	e_ident[CI_NIDENT];
#define CI_IDENT	"\177CGC\x01\x01\x01\x43\x01"
   /* ELF vs CGC identification 
   * ELF          CGC
   *  0x7f        0x7f
   *  'E'         'C'
   *  'L'         'G'
   *  'F'         'C'
   *  class       1       : '1' translates to 32bit ELF
   *  data        1       : '1' translates to little endian ELF
   *  version     1       : '1' translates to little endian ELF
   *  osabi       \x43    : '1' CGC OS
   *  abiversion  1       : '1' translates to version 1
   *  padding     random values
   */
   uint16_t	e_type;         /* Must be 2 for executable */
   uint16_t	e_machine;      /* Must be 3 for i386 */
   uint32_t	e_version;      /* Must be 1 */
   uint32_t	e_entry;        /* Virtual address entry point */
   uint32_t	e_phoff;        /* Program Header offset */
   uint32_t	e_shoff;        /* Section Header offset */
   uint32_t	e_flags;        /* Must be 0 */
   uint16_t	e_ehsize;       /* CGC header's size */
   uint16_t	e_phentsize;    /* Program header entry size */
   uint16_t	e_phnum;        /* # program header entries */
   uint16_t	e_shentsize;    /* Section header entry size */
   uint16_t	e_shnum;        /* # section header entries */
   uint16_t	e_shstrndx;     /* sect header # of str table */
} CGC32_hdr;

/* The CGC Executable Program Header */
typedef struct _CGC32_Phdr {
   uint32_t        p_type;         /* Section type */
#define PT_NULL     0               /* Unused header */
#define PT_LOAD     1               /* Segment loaded into mem */
#define PT_PHDR     6               /* Program hdr tbl itself */
#define PT_GNU_STACK (0x60000000 + 0x474e551)
#define PT_CGCPOV2  0x6ccccccc      /* CFE Type 2 PoV flag sect */
   uint32_t        p_offset;       /* Offset into the file */
   uint32_t        p_vaddr;        /* Virtual program address */
   uint32_t        p_paddr;        /* Set to zero */
   uint32_t        p_filesz;       /* Section bytes in file */
   uint32_t        p_memsz;        /* Section bytes in memory */
   uint32_t        p_flags;        /* section flags */
#define PF_X        (1<<0)          /* Mapped executable */
#define PF_W        (1<<1)          /* Mapped writable */
#define PF_R        (1<<2)          /* Mapped readable */
   /* Acceptable flag combinations are:
   *        PF_R
   *        PF_R|PF_W
   *        PF_R|PF_X
   *        PF_R|PF_W|PF_X
   */
   uint32_t        p_align;        /* Only used by core dumps */
} CGC32_Phdr;

static int isCGCExec(const char *abs) {
   struct stat sbuf;
   int valid = 0;
   //if (stat(abs, &sbuf) == 0 && sbuf.st_mode > 0 && (sbuf.st_mode & S_IXUSR) != 0) {
   if (stat(abs, &sbuf) == 0){ 
      //now verify that it's actually a CGC binary
      FILE *f = fopen(abs, "rb");
      while (f != NULL) {
         CGC32_hdr hdr;
         if (fread(&hdr, sizeof(CGC32_hdr), 1, f) != 1 || 
               memcmp(hdr.e_ident, "\x7f" "CGC" "\x01\x01\x01\x43\x01", 9) != 0) {
            break;
         }
         if (hdr.e_ehsize != sizeof(CGC32_hdr)) {
            break;
         }
         if (hdr.e_type != ET_EXEC) {
            break;
         }
         if (hdr.e_machine != EM_386) {
            break;
         }
         if (hdr.e_version != EV_CURRENT) {
            break;
         }
         if (hdr.e_flags != 0) {
            break;
         }
         if (hdr.e_phnum == 0) {
            break;
         }
         if (hdr.e_phentsize != sizeof(CGC32_Phdr)) {
            break;
         }
         if (fseek(f, hdr.e_phoff, SEEK_SET) != 0) {
            break;
         }
         int i;
         for (i = 0; i < hdr.e_phnum; i++) {
            CGC32_Phdr ph;
            if (fread(&ph, sizeof(CGC32_Phdr), 1, f) != 1) {
               break;
            }
            if (ph.p_type == PT_NULL || ph.p_type == PT_LOAD ||
                ph.p_type == PT_PHDR || ph.p_type == PT_CGCPOV2) {
               continue;
            }
            else if (ph.p_type == PT_GNU_STACK) {
               //PT_GNU_STACK program header was detected. These will be considered invalid prior to CQE.
               continue;
            }
            else {
               //Invalid program header. These will be considered invalid prior to CQE
               continue;
            }
         }            
         valid = i == hdr.e_phnum;
      }
      if (f != NULL) {
         fclose(f);
      }
   }
   return valid;
}

int main(int argc, char **argv) {
   if (argc != 3) {
      fprintf(stderr, "usage: unstack <infile> <outfile>\n");
      exit(1);
   }
   FILE *f = fopen(argv[1], "rb");
   if (f == NULL) {
      fprintf(stderr, "Failed to open input file %s\n", argv[1]);
      exit(1);
   }
   if (!isCGCExec(argv[1])) {
      fprintf(stderr, "%s does not appear to be a valid CGC binary\n", argv[1]);
      exit(1);
   }
   CGC32_hdr e;
   if (fread(&e, sizeof(e), 1, f) != 1) {
      fprintf(stderr, "read fail for CGC header\n");
      exit(1);
   }
   CGC32_Phdr *p = ( CGC32_Phdr *) malloc(e.e_phnum * e.e_phentsize);
   if (fseek(f, e.e_phoff, SEEK_SET) != 0) {
      fprintf(stderr, "seek fail for phdr\n");
      exit(1);
   }
   if (fread(p, sizeof(*p), e.e_phnum, f) != e.e_phnum) {
      fprintf(stderr, "phdr read fail\n");
      exit(1);
   }
   fclose(f);
   int i;
   int count = 0;
   for (i = 0; i < e.e_phnum; i++) {
      if (p[i].p_type == PT_GNU_STACK) {
         if (count == 0) {
            char *cmd;
            asprintf(&cmd, "cp %s %s", argv[1], argv[2]);
            if (system(cmd) != 0) {
               fprintf(stderr, "Unable to copy input file\n");
               exit(1);
            }
            free(cmd);
            count++;
         }
         int fo = open(argv[2], O_WRONLY);
         if (fo < 0) {
            fprintf(stderr, "Failed to open output file for writing: %s\n", argv[2]);
            exit(1);
         }
         memcpy(p + i, p + i + 1, sizeof(CGC32_Phdr) * (e.e_phnum - (i + 1)));
         lseek(fo, e.e_phoff, SEEK_SET);
         write(fo, p, sizeof(*p) * e.e_phnum - 1); 
         lseek(fo, 0, SEEK_SET);
         e.e_phnum--;
         write(fo, &e, sizeof(e));
         close(fo); 
      }
   }
   if (count == 0) {
      fprintf(stderr, "Input file (%s) does not appear to contain a PT_GNU_STACK header\n", argv[1]);
   }

}


