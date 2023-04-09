// stolen from https://github.com/okirch/pcr-oracle/
// https://github.com/hfiref0x/AuthHashCalc is also useful
/*
 *   Copyright (C) 2022, 2023 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Olaf Kirch <okir@suse.com>
 *
 * This file contains functions to build the Authenticode digest
 * of a PECOFF executable. The defails are described in
 * "Windows Authenticode Portable Executable Signature Format"
 * (sorry, you need to google for this).
 *
 * Information on the layout of PECOFF files, consult
 * https://docs.microsoft.com/windows/win32/debug/pe-format
 *
 * Another good resource is the pesign package, which has code
 * to do this as well.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <assert.h>

//#define DEBUG

#ifdef DEBUG
#define DEBUG_AUTHENTICODE
#endif

#define EFI_TCG2_BOOT_HASH_ALG_SHA1 0x00000001
#define EFI_TCG2_BOOT_HASH_ALG_SHA256 0x00000002
#define EFI_TCG2_BOOT_HASH_ALG_SHA384 0x00000004
#define EFI_TCG2_BOOT_HASH_ALG_SHA512 0x00000008
#define EFI_TCG2_BOOT_HASH_ALG_SM3_256 0x00000010

#define MSDOS_STUB_PE_OFFSET  0x3c

#define PECOFF_IMAGE_FILE_MACHINE_AMD64   0x8664

#define PECOFF_HEADER_LENGTH        20
#define PECOFF_HEADER_MACHINE_OFFSET      0x0000
#define PECOFF_HEADER_NUMBER_OF_SECTIONS_OFFSET   0x0002
#define PECOFF_HEADER_SYMTAB_POS_OFFSET     0x0008
#define PECOFF_HEADER_SYMTAB_CNT_OFFSET     0x000c
#define PECOFF_HEADER_OPTIONAL_HDR_SIZE_OFFSET    0x0010

#define PECOFF_OPTIONAL_HDR_MAGIC_OFFSET    0x0000
#define PECOFF_OPTIONAL_HDR_SIZEOFHEADERS_OFFSET  0x003c
#define PECOFF_OPTIONAL_HDR_CHECKSUM_OFFSET   0x0040

#define PECOFF_FORMAT_PE32        0x10b
#define PECOFF_FORMAT_PE32_PLUS       0x20b
#define PECOFF_DATA_DIRECTORY_CERTTBL_INDEX   4


typedef struct pecoff_image_info pecoff_image_info_t;
typedef struct tpm_algo_info  tpm_algo_info_t;
typedef struct buffer   buffer_t;
typedef struct tpm_evdigest tpm_evdigest_t;
typedef struct digest_ctx digest_ctx_t;

struct buffer {
  /* we make these size_t's to be compatible with the TSS2 marshal/unmarshal api */
  size_t      rpos;
  size_t      wpos;
  size_t      size;
  unsigned char *   data;
};

struct tpm_algo_info {
  unsigned int    tcg_id;
  const char *    openssl_name;
  int    digest_size;
};

struct tpm_evdigest {
  const tpm_algo_info_t * algo;
  unsigned int    size;
  unsigned char   data[EVP_MAX_MD_SIZE];
};

struct digest_ctx {
  EVP_MD_CTX *  mdctx;
  tpm_evdigest_t  md;
};

enum {
  __TPM2_ALG_sha1 = 4,
  __TPM2_ALG_sha256 = 11,
  __TPM2_ALG_sha384 = 12,
  __TPM2_ALG_sha512 = 13,

  TPM2_ALG_MAX
};

#define DESCRIBE_ALGO(name, size) \
  __DESCRIBE_ALGO(name, __TPM2_ALG_ ## name, size)
#define __DESCRIBE_ALGO(name, id, size) \
  [id]  = { id,   #name,    size }
static tpm_algo_info_t    tpm_algorithms[TPM2_ALG_MAX] = {
  DESCRIBE_ALGO(sha1,   20),
  DESCRIBE_ALGO(sha256,   32),
  DESCRIBE_ALGO(sha384,   48),
  DESCRIBE_ALGO(sha512,   64),
};


// ------------------------------------------------------------------


#ifdef DEBUG
static inline void
debug_impl(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "::: ");
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}
#endif

static inline void
error(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "Error: ");
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

static inline void
fatal(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "Fatal: ");
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  exit(2);
}


// ------------------------------------------------------------------


#ifdef DEBUG_AUTHENTICODE
# define debug(args ...) \
  do { \
    debug_impl(args); \
  } while (0)
# define pe_debug(args ...) \
  do { \
    debug_impl(args); \
  } while (0)
#else
# define debug(args ...) \
  do { } while (0)
# define pe_debug(args ...) \
  do { } while (0)
#endif

typedef struct pecoff_placement {
  uint32_t  addr;
  uint32_t  size;
} pecoff_placement_t;

typedef pecoff_placement_t  pecoff_image_datadir_t;

typedef struct pecoff_section {
  char      name[8];

  /* virtual addr of section */
  pecoff_placement_t  virtual;

  /* position within file */
  pecoff_placement_t  raw;
} pecoff_section_t;

#define PECOFF_MAX_HOLES  10
#define PECOFF_MAX_AREAS  64

typedef struct authenticode_image_info {
  /* authenticated range of file */
  pecoff_placement_t  auth_range;

  unsigned int    hashed_bytes;

  unsigned int    num_holes;
  pecoff_placement_t  hole[PECOFF_MAX_HOLES];

  unsigned int    num_areas;
  pecoff_placement_t  area[PECOFF_MAX_AREAS];
} authenticode_image_info_t;

struct pecoff_image_info {
  char *      display_name;
  buffer_t *    data;

  struct {
    uint32_t  offset;
    uint16_t  machine_id;
    uint16_t  num_sections;
    uint32_t  symtab_offset;
    uint16_t  optional_hdr_size;
    uint32_t  optional_hdr_offset;

    uint32_t  section_table_offset;
  } pe_hdr;

  struct {
    uint32_t  size_of_headers;
    uint32_t  data_dir_count;
  } pe_optional_header;

  unsigned int    format;

  unsigned int    num_data_dirs;
  pecoff_image_datadir_t *data_dirs;

  unsigned int    num_sections;
  pecoff_section_t *  section;

  authenticode_image_info_t auth_info;
};


// ------------------------------------------------------------------


static inline void
buffer_init_read(buffer_t *bp, void *data, unsigned int len)
{
  bp->data = (unsigned char *) data;
  bp->rpos = 0;
  bp->wpos = len;
  bp->size = len;
}

static inline void
buffer_init_write(buffer_t *bp, void *data, unsigned int len)
{
  bp->data = (unsigned char *) data;
  bp->rpos = 0;
  bp->wpos = 0;
  bp->size = len;
}

static inline buffer_t *
buffer_alloc_write(unsigned long size)
{
  buffer_t *bp;

  size = (size + 7) & ~7UL;
  bp = malloc(sizeof(*bp) + size);
  buffer_init_write(bp, (void *) (bp + 1), size);

  return bp;
}

static inline bool
buffer_get_buffer(buffer_t *bp, unsigned int count, buffer_t *res)
{
  if (count > bp->wpos - bp->rpos)
    return false;

  buffer_init_read(res, bp->data + bp->rpos, count);
  bp->rpos += count;
  return true;
}

static inline buffer_t *
buffer_read_file(const char *filename)
{
  bool closeit = true;
  buffer_t *bp;
  struct stat stb;
  int count;
  int fd;

  if (filename == NULL || !strcmp(filename, "-")) {
    closeit = false;
    fd = 0;
  } else
  if ((fd = open(filename, O_RDONLY)) < 0) {
    fatal("Unable to open file %s: %m\n", filename);
  }

  if (fstat(fd, &stb) < 0)
    fatal("Cannot stat %s: %m\n", filename);

  bp = buffer_alloc_write(stb.st_size);
  if (bp == NULL)
    fatal("Cannot allocate buffer of %lu bytes for %s: %m\n",
        (unsigned long) stb.st_size,
        filename);

  count = read(fd, bp->data, stb.st_size);
  if (count < 0)
    fatal("Error while reading from %s: %m\n", filename);

  if (count != stb.st_size) {
    fatal("Short read from %s\n", filename);
  }

  if (closeit)
    close(fd);

  debug("Read %u bytes from %s\n", count, filename);
  bp->wpos = count;
  return bp;
}

static inline void
buffer_free(buffer_t *bp)
{
  free(bp);
}

static inline unsigned int
buffer_available(const buffer_t *bp)
{
  return bp->wpos - bp->rpos;
}

static inline const void *
buffer_read_pointer(const buffer_t *bp)
{
  return bp->data + bp->rpos;
}

static inline bool
buffer_seek_read(buffer_t *bp, unsigned int new_pos)
{
  if (new_pos > bp->wpos)
    return false;

  bp->rpos = new_pos;
  return true;
}

static inline bool
buffer_get(buffer_t *bp, void *dest, unsigned int count)
{
  if (count > bp->wpos - bp->rpos)
    return false;

  memcpy(dest, bp->data + bp->rpos, count);
  bp->rpos += count;
  return true;
}

static inline bool
buffer_get_u16le(buffer_t *bp, uint16_t *vp)
{
  if (!buffer_get(bp, vp, sizeof(*vp)))
    return false;
  *vp = le16toh(*vp);
  return true;
}

static inline bool
buffer_get_u32le(buffer_t *bp, uint32_t *vp)
{
  if (!buffer_get(bp, vp, sizeof(*vp)))
    return false;
  *vp = le32toh(*vp);
  return true;
}


// ------------------------------------------------------------------


static inline const tpm_algo_info_t *
digest_by_name(const char *name)
{
  const tpm_algo_info_t *algo;
  int i;

  for (i = 0, algo = tpm_algorithms; i < TPM2_ALG_MAX; ++i, ++algo) {
    if (algo->openssl_name && !strcasecmp(algo->openssl_name, name))
      return algo;
  }

  return NULL;
}

static inline digest_ctx_t *
digest_ctx_new(const tpm_algo_info_t *algo_info)
{
  const EVP_MD *evp_md;
  digest_ctx_t *ctx;

  evp_md = EVP_get_digestbyname(algo_info->openssl_name);
  if (evp_md == NULL) {
    error("Unknown message digest %s\n", algo_info->openssl_name);
    return NULL;
  }

  assert(EVP_MD_size(evp_md) == algo_info->digest_size);

  ctx = calloc(1, sizeof(*ctx));
  ctx->mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx->mdctx, evp_md, NULL);

  ctx->md.algo = algo_info;

  return ctx;
}

static inline void
digest_ctx_update(digest_ctx_t *ctx, const void *data, unsigned int size)
{
  if (ctx->mdctx == NULL)
    fatal("%s: trying to update digest after having finalized it\n", __func__);

  EVP_DigestUpdate(ctx->mdctx, data, size);
}

static inline tpm_evdigest_t *
digest_ctx_final(digest_ctx_t *ctx, tpm_evdigest_t *result)
{
  tpm_evdigest_t *md = &ctx->md;

  if (ctx->mdctx) {
    EVP_DigestFinal_ex(ctx->mdctx, md->data, &md->size);

    EVP_MD_CTX_free(ctx->mdctx);
    ctx->mdctx = NULL;
  }

  if (result) {
    *result = *md;
    md = result;
  }

  return md;
}

static inline void
digest_ctx_free(digest_ctx_t *ctx)
{
  (void) digest_ctx_final(ctx, NULL);

  free(ctx);
}


// ------------------------------------------------------------------


static inline void
assign_string(char **var, const char *string)
{
  if (*var) {
    free(*var);
    *var = NULL;
  }
  if (string)
    *var = strdup(string);
}

static inline pecoff_image_info_t *
pecoff_image_info_alloc(buffer_t *data, const char *display_name)
{
  pecoff_image_info_t *img;

  img = calloc(1, sizeof(*img));
  assign_string(&img->display_name, display_name);
  img->data = data;
  return img;
}

static inline void
pecoff_image_info_free(pecoff_image_info_t *img)
{
  buffer_free(img->data);
  free(img->display_name);
  free(img->data_dirs);
  free(img->section);
  free(img);
}

static int
pecoff_placement_compare(const void *a, const void *b)
{
  const pecoff_placement_t *pa = a;
  const pecoff_placement_t *pb = b;

  return (int) pa->addr - (int) pb->addr;
}


// ------------------------------------------------------------------


static void
authenticode_add_range(authenticode_image_info_t *info, unsigned int offset, unsigned int len)
{
  pecoff_placement_t *h;

  pe_debug("  Authenticode: Including %u bytes at offset %u\n", len, offset);
  if (info->num_areas >= PECOFF_MAX_AREAS)
    fatal("%s: cannot cover more than %d areas of a PE executable\n", __func__, PECOFF_MAX_AREAS);

  h = info->area + info->num_areas++;
  h->addr = offset;
  h->size = len;
}

static void
authenticode_finalize(authenticode_image_info_t *info)
{
  unsigned int i, j, range_end;
  pecoff_placement_t *area, *hole;

  for (i = 0, hole = info->hole; i < info->num_holes; ++i, ++hole) {
    unsigned int hole_end;

    pe_debug("  Hole %2u: 0x%x->0x%x\n", i, hole->addr, hole->addr + hole->size);
    hole_end = hole->addr + hole->size;

    for (j = 0, area = info->area; j < info->num_areas; ++j, ++area) {
      unsigned int area_end = area->addr + area->size;

      if (hole_end <= area->addr || area_end <= hole->addr)
        continue;

      pe_debug("  Area %u: 0x%x->0x%x overlaps hole %u\n", j, area->addr, area->addr + area->size, i);

      if (area->addr < hole->addr) {
        area->size = hole->addr - area->addr;
      } else {
        area->size = 0;
      }

      if (hole_end < area_end)
        authenticode_add_range(info, hole_end, area_end - hole_end);
    }
  }

  qsort(info->hole, info->num_holes, sizeof(info->hole[0]), pecoff_placement_compare);
  qsort(info->area, info->num_areas, sizeof(info->area[0]), pecoff_placement_compare);

  range_end = info->auth_range.addr + info->auth_range.size;
  for (i = 0, area = info->area; i < info->num_areas; ++i, ++area) {
    pe_debug("  Area %u: 0x%x->0x%x\n", i, area->addr, area->addr + area->size);
    if (i && area->addr < area[-1].addr + area[-1].size)
      fatal("PECOFF: area %u of PE image overlaps area %u\n",
          i, i - 1);

    if (area->addr >= range_end) {
      pe_debug("** Area %u is beyond the end of the auth range **\n", i);
      info->num_areas = i;
      break;
    }

    if (area->addr + area->size > range_end) {
      pe_debug("** Area %u extends beyond the end of the auth range **\n", i);
      area->size = range_end - area->addr;
    }
  }

  for (i = 0, hole = info->hole; i < info->num_holes; ++i, ++hole) {
    pe_debug("  Hole %2u: 0x%x->0x%x\n", i, hole->addr, hole->addr + hole->size);
  }
}

static void
authenticode_set_range(authenticode_image_info_t *info, unsigned int offset, unsigned int len)
{
  info->auth_range.addr = offset;
  info->auth_range.size = len;
}

static tpm_evdigest_t *
authenticode_compute(authenticode_image_info_t *info, buffer_t *in, digest_ctx_t *digest)
{
  unsigned int area_index;
  static tpm_evdigest_t md;

  authenticode_finalize(info);

  for (area_index = 0; area_index < info->num_areas; ++area_index) {
    pecoff_placement_t *area = &info->area[area_index];

    if (!buffer_seek_read(in, area->addr)
     || buffer_available(in) < area->size) {
      error("area %u points outside file data?!\n", area_index);
      return NULL;
    }

    pe_debug("  Hashing range 0x%x->0x%x\n", area->addr, area->addr + area->size);
    digest_ctx_update(digest, buffer_read_pointer(in), area->size);
  }

  return digest_ctx_final(digest, &md);
}

static inline tpm_evdigest_t *
authenticode_get_digest(pecoff_image_info_t *img, digest_ctx_t *digest)
{
  return authenticode_compute(&img->auth_info, img->data, digest);
}

static void
authenticode_exclude_range(authenticode_image_info_t *info, unsigned int offset, unsigned int len)
{
  pecoff_placement_t *h;

  if( len > 0 ) {    
    pe_debug("  Authenticode: Excluding %u bytes at offset %u\n", len, offset);
    if (info->num_holes >= PECOFF_MAX_HOLES)
      fatal("%s: cannot punch more than %d holes into a file\n", __func__, PECOFF_MAX_HOLES);

    h = info->hole + info->num_holes++;
    h->addr = offset;
    h->size = len;
  }
}

static unsigned int
authenticode_skip(authenticode_image_info_t *info, unsigned int last_offset, unsigned int hole_offset, unsigned int hole_len)
{
  authenticode_add_range(info, last_offset, hole_offset - last_offset);
  return hole_offset + hole_len;
}


// ------------------------------------------------------------------


static inline bool
__pecoff_seek(buffer_t *in, const pecoff_image_info_t *img, unsigned int offset)
{
  return buffer_seek_read(in, img->pe_hdr.offset + offset);
}

static inline bool
__pecoff_get_u16(buffer_t *in, const pecoff_image_info_t *img, unsigned int offset, uint16_t *vp)
{
  return __pecoff_seek(in, img, offset) && buffer_get_u16le(in, vp);
}

static inline bool
__pecoff_get_u32(buffer_t *in, const pecoff_image_info_t *img, unsigned int offset, uint32_t *vp)
{
  return __pecoff_seek(in, img, offset) && buffer_get_u32le(in, vp);
}

static inline const char *
__pecoff_get_machine(const pecoff_image_info_t *img)
{
  static struct {
    unsigned int  id;
    const char *  name;
  } pe_machine_ids[] = {
    { 0,    "unknown" },
    { 0x1c0,  "arm"   },
    { 0xaa64, "aarch64" },
    { 0x8664, "x86_64"  },
    { 0, NULL }
  }, *p;

  pe_debug("  Machine ID 0x%x\n", img->pe_hdr.machine_id);
  for (p = pe_machine_ids; p->name; ++p) {
    if (p->id == img->pe_hdr.machine_id)
      return p->name;
  }

  pe_debug("PE/COFF image has unsupported machine ID 0x%x\n", img->pe_hdr.machine_id);
  return "unsupported";
}

#ifdef DEBUG_AUTHENTICODE
static inline void
__pecoff_show_header(pecoff_image_info_t *img)
{
  pe_debug("  PE header at 0x%x\n", img->pe_hdr.offset);
  pe_debug("  Architecture: %s\n", __pecoff_get_machine(img));
  pe_debug("  Number of sections: %d\n", img->pe_hdr.num_sections);
  pe_debug("  Symbol table position: 0x%08x\n", img->pe_hdr.symtab_offset);
  pe_debug("  Optional header size: %d\n", img->pe_hdr.optional_hdr_size);
}

static inline void
__pecoff_show_optional_header(pecoff_image_info_t *img)
{
  unsigned int i;

  switch (img->format) {
  case PECOFF_FORMAT_PE32:
    pe_debug("  PECOFF image format: PE32\n");
    break;

  case PECOFF_FORMAT_PE32_PLUS:
    pe_debug("  PECOFF image format: PE32+\n");
    break;

  default:
    pe_debug("  PECOFF image format: unknown\n");
    break;
  }

  pe_debug("  Size of headers: %d\n", img->pe_optional_header.size_of_headers);
  pe_debug("  Data dir entries: %d\n", img->pe_optional_header.data_dir_count);

  for (i = 0; i < img->num_data_dirs; ++i) {
    pecoff_image_datadir_t *de = img->data_dirs + i;

    if (de->size)
      pe_debug("  Data dir %d: %u bytes at %08x\n", i, de->size, de->addr);
  }
}
#endif

static bool
__pecoff_process_header(buffer_t *in, pecoff_image_info_t *img)
{
  if (!buffer_seek_read(in, MSDOS_STUB_PE_OFFSET)
   || !buffer_get_u32le(in, &img->pe_hdr.offset))
    return false;

  if (!buffer_seek_read(in, img->pe_hdr.offset)
   || memcmp(buffer_read_pointer(in), "PE\0\0", 4))
    return false;

  /* PE header starts immediately after the PE signature */
  img->pe_hdr.offset += 4;

  if (!__pecoff_get_u16(in, img, PECOFF_HEADER_MACHINE_OFFSET, &img->pe_hdr.machine_id))
    return NULL;

  if (!__pecoff_get_u16(in, img, PECOFF_HEADER_NUMBER_OF_SECTIONS_OFFSET, &img->pe_hdr.num_sections))
    return false;

  if (!__pecoff_get_u32(in, img, PECOFF_HEADER_SYMTAB_POS_OFFSET, &img->pe_hdr.symtab_offset))
    return false;

  img->pe_hdr.optional_hdr_offset = img->pe_hdr.offset + PECOFF_HEADER_LENGTH;
  if (!__pecoff_get_u16(in, img, PECOFF_HEADER_OPTIONAL_HDR_SIZE_OFFSET, &img->pe_hdr.optional_hdr_size))
    return false;

  img->pe_hdr.section_table_offset = img->pe_hdr.optional_hdr_offset + img->pe_hdr.optional_hdr_size;

  return true;
}

static bool
__pecoff_process_optional_header(buffer_t *in, pecoff_image_info_t *info)
{
  unsigned int hdr_offset = info->pe_hdr.optional_hdr_offset;
  unsigned int hdr_size = info->pe_hdr.optional_hdr_size;
  buffer_t hdr;
  uint16_t magic;
  unsigned int data_dir_offset, i, hash_base = 0;

  if (hdr_size == 0) {
    error("Invalid PE image: OptionalHdrSize can't be 0\n");
    return false;
  }

  /* Create a buffer that provides access to the PE header but not beyond */
  if (!buffer_seek_read(in, hdr_offset)
   || !buffer_get_buffer(in, hdr_size, &hdr))
    return false;

  if (!buffer_seek_read(&hdr, PECOFF_OPTIONAL_HDR_MAGIC_OFFSET)
   || !buffer_get_u16le(&hdr, &magic))
    return false;

  switch (magic) {
  case PECOFF_FORMAT_PE32:
    /* We do not point to the Data Directory itself as defined in the
     * PE spec, but to NumberOfRvaAndSizes which is the 32bit word
     * immediately preceding the Data Directory. */
    data_dir_offset = 92;
    break;

  case PECOFF_FORMAT_PE32_PLUS:
    /* We do not point to the Data Directory itself as defined in the
     * PE spec, but to NumberOfRvaAndSizes which is the 32bit word
     * immediately preceding the Data Directory. */
    data_dir_offset = 108;
    break;

  default:
    error("Unexpected magic number 0x%x in PECOFF optional header\n", magic);
    return false;
  }

  info->format = magic;

  if (!buffer_seek_read(&hdr, PECOFF_OPTIONAL_HDR_SIZEOFHEADERS_OFFSET)
   || !buffer_get_u32le(&hdr, &info->pe_optional_header.size_of_headers))
    return false;

  /* Skip the checksum field when computing the digest.
   * The offset of the checksum is the same for PE32 and PE32+ */
  hash_base = authenticode_skip(&info->auth_info, hash_base,
      hdr_offset + PECOFF_OPTIONAL_HDR_CHECKSUM_OFFSET, 4);

  if (!buffer_seek_read(&hdr, data_dir_offset)
   || !buffer_get_u32le(&hdr, &info->pe_optional_header.data_dir_count))
    return false;

  if (info->pe_optional_header.data_dir_count <= PECOFF_DATA_DIRECTORY_CERTTBL_INDEX) {
    error("PECOFF data directory too small - cannot find Certificate Table (expected at index %u)\n", PECOFF_DATA_DIRECTORY_CERTTBL_INDEX);
    return false;
  }

  info->data_dirs = calloc(info->pe_optional_header.data_dir_count, sizeof(info->data_dirs[0]));
  info->num_data_dirs = info->pe_optional_header.data_dir_count;

  for (i = 0; i < info->pe_optional_header.data_dir_count; ++i) {
    pecoff_image_datadir_t *de = info->data_dirs + i;

    if (!buffer_get_u32le(&hdr, &de->addr)
     || !buffer_get_u32le(&hdr, &de->size))
      return false;
  }

  /* Exclude the data directory entry pointing to the certificate table */
  hash_base = authenticode_skip(&info->auth_info, hash_base,
      hdr_offset + data_dir_offset + 4 + 8 * PECOFF_DATA_DIRECTORY_CERTTBL_INDEX, 8);

  authenticode_exclude_range(&info->auth_info,
      info->data_dirs[PECOFF_DATA_DIRECTORY_CERTTBL_INDEX].addr,
      info->data_dirs[PECOFF_DATA_DIRECTORY_CERTTBL_INDEX].size);

  /* digest everything until the end of the PE headers, incl the section headers */
  authenticode_add_range(&info->auth_info, hash_base, info->pe_optional_header.size_of_headers - hash_base);
  info->auth_info.hashed_bytes = info->pe_optional_header.size_of_headers;

  return true;
}

static bool
__pecoff_process_sections(buffer_t *in, pecoff_image_info_t *info)
{
  unsigned int tbl_offset = info->pe_hdr.section_table_offset;
  unsigned int num_sections = info->pe_hdr.num_sections;
  buffer_t hdr;
  unsigned int i;
  pecoff_section_t *sec;

  pe_debug("  Processing %u sections (table at offset %u)\n", num_sections, tbl_offset);

  /* Create a buffer that provides access to the PE header but not beyond */
  if (!buffer_seek_read(in, tbl_offset)
   || !buffer_get_buffer(in, 40 * num_sections, &hdr))
    return false;

  info->num_sections = num_sections;
  info->section = calloc(num_sections, sizeof(info->section[0]));
  for (i = 0; i < num_sections; ++i) {
    pecoff_section_t *sec = info->section + i;

    if (!buffer_seek_read(&hdr, i * 40))
      return false;

    if (!buffer_get(&hdr, sec->name, 8)
     || !buffer_get_u32le(&hdr, &sec->virtual.size)
     || !buffer_get_u32le(&hdr, &sec->virtual.addr)
     || !buffer_get_u32le(&hdr, &sec->raw.size)
     || !buffer_get_u32le(&hdr, &sec->raw.addr))
      return false;

    pe_debug("  Section %-8s raw %7u at 0x%08x-0x%08x\n",
        sec->name, sec->raw.size, sec->raw.addr, sec->raw.addr + sec->raw.size);
  }

  /* We are supposed to sort the sections in ascending order, but we're not doing it here, we
   * let authenticode_finalize() do it for us. */
  for (i = 0, sec = info->section; i < num_sections; ++i, ++sec) {
    if (sec->raw.size != 0) {
      authenticode_add_range(&info->auth_info, sec->raw.addr, sec->raw.size);
      /* Note: even if we later omit (part of) this section because it overlaps
       * a hole, we still account for these as "hashed_bytes" */
      info->auth_info.hashed_bytes += sec->raw.size;
    }
  }

  return true;
}

static inline pecoff_image_info_t *
pecoff_inspect(buffer_t *in, const char *display_name)
{
  pecoff_image_info_t *img;
  authenticode_image_info_t *auth_info;

  debug("Reading EFI application %s\n", display_name);

  img = pecoff_image_info_alloc(in, display_name);

  if (!__pecoff_process_header(in, img)) {
    error("PECOFF: error processing image header\n");
    goto failed;
  }

  #ifdef DEBUG_AUTHENTICODE
  __pecoff_show_header(img);
  #endif

  if (!__pecoff_process_optional_header(in, img)) {
    error("PECOFF: error processing optional header of image file\n");
    goto failed;
  }

  #ifdef DEBUG_AUTHENTICODE
  __pecoff_show_optional_header(img);
  #endif

  if (!__pecoff_process_sections(in, img)) {
    error("PECOFF: error processing section table of image file\n");
    goto failed;
  }

  auth_info = &img->auth_info;
  if (auth_info->hashed_bytes < in->wpos) {
    unsigned int trailing = in->wpos - auth_info->hashed_bytes;

    authenticode_add_range(auth_info, auth_info->hashed_bytes, trailing);
    auth_info->hashed_bytes += trailing;
  }

  authenticode_set_range(auth_info, 0, auth_info->hashed_bytes);
  return img;

failed:
  pecoff_image_info_free(img);
  return NULL;
}


// ------------------------------------------------------------------


static inline
void
hash_oneshot(
  const tpm_algo_info_t *in_algo,
  unsigned char *out_data,
  const unsigned char *in_data,
  size_t in_data_len
) {
  digest_ctx_t *ctx = digest_ctx_new(in_algo);
  assert( ctx != NULL );
  digest_ctx_update(ctx, in_data, in_data_len);
  digest_ctx_final(ctx, NULL);
  memcpy(out_data, ctx->md.data, ctx->md.size);
  free(ctx);
}

static inline
void
print_hex(const unsigned char *data, size_t data_length)
{
  for (size_t i = 0; i < data_length; i++) {
    printf("%02x", data[i]);
  }
}

static inline
void
pcr_extend(
  struct tpm_evdigest *inout_pcr,
  const unsigned char *data,
  size_t data_length,
  bool pre_hash
) {
  const tpm_algo_info_t *algo = inout_pcr->algo;
  unsigned char buf[algo->digest_size * 2];
  memset(buf, 0, algo->digest_size * 2);
  memcpy(buf, inout_pcr->data, algo->digest_size);

  if( pre_hash ) {
    hash_oneshot(algo, &buf[algo->digest_size], data, data_length);
  }
  else {
    assert( (int)data_length == algo->digest_size );
    memcpy(&buf[algo->digest_size], data, data_length);
  }

  hash_oneshot(algo, inout_pcr->data, buf, algo->digest_size * 2);
}

static inline
void pcr_extend_str( struct tpm_evdigest *inout_pcr, const char *str ) {
  pcr_extend(inout_pcr, (const unsigned char *)str, strlen(str), true);
}

static inline
void pcr_extend_separator( struct tpm_evdigest *inout_pcr ) {
  unsigned char empty[4] = {0,0,0,0};
  pcr_extend(inout_pcr, empty, 4, true);
}


// ------------------------------------------------------------------


int main( int argc, char **argv )
{
  int ret = 1;

  if( argc < 3 ) {
    error("Usage: %s <alg> <uki.efi|-> [variant]\n", argv[0]);
    return 1;
  }

  char *algo_name = argv[1];
  char *efifile_path = argv[2];

  digest_ctx_t *digest = NULL;
  pecoff_image_info_t *img = NULL;

  buffer_t *in = buffer_read_file(efifile_path);
  if( NULL == in ) {
    error("Error: error opening %s\n", efifile_path);
    goto end;
  }

  // takes ownership of buffer
  if( NULL == (img = pecoff_inspect(in, efifile_path)) ) {
    error("Error: error inspecting %s\n", efifile_path);
    goto end;
  }

  // Calculate authenticode digest
  const tpm_algo_info_t *algo = digest_by_name(algo_name);
  if( ! algo ) {
    error("Error: unknown hash algorithm %s\n", algo_name);
    goto end;
  }

  if( NULL == (digest = digest_ctx_new(algo)) ) {
    error("Error: cannot creat digest context\n");
    goto end;
  }

  if ( NULL == authenticode_get_digest(img, digest) ) {
    error("Error: cannot perform authenticode hash\n");
    goto end;
  }

  int variant = 0;
  if( argc > 3 ) {
    variant = atoi(argv[3]);
  }

  digest_ctx_t *pcr4 = digest_ctx_new(algo);

  if( variant == 1 ) {    
    // QEMU does this, but some Lenovo UEFI firmware doesn't...
    // See Spec: https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html#pcr-4
    pcr_extend_str(&pcr4->md, "Calling EFI Application from Boot Option");
  }
  else if( variant != 0 ) {
    fatal("Unknown PCR sequence variant\n");
  }

  pcr_extend_separator(&pcr4->md);

  pcr_extend(&pcr4->md, digest->md.data, algo->digest_size, false);

  print_hex(pcr4->md.data, algo->digest_size);
  printf("\n");

  ret = 0;

end:
  if( img != NULL ) pecoff_image_info_free(img);
  if( digest != NULL ) digest_ctx_free(digest);
  return ret;
}
