/* 
 * Copyright (C) 2006 David Boyce.  All rights reserved.
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stddef.h>
#include <string.h>
#include <sys/types.h>

#include "zipfile.h"
#include "zipfmt.h"

enum result { RES_SAME, RES_DIFFERENT, RES_UNKNOWN };

/* Return nonzero if the data looks like a ZIP archive. */
int
is_zip_file(const void *data, off_t size)
{
    /* Expect at least one file header and the end of central directory
       record. */
    return size >= (off_t)(sizeof(struct file_header) + sizeof(struct cd_end))
	&& SIGNATURE_MATCHES(data, file_header);
}

/* Return a 16-bit value */
static unsigned
get_u16(const byte *b)
{
    return b[0] | (b[1] << 8);
}

/* Return a 32-bit value */
static unsigned
get_u32(const byte *b)
{
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
}

/* Return a 64-bit value. */
static unsigned long long
get_u64(const byte *b)
{
    return get_u32(b) | ((unsigned long long)get_u32(b + 4) << 32);
}

#define ADVANCE(SIZE)				\
    do {					\
	size_t s__ = (SIZE);			\
	size_left -= s__;			\
	data1 += s__;				\
	data2 += s__;				\
    } while(0)

#define COMPARE_AND_ADVANCE(SIZE)		\
    do {					\
	size_t s__ = (SIZE);			\
	if ((size_t)size_left < s__)		\
	    return RES_UNKNOWN;			\
	if (memcmp(data1, data2, s__) != 0)	\
	    return RES_DIFFERENT;		\
	size_left -= s__;			\
	data1 += s__;				\
	data2 += s__;				\
    } while(0)

/* Compare per-file extra data;
   Update compressed_size if it is not NULL, otherwise assume compressed_size
   is not present in the zip64 header. */
static enum result
cmp_file_extra(const unsigned char **p1, const unsigned char **p2, off_t *p3,
	       size_t extra_len, int *is_zip64,
	       unsigned long long *compressed_size)
{
    const unsigned char *data1, *data2;
    off_t size_left;

    data1 = *p1;
    data2 = *p2;
    size_left = *p3;
    while (extra_len >= sizeof(struct extra_header)) {
	struct extra_header eh;
	size_t len;

	memcpy(&eh, data1, sizeof(eh));
	COMPARE_AND_ADVANCE(sizeof(eh));
	len = get_u16(eh.data_size);
	if (extra_len < sizeof(eh) + len)
	    return RES_UNKNOWN;
	extra_len -= sizeof(eh) + len;
	if (memcmp(eh.id, eh_id_zip64, sizeof(eh_id_zip64)) == 0) {
	    *is_zip64 = 1;
	    if (compressed_size != NULL)
		*compressed_size = get_u64(data1 + 8);
	    COMPARE_AND_ADVANCE(len);
	} else if (memcmp(eh.id, eh_id_ext_timestamp,
			  sizeof(eh_id_ext_timestamp)) == 0) {
	    if (len < 1)
		return RES_UNKNOWN;
	    COMPARE_AND_ADVANCE(1);	/* Time presence flags */
	    ADVANCE(len - 1);	/* mtime, atime, ctime - if present */
	} else
	    COMPARE_AND_ADVANCE(len);
    }
    if (extra_len != 0)
	return RES_UNKNOWN;
    *p1 = data1;
    *p2 = data2;
    *p3 = size_left;
    return RES_SAME;
}

/* Compare data about a single file */
static enum result
cmp_one_file(const unsigned char **p1, const unsigned char **p2, off_t *p3)
{
    static const byte unset[4] = { '\xFF', '\xFF', '\xFF', '\xFF' };

    const unsigned char *data1, *data2;
    off_t size_left;
    struct file_header h1, h2;
    size_t len;
    unsigned long long compressed_size;
    int is_zip64;
    enum result res;

    data1 = *p1;
    data2 = *p2;
    size_left = *p3;
    memcpy(&h1, data1, sizeof(h1));
    memcpy(&h2, data2, sizeof(h2));
    ADVANCE(sizeof(h1));
    memset(h1.mtime, 0, sizeof(h1.mtime));
    memset(h2.mtime, 0, sizeof(h2.mtime));
    memset(h1.mdate, 0, sizeof(h1.mdate));
    memset(h2.mdate, 0, sizeof(h2.mdate));
    if (memcmp(&h1, &h2, sizeof(h1)) != 0)
	return RES_DIFFERENT;
    compressed_size = get_u32(h1.compressed_size);
    is_zip64 = 0;
    len = get_u16(h1.name_length);
    COMPARE_AND_ADVANCE(len);
    res = cmp_file_extra(&data1, &data2, &size_left, get_u16(h1.extra_length),
			 &is_zip64,
			 (memcmp(h1.uncompressed_size, unset, sizeof(unset))
			  == 0
			  && (memcmp(h1.uncompressed_size, unset, sizeof(unset))
			      == 0)) ? &compressed_size : NULL);
    if (res != RES_SAME)
	return res;
    if (compressed_size != 0)
	COMPARE_AND_ADVANCE((size_t)compressed_size);
    else if (h1.flags[0] & FLAGS_0_HAVE_DESCRIPTOR) {
	size_t off;

	/* Just search for the descriptor; perhaps we could start with the
	   central directory and get the compressed size from there instead? */
	off = 0;
	while (off + sizeof(file_descriptor_signature)
	       + sizeof(struct file_descriptor_zip32) < (size_t)size_left) {
	    const unsigned char *p;

	    p = memchr(data1 + off, file_descriptor_signature[0],
		       size_left - off);
	    if (p != NULL && memcmp(p, file_descriptor_signature,
				    sizeof(file_descriptor_signature)) == 0) {
		size_t skip_size;

		skip_size = p - data1;
		if (memcmp(data2 + skip_size, file_descriptor_signature,
			   sizeof(file_descriptor_signature)) == 0) {
		    /* Got the signature in both files, probably a match. */
		    COMPARE_AND_ADVANCE(skip_size);
		    break;
		}
	    }
	    off = (p - data1) + 1;
	}
    }
    if (h1.flags[0] & FLAGS_0_HAVE_DESCRIPTOR) {
	if ((size_t)size_left >= sizeof(file_descriptor_signature)
	    && memcmp(data1, file_descriptor_signature,
		      sizeof(file_descriptor_signature)) == 0
	    && memcmp(data2, file_descriptor_signature,
		      sizeof(file_descriptor_signature)) == 0)
	    ADVANCE(sizeof(file_descriptor_signature));
	if (is_zip64)
	    len = sizeof(struct file_descriptor_zip64);
	else
	    len = sizeof(struct file_descriptor_zip32);
	COMPARE_AND_ADVANCE(len);
    }
    *p1 = data1;
    *p2 = data2;
    *p3 = size_left;
    return RES_SAME;
}

/* Compare central directory data about a single file */
static int
cmp_one_cd_file(const unsigned char **p1, const unsigned char **p2, off_t *p3)
{
    const unsigned char *data1, *data2;
    off_t size_left;
    struct cd_file h1, h2;
    size_t len;
    enum result res;
    int is_zip64;

    data1 = *p1;
    data2 = *p2;
    size_left = *p3;
    memcpy(&h1, data1, sizeof(h1));
    memcpy(&h2, data2, sizeof(h2));
    ADVANCE(sizeof(h1));
    memset(h1.mtime, 0, sizeof(h1.mtime));
    memset(h2.mtime, 0, sizeof(h2.mtime));
    memset(h1.mdate, 0, sizeof(h1.mdate));
    memset(h2.mdate, 0, sizeof(h2.mdate));
    if (memcmp(&h1, &h2, sizeof(h1)) != 0)
	return RES_DIFFERENT;
    len = get_u16(h1.name_length);
    COMPARE_AND_ADVANCE(len);
    res = cmp_file_extra(&data1, &data2, &size_left, get_u16(h1.extra_length),
			 &is_zip64, NULL);
    if (res != RES_SAME)
	return res;
    len = get_u16(h1.comment_length);
    COMPARE_AND_ADVANCE(len);
    *p1 = data1;
    *p2 = data2;
    *p3 = size_left;
    return RES_SAME;
}

#undef ADVANCE
#undef COMPARE_AND_ADVANCE

#define ADVANCE(SIZE)				\
    do {					\
	size_t s__ = (SIZE);			\
	size_left -= s__;			\
	data1 += s__;				\
	data2 += s__;				\
    } while(0)

#define COMPARE_AND_ADVANCE(SIZE)		\
    do {					\
	size_t s__ = (SIZE);			\
	if ((size_t)size_left < s__)		\
	    goto unknown;			\
	if (memcmp(data1, data2, s__) != 0)	\
	    return -1;				\
	size_left -= s__;			\
	data1 += s__;				\
	data2 += s__;				\
    } while(0)

/* Return zero if the two input ZIP archives contain the same files in the same
   order. */
int
cmp_zip_files(const void *data1_, const void *data2_, off_t total_size)
{
    const unsigned char *data1, *data2;
    off_t size_left;
    size_t len;
    enum result res;

    data1 = data1_;
    data2 = data2_;
    size_left = total_size;
    /* File data */
    while (size_left >= (off_t)sizeof(struct file_header)
	   && SIGNATURE_MATCHES(data1, file_header)
	   && SIGNATURE_MATCHES(data2, file_header)) {
	res = cmp_one_file(&data1, &data2, &size_left);
	if (res != RES_SAME)
	    goto not_same;
    }
    /* Archive decryption header would go here. */
    if ((size_t)size_left >= sizeof(struct archive_extra_data)
	&& SIGNATURE_MATCHES(data1, archive_extra_data)
	&& SIGNATURE_MATCHES(data2, archive_extra_data)) {
	len = get_u32(data1 + offsetof(struct archive_extra_data,
				       extra_length));
	COMPARE_AND_ADVANCE(sizeof(struct archive_extra_data) + len);
    }
    while ((size_t)size_left >= (off_t)sizeof(struct cd_file)
	   && SIGNATURE_MATCHES(data1, cd_file)
	   && SIGNATURE_MATCHES(data2, cd_file)) {
	res = cmp_one_cd_file(&data1, &data2, &size_left);
	if (res != RES_SAME)
	    goto not_same;
    }
    if ((size_t)size_left >= sizeof(struct cd_signature)
	&& SIGNATURE_MATCHES(data1, cd_signature)
	&& SIGNATURE_MATCHES(data2, cd_signature)) {
	len = get_u16(data1 + offsetof(struct cd_signature, data_length));
	COMPARE_AND_ADVANCE(sizeof(struct cd_signature) + len);
    }
    if ((size_t)size_left >= sizeof(struct cd_end_zip64_v1)
	&& SIGNATURE_MATCHES(data1, cd_end_zip64_v1)
	&& SIGNATURE_MATCHES(data2, cd_end_zip64_v1)) {
	len = 12 + (size_t)get_u64(data1 + offsetof(struct cd_end_zip64_v1,
					    cd_end_zip64_size));
	COMPARE_AND_ADVANCE(len);
    }
    if ((size_t)size_left >= sizeof(struct cd_end_locator_zip64)
	&& SIGNATURE_MATCHES(data1, cd_end_locator_zip64)
	&& SIGNATURE_MATCHES(data2, cd_end_locator_zip64))
	COMPARE_AND_ADVANCE(sizeof(struct cd_end_locator_zip64));
    if ((size_t)size_left >= sizeof(struct cd_end)
	&& SIGNATURE_MATCHES(data1, cd_end)
	&& SIGNATURE_MATCHES(data2, cd_end)) {
	len = get_u16(data1 + offsetof(struct cd_end, comment_length));
	COMPARE_AND_ADVANCE(sizeof(struct cd_end) + len);
    }
    if (size_left != 0)
	goto unknown;
    return 0;

  not_same:
    if (res == RES_DIFFERENT)
	return -1;
  unknown:
    return memcmp(data1_, data2_, total_size);
}
