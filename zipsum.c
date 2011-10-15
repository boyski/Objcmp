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

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "zipfmt.h"

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
	if ((size_t)size_left < s__)		\
	    return -1;				\
	size_left -= s__;			\
	data += s__;				\
    } while(0)

/* Clear per-file extra data;
   Update compressed_size if it is not NULL, otherwise assume compressed_size
   is not present in the zip64 header. */
static int
clear_file_extra(unsigned char **p1, off_t *p2, size_t extra_len, int *is_zip64,
		 unsigned long long *compressed_size)
{
    unsigned char *data;
    off_t size_left;

    data = *p1;
    size_left = *p2;
    while (extra_len >= sizeof(struct extra_header)) {
	struct extra_header eh;
	size_t len;

	memcpy(&eh, data, sizeof(eh));
	ADVANCE(sizeof(eh));
	len = get_u16(eh.data_size);
	if (extra_len < sizeof(eh) + len)
	    return -1;
	extra_len -= sizeof(eh) + len;
	if (memcmp(eh.id, eh_id_zip64, sizeof(eh_id_zip64)) == 0) {
	    *is_zip64 = 1;
	    if (compressed_size != NULL)
		*compressed_size = get_u64(data + 8);
	    ADVANCE(len);
	} else if (memcmp(eh.id, eh_id_ext_timestamp,
			  sizeof(eh_id_ext_timestamp)) == 0) {
	    if (len < 1)
		return -1;
	    ADVANCE(1);		/* Time presence flags */
	    memset(data, 0, len - 1);	/* mtime, atime, ctime - if present */
	    ADVANCE(len - 1);
	} else
	    ADVANCE(len);
    }
    if (extra_len != 0)
	return -1;
    *p1 = data;
    *p2 = size_left;
    return 0;
}

/* Clear data about a single file */
static int
clear_one_file(unsigned char **p1, off_t *p2)
{
    static const byte unset[4] = { '\xFF', '\xFF', '\xFF', '\xFF' };

    unsigned char *data;
    off_t size_left;
    struct file_header h;
    size_t len;
    unsigned long long compressed_size;
    int is_zip64;

    data = *p1;
    size_left = *p2;
    memcpy(&h, data, sizeof(h));
    memset(h.mtime, 0, sizeof(h.mtime));
    memset(h.mdate, 0, sizeof(h.mdate));
    memcpy(data, &h, sizeof(h));
    ADVANCE(sizeof(h));
    compressed_size = get_u32(h.compressed_size);
    is_zip64 = 0;
    len = get_u16(h.name_length);
    ADVANCE(len);
    if (clear_file_extra(&data, &size_left, get_u16(h.extra_length), &is_zip64,
			 (memcmp(h.uncompressed_size, unset, sizeof(unset)) == 0
			  && (memcmp(h.uncompressed_size, unset, sizeof(unset))
			      == 0)) ? &compressed_size : NULL) != 0)
	return -1;
    if (compressed_size != 0)
	ADVANCE((size_t)compressed_size);
    else if (h.flags[0] & FLAGS_0_HAVE_DESCRIPTOR) {
	size_t off;

	/* Just search for the descriptor; perhaps we could start with the
	   central directory and get the compressed size from there instead? */
	off = 0;
	while (off + sizeof(file_descriptor_signature)
	       + sizeof(struct file_descriptor_zip32) < (size_t)size_left) {
	    unsigned char *p;

	    p = memchr(data + off, file_descriptor_signature[0],
		       size_left - off);
	    if (p != NULL && memcmp(p, file_descriptor_signature,
				    sizeof(file_descriptor_signature)) == 0) {
		ADVANCE(p - data);
		break;
	    }
	    off = (p - data) + 1;
	}
    }
    if (h.flags[0] & FLAGS_0_HAVE_DESCRIPTOR) {
	if ((size_t)size_left >= sizeof(file_descriptor_signature)
	    && memcmp(data, file_descriptor_signature,
		      sizeof(file_descriptor_signature)) == 0)
	    ADVANCE(sizeof(file_descriptor_signature));
	if (is_zip64)
	    len = sizeof(struct file_descriptor_zip64);
	else
	    len = sizeof(struct file_descriptor_zip32);
	ADVANCE(len);
    }
    *p1 = data;
    *p2 = size_left;
    return 0;
}

/* Clear central directory data about a single file */
static int
clear_one_cd_file(unsigned char **p1, off_t *p2)
{
    unsigned char *data;
    off_t size_left;
    struct cd_file h;
    size_t len;
    int is_zip64;

    data = *p1;
    size_left = *p2;
    memcpy(&h, data, sizeof(h));
    memset(h.mtime, 0, sizeof(h.mtime));
    memset(h.mdate, 0, sizeof(h.mdate));
    memcpy(data, &h, sizeof(h));
    ADVANCE(sizeof(h));
    len = get_u16(h.name_length);
    ADVANCE(len);
    if (clear_file_extra(&data, &size_left, get_u16(h.extra_length), &is_zip64,
			 NULL) != 0)
	return -1;
    len = get_u16(h.comment_length);
    ADVANCE(len);
    *p1 = data;
    *p2 = size_left;
    return 0;
}

#undef ADVANCE

#define ADVANCE(SIZE)				\
    do {					\
	size_t s__ = (SIZE);			\
	if ((size_t)size_left < s__)		\
	    return -1;				\
	size_left -= s__;			\
	data += s__;				\
    } while(0)

/* Zero all known timestamps in data_.  Return zero if cleared successfully. */
static int
clear_zip_file(void *data_, off_t total_size)
{
    unsigned char *data;
    off_t size_left;
    size_t len;

    data = data_;
    size_left = total_size;
    /* File data */
    while (size_left >= (off_t)sizeof(struct file_header)
	   && SIGNATURE_MATCHES(data, file_header)) {
	if (clear_one_file(&data, &size_left) != 0)
	    return -1;
    }
    /* Archive decryption header would go here. */
    if ((size_t)size_left >= sizeof(struct archive_extra_data)
	&& SIGNATURE_MATCHES(data, archive_extra_data)) {
	len = get_u32(data + offsetof(struct archive_extra_data, extra_length));
	ADVANCE(sizeof(struct archive_extra_data) + len);
    }
    while ((size_t)size_left >= (off_t)sizeof(struct cd_file)
	   && SIGNATURE_MATCHES(data, cd_file)) {
	if (clear_one_cd_file(&data, &size_left) != 0)
	    return -1;
    }
    if ((size_t)size_left >= sizeof(struct cd_signature)
	&& SIGNATURE_MATCHES(data, cd_signature)) {
	len = get_u16(data + offsetof(struct cd_signature, data_length));
	ADVANCE(sizeof(struct cd_signature) + len);
    }
    if ((size_t)size_left >= sizeof(struct cd_end_zip64_v1)
	&& SIGNATURE_MATCHES(data, cd_end_zip64_v1)) {
	len = 12 + (size_t)get_u64(data + offsetof(struct cd_end_zip64_v1,
						   cd_end_zip64_size));
	ADVANCE(len);
    }
    if ((size_t)size_left >= sizeof(struct cd_end_locator_zip64)
	&& SIGNATURE_MATCHES(data, cd_end_locator_zip64))
	ADVANCE(sizeof(struct cd_end_locator_zip64));
    if ((size_t)size_left >= sizeof(struct cd_end)
	&& SIGNATURE_MATCHES(data, cd_end)) {
	len = get_u16(data + offsetof(struct cd_end, comment_length));
	ADVANCE(sizeof(struct cd_end) + len);
    }
    if (size_left != 0)
	return -1;
    return 0;
}

static void
die(int err, const char *msg)
{
    if (err != 0)
	perror(msg);
    else
	fprintf(stderr, "%s\n", msg);
    exit(1);
}

int
main(int argc, char *argv[])
{
    unsigned char *buf;
    unsigned sum;
    size_t buf_size, data_size, i, j;
    FILE *f;
    int rc = 0;

    if (argc < 2) {
	fprintf(stderr, "Usage: zipsum filename ...\n");
	return 1;
    }

    buf_size = 65536;
    buf = malloc(buf_size);
    if (buf == NULL)
	die(errno, "malloc");

    for (i = 1; i < argc; i++) {
	f = fopen(argv[i], "rb");
	if (f == NULL)
	    die(errno, "fopen");
	data_size = 0;
	for (;;) {
	    size_t run;

	    if (data_size == buf_size) {
		buf_size *= 2;
		buf = realloc(buf, buf_size);
		if (buf == NULL)
		    die(errno, "realloc");
	    }
	    run = fread(buf + data_size, 1, buf_size - data_size, f);
	    if (run == 0)
		break;
	    data_size += run;
	}
	fclose(f);
	if (clear_zip_file(buf, data_size) != 0) {
	    fprintf(stderr, "%s: unrecognized ZIP file format\n", argv[i]);
	    rc = 1;
	    continue;
	}
	/* A stupid checksum */
	sum = 0;
	for (j = 0; j < data_size; j += 4)
	    sum += buf[j] | (buf[j + 1] << 8) | (buf[j + 2] << 16)
		| (buf[j + 2] << 24);
	while (j < data_size) {
	    sum += buf[j];
	    j++;
	}
	printf("%08X\t%s\n", sum, argv[i]);
    }

    free(buf);
    return rc;
}
