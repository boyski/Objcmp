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

/*
 * The archive code for Windows is based on on the Microsoft document
 * "pecoff.doc", sections 7 and 8. There is no equivalent official
 * standard for Unix ar but the code here is based on BSD and seems
 * to work on all platforms tested to date. FWIW the GNU ar program
 * can read both Unix and Windows archives so may be a useful
 * reference on complex problems, but I haven't needed it yet.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#if defined(_WIN32)
#define ARMAG				IMAGE_ARCHIVE_START
#define SARMAG				IMAGE_ARCHIVE_START_SIZE
#define ARFMAG				IMAGE_ARCHIVE_END
#define WIN32_LEAN_AND_MEAN 
#define PATH_MAX			MAX_PATH
#define snprintf			_snprintf
#define S_ISDIR(mode)			(((mode)&0xF000) == 0x4000)
#define S_ISREG(mode)			(((mode)&0xF000) == 0x8000)
#include <windows.h> 
#include <direct.h>
#include <io.h>
#include <malloc.h>
#include <process.h>
#include <stdlib.h>
#include "Unstamp.h"
#else	/*_WIN32*/
#if !defined(BSD)
#include <alloca.h>
#endif
#include <ar.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <unistd.h>
#endif	/*_WIN32*/

#include "zipfile.h"

static int dflag, sflag, vflag;

static char *prog = "objcmp";

#define F				__FILE__
#define L				__LINE__

static void
usage(void)
{
    fprintf(stderr, "Usage: %s [-d] [-s] [-v] <file1> <file2>\n", prog);
    fprintf(stderr,
"\nFlags:\n\
    -d		Dumb mode - do a brute force comparison\n\
    -s		Silent mode - print no output\n\
    -v		Verbose mode - print identical files too\n\
\n\
Compares any two files and returns an exit status of 0 iff they are\n\
known to be 'semantically identical'. The two files are first mapped into\n\
memory and the first blocks compared. If both files are recognized as\n\
known binary types which embed date stamps and/or version data, the offsets\n\
containing these meaningless-at-runtime fields are zeroed. Then,\n\
whether any fields were zeroed or not, the two blocks of memory\n\
are compared byte for byte.\n\
\n\
Recognized file formats include PE (.exe and .dll) and COFF (.obj)\n\
on Windows, and archive files (.lib or .a) on both Windows and Unix.\n\
\n\
No guarantee is made that files which compare different do in fact\n\
differ in any semantic way. Rather, a pessimistic approach is taken\n\
by guaranteeing only that files which compare identical do NOT differ\n\
at runtime.\n\
");

    exit(2);
}

static char *
base_name(const char *path)
{
#ifdef _WIN32
    char fname[_MAX_FNAME], ext[_MAX_EXT], buf[_MAX_PATH];

    _splitpath(path, NULL, NULL, fname, ext);
    strcpy(buf, fname);
    strcat(buf, ext);
    if (!_stricmp(strchr(path, '\0') - strlen(buf), buf)) {
	return (char *)(strchr(path, '\0') - strlen(buf));
    } else {
	return _strdup(buf);
    }
#else	/*_WIN32*/
    return basename((char *)path);
#endif	/*_WIN32*/
}

void
errmsg(int rc, const char *f, int l, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: %s: [at %s:%d] ",
	prog, rc ? "Error" : "Warning", f, l);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void) fputc('\n', stderr);
    if (rc)
	exit(rc);
}

#if defined(_WIN32)
void
sys_err(const char *f, int l, int code, const char *string)
{
    char *msg;

    DWORD flgs = FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM;

    if(!FormatMessage(flgs, NULL, GetLastError(), 0, (LPSTR)&msg, 0, NULL))
        msg = "unknown error";

    errmsg(code, f, l, "%s: %s", string, msg);
}
#else	/*_WIN32*/
void
sys_err(const char *f, int l, int code, const char *string)
{
    errmsg(code, f, l, "%s: %s", string, strerror(errno));
}
#endif	/*_WIN32*/

#if defined(_WIN32)
static void
unstamp2(const char *name1, unsigned char *data1,
	 const char *name2, unsigned char *data2,
	 off_t *plen)
{
    if (unstamp(data1, plen) && name1)
	errmsg(0, F,L, "error unstamping '%s'", name1);
    if (unstamp(data2, plen) && name2)
	errmsg(0, F,L, "error unstamping '%s'", name2);
}
#endif	/*_WIN32*/

#if defined(_WIN32)
static int
cmp_archive(const char *path1, unsigned char *data1,
		const char *path2, unsigned char *data2, off_t len)
{
    unsigned char *dot1, *dot2;
    IMAGE_ARCHIVE_MEMBER_HEADER ar;
    char *strtab = NULL, *p;
    const char *name;
    int rc;

    (void)path2;

    dot1 = data1 + SARMAG;
    dot2 = data2 + SARMAG;

    for (rc = 0; rc == 0 && dot1 < data1 + len;) {
	char name_buf[sizeof(ar.Name) + 1];
	off_t size;
	int i;

	// Read this file's header and move the pointer past it.
	memcpy(&ar, dot1, sizeof(ar));
	dot1 += sizeof(ar);
	dot2 += sizeof(ar);

	// Figure out the boundary of this file within the archive,
	// rounding up to the next even number. If a padding char
	// is present it will be a newline and thus 'stable' from
	// a hashing point of view.
	size = atol((const char *)ar.Size);
	size += size % 2;

	if (!size) {
	    errmsg(2, F,L, "corrupt archive: %s", path1);
	}

	// Force the name field to be null-terminated so it's easier
	// to check for a legit name.
	memcpy(name_buf, ar.Name, sizeof(ar.Name));
	name_buf[sizeof(ar.Name)] = '\0';
	name = name_buf;

	// Skip past certain "internal" files representing
	// symbol tables and string tables. The Windows
	// "pecoff.doc" is (typically) confused about whether
	// the magic char here is / or \, so we check for both.
	if (name[0] == '/' || name[0] == '\\') {
	    if (name[1] == '\0' || name[1] == '/' || name[1] == '\\') {
		// The extended string table is named "//" and filenames
		// within it are delimited by '/'. Save it aside and
		// convert the delimiters to NULs.
		if (name[1] == '/') {
		    strtab = (char *)alloca(size);
		    memcpy(strtab, dot1, size);
		    for (i = 0; i < size; i++) {
			if (strtab[i] == '/')
			    strtab[i] = '\0';
		    }
		}
		dot1 += size;
		dot2 += size;
		continue;
	    } else if (strtab && isdigit(name[1])) {
		// A long name, found by its offset in the string table.
		name = strtab + atoi(name + 1);
		if ((p = strchr(name, '/'))) {
		    *p = '\0';
		}
	    }
	} else if ((p = strchr(name, '/'))) {
	    // Must be a short name; trim the / delimiter.
	    *p = '\0';
	} else {
	    // My reading of the spec implied that a name not
	    // containing a / was bogus but some archivers disagree.
	    // And they're more likely right.
	    //errmsg(2, F,L, "corrupt archive: %s", path1);
	}

	// On Windows an archive may be a regular static library
	// like on Unix, or it may be an "import library", which
	// is just a collection of symbols exported by an
	// accompanying DLL. The following block is to remove an
	// extra date stamp in import libraries. See pecoff.doc
	// section 8 for details.
	if (*((UINT16 *)(dot1)) == IMAGE_FILE_MACHINE_UNKNOWN &&
	    *((UINT16 *)(dot2)) == IMAGE_FILE_MACHINE_UNKNOWN &&
	    *((UINT16 *)(dot1 + 2)) == 0xFFFF &&
	    *((UINT16 *)(dot2 + 2)) == 0xFFFF) {

	    // Zero out the version field within the import header.
	    *((UINT16 *)(dot1 + 4)) = 0;
	    *((UINT16 *)(dot2 + 4)) = 0;

	    // Zero out the datestamp field within the import header.
	    *((UINT32 *)(dot1 + 8)) = 0;
	    *((UINT32 *)(dot2 + 8)) = 0;
	}

	// Fix the individual .obj files represented by this offset.
	unstamp2(name, dot1, name, dot2, NULL);

	// The loop will end as soon as this is nonzero.
	rc = memcmp(dot1, dot2, size);

	if (vflag)
	    printf("* %s %s\n", name, rc ? "differ" : "same");

	// Advance to the next header.
	dot1 += size;
	dot2 += size;
    }

    return rc;
}
#else	/*_WIN32*/
static int
cmp_archive(const char *path1, unsigned char *data1,
		const char *path2, unsigned char *data2, off_t len)
{
    unsigned char *dot1, *dot2;
    struct ar_hdr ar;
    char *strtab = NULL, *p;
    const char *name;
    int rc;

    (void)path2;

    dot1 = data1 + SARMAG;
    dot2 = data2 + SARMAG;

    for (rc = 0; rc == 0 && dot1 < data1 + len;) {
	char name_buf[sizeof(ar.ar_name) + 1];
	off_t size;
	int i;

	// Read each file's header and move the pointer past it.
	memcpy(&ar, dot1, sizeof(ar));
	dot1 += sizeof(ar);
	dot2 += sizeof(ar);

	// Figure out the boundary of this file within the archive,
	// rounding up to the next even number. If a padding char
	// is present it will be a newline and thus 'stable' from
	// a comparison point of view.
	size = atol(ar.ar_size);
	size += size % 2;

	if (!size) {
	    errmsg(2, F,L, "corrupt archive: %s", path1);
	}

	// Force the name field to be null-terminated so it's easier
	// to check for a legit name.
	memcpy(name_buf, ar.ar_name, sizeof(ar.ar_name));
	name_buf[sizeof(ar.ar_name)] = '\0';
	name = name_buf;

	// Skip past certain "internal" files representing
	// symbol tables and string tables.
	if (name[0] == '/') {
	    if (name[1] == '\0' || name[1] == '/' || name[1] == ' ') {
		// The extended string table is named "//" and filenames
		// within it are delimited by '/'. Save it aside and
		// convert the delimiters to NULs.
		if (name[1] == '/') {
		    strtab = (char *)alloca(size);
		    memcpy(strtab, dot1, size);
		    for (i = 0; i < size; i++) {
			if (strtab[i] == '/')
			    strtab[i] = '\0';
		    }
		}
		dot1 += size;
		dot2 += size;
		continue;
	    } else if (strtab && isdigit(name[1])) {
		// A long name, found by its offset in the string table.
		name = strtab + atoi(name + 1);
		if ((p = strchr(name, '/'))) {
		    *p = '\0';
		}
	    }
	} else if ((p = strchr(name, '/'))) {
	    // Must be a short name; trim the / delimiter.
	    *p = '\0';
	} else {
	    errmsg(2, F,L, "corrupt archive: %s", path1);
	}

	// The loop will end as soon as this is nonzero.
	rc = memcmp(dot1, dot2, size);

	if (vflag)
	    printf("* %s %s\n", name, rc ? "differ" : "same");

	// Advance to the next header.
	dot1 += size;
	dot2 += size;
    }

    return rc;
}
#endif	/*_WIN32*/

static int
cmp_data(const char *path1, unsigned char *data1,
	 const char *path2, unsigned char *data2,
	 off_t len)
{
    int rc;

    if (dflag) {
	rc = memcmp(data1, data2, len);
    } else if (!memcmp(data1, ARMAG, SARMAG) && !memcmp(data2, ARMAG, SARMAG)) {
	rc = cmp_archive(path1, data1, path2, data2, len);
    } else if (is_zip_file(data1, len) && is_zip_file(data2, len)) {
	rc = cmp_zip_files(data1, data2, len);
#if defined(_WIN32)
    } else if (((PIMAGE_DOS_HEADER)data1)->e_magic == IMAGE_DOS_SIGNATURE &&
	       ((PIMAGE_DOS_HEADER)data2)->e_magic == IMAGE_DOS_SIGNATURE) {
	// They're both PE (.exe/.dll) files.
	unstamp2(path1, data1, path2, data2, &len);
	rc = memcmp(data1, data2, len);
    } else if (((PIMAGE_FILE_HEADER)data1)->Machine==IMAGE_FILE_MACHINE_I386 &&
	       ((PIMAGE_FILE_HEADER)data2)->Machine==IMAGE_FILE_MACHINE_I386) {
	// They're both COFF object (.obj) files.
	unstamp2(path1, data1, path2, data2, NULL);
	rc = memcmp(data1, data2, len);
#endif	/*_WIN32*/
    } else {
	rc = memcmp(data1, data2, len);
    }

    return rc;
}

char *
find_file(const char *path1, const char *path2,
    char *buf, off_t len, struct stat *stptr)
{
    int num;

    num = snprintf(buf, --len, "%s", path1);
    if (num < 0 || num > len)
	errmsg(2, F,L, "path overflow: %s", path1);
    buf[len] = '\0';
    if (!stat(buf, stptr)) {
	if (S_ISDIR(stptr->st_mode)) {
	    num = snprintf(buf, len, "%s/%s", path1, base_name(path2));
	    if (num < 0 || num > len)
		errmsg(2, F,L, "path overflow: %s", path1);
	    buf[len] = '\0';
	    if (!stat(buf, stptr) && S_ISREG(stptr->st_mode))
		return buf;
	} else if (S_ISREG(stptr->st_mode)) {
	    return buf;
	}
    }

    buf[0] = '\0';
    return NULL;
}

int
cmp_files(const char *path1, off_t len1, const char *path2, off_t len2)
{
    unsigned char *data1, *data2;
    int rc;

#if defined(_WIN32)
    HANDLE fh1, fh2;
    HANDLE hmap1, hmap2;

    fh1 = CreateFile(path1, GENERIC_READ,
	    FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
	    FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh1 == INVALID_HANDLE_VALUE)
	sys_err(F,L, 2, path1);

    fh2 = CreateFile(path2, GENERIC_READ,
	    FILE_SHARE_READ, NULL, OPEN_EXISTING,
	    FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh2 == INVALID_HANDLE_VALUE)
	sys_err(F,L, 2, path2);

    if (!(hmap1 = CreateFileMapping(fh1, NULL, PAGE_READONLY, 0, 0, NULL)))
	sys_err(F,L, 2, path1);
    if (!(data1 = MapViewOfFile(hmap1, FILE_MAP_COPY, 0, 0, len1)))
	sys_err(F,L, 2, path1);

    if (!(hmap2 = CreateFileMapping(fh2, NULL, PAGE_READONLY, 0, 0, NULL)))
	sys_err(F,L, 2, path2);
    if (!(data2 = MapViewOfFile(hmap2, FILE_MAP_COPY, 0, 0, len2)))
	sys_err(F,L, 2, path2);

    rc = cmp_data(path1, data1, path2, data2, len1);

    if (UnmapViewOfFile(data1) == 0)
	sys_err(F,L, 2, path1);
    if (!CloseHandle(fh1) || !CloseHandle(hmap1))
	sys_err(F,L, 2, path1);

    if (UnmapViewOfFile(data2) == 0)
	sys_err(F,L, 2, path2);
    if (!CloseHandle(fh2) || !CloseHandle(hmap2))
	sys_err(F,L, 2, path2);

#else	/*_WIN32*/
    int fd1, fd2;

    if ((fd1 = open(path1, O_RDONLY)) < 0)
	sys_err(F,L, 2, path1);
    data1 = mmap(0, len1, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd1, 0);
    if (data1 == MAP_FAILED)
	sys_err(F,L, 2, path1);
    if (close(fd1) < 0)
	sys_err(F,L, 2, path1);
    if (madvise(data1, len1, MADV_SEQUENTIAL))
	sys_err(F,L, 0, path1);


    if ((fd2 = open(path2, O_RDONLY)) < 0)
	sys_err(F,L, 2, path2);
    data2 = mmap(0, len2, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd2, 0);
    if (data2 == MAP_FAILED)
	sys_err(F,L, 2, path2);
    if (close(fd2) < 0)
	sys_err(F,L, 2, path2);
    if (madvise(data2, len2, MADV_SEQUENTIAL))
	sys_err(F,L, 0, path2);

    rc = cmp_data(path1, data1, path2, data2, len1);

    if (munmap(data1, len1) < 0)
	sys_err(F,L, 2, path1);
    if (munmap(data2, len2) < 0)
	sys_err(F,L, 2, path2);
#endif	/*_WIN32*/

    return rc;
}

int
main(int argc, char *argv[])
{
    int rc;
    char path1[PATH_MAX], path2[PATH_MAX];
    struct stat stbuf1;
    struct stat stbuf2;
    off_t len1, len2;

    argv++, argc--;

    while (argc > 2 && argv[0][0] == '-' && argv[0][1] && !argv[0][2]) {
	if (argv[0][1] == 'd') {
	    dflag = 1;
	} else if (argv[0][1] == 's') {
	    sflag = 1;
	} else if (argv[0][1] == 'v') {
	    vflag = 1;
	}
	argv++, argc--;
    }

    if (argc != 2)
	usage();

    if (!(find_file(argv[0], argv[1], path1, sizeof(path1), &stbuf1)))
	errmsg(2, F,L, "%s: no such file", argv[0]);

    if (!(find_file(argv[1], argv[0], path2, sizeof(path2), &stbuf2)))
	errmsg(2, F,L, "%s: no such file", argv[1]);

    len1 = stbuf1.st_size;
    len2 = stbuf2.st_size;

    if (len1 != len2) {
	// Files are ipso facto different.
	rc = 1;
    } else if (len1 == 0) {
	// Files are both zero-length.
	rc = 0;
#if !defined(_WIN32)
    } else if (!dflag &&
		(stbuf1.st_dev && stbuf1.st_dev == stbuf2.st_dev) &&
		(stbuf1.st_ino && stbuf1.st_ino == stbuf2.st_ino)) {
	// Files are actually the same file (this test doesn't work
	// on Windows).
	rc = 0;
#endif	/*!_WIN32*/
    } else {
	// Do an actual comparison.
	rc = cmp_files(path1, len1, path2, len2);
    }

    if (!sflag) {
	if (rc) {
	    printf("%s and %s differ\n", path1, path2);
	} else if (vflag) {
	    printf("%s and %s same\n", path1, path2);
	}
    }

    return rc ? 1 : 0;
}
