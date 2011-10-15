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

#ifndef	ZIPFILE_H__
#define	ZIPFILE_H__

#ifdef	__cplusplus
extern "C" {
#endif	/*__cplusplus*/

/* Return nonzero if the data looks like a ZIP archive. */
int is_zip_file(const void *, off_t);

/* Return zero if the two input ZIP archives contain the same files in the same
   order. */
int cmp_zip_files(const void *, const void *, off_t);

#ifdef	__cplusplus
}
#endif	/*__cplusplus*/

#endif	/*ZIPFILE_H__*/
