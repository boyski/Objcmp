/* 
 * Copyright (C) 2006 David Boyce.  All rights reserved.
 * This file based on code written by Tim Tornstrom and purchased
 * via RentACoder.com (Request Id 401892).
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

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h>
#include <io.h>
#include <malloc.h>
#include "sys/types.h"
#include "Unstamp.h"
#else	/*_WIN32*/
#if !defined(BSD)
#include <alloca.h>
#endif
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#endif	/*_WIN32*/

#include <assert.h>
#include <stdlib.h>
#include <time.h>

#define MAKE_PTR(type, a, b) (type)((ULONG_PTR)a + (ULONG_PTR)b)

/* CodeView signatures. */
#define		CV_TYPE_NV09		0x3930424E	// NB09         Debuginfo in EXE
#define		CV_TYPE_NV10		0x3031424E	// NB10         VC 6.0          external PDB 2.0 file
#define		CV_TYPE_NV11		0x3131424E	// NB11         Debuginfo in EXE
#define		CV_TYPE_RSDS		0x53445352	// RSDS         VC .NET         external PDB 7.0 file

/* PDB 2.0 file */
typedef struct t_PDB20 {
    DWORD Signature;
    DWORD Offset;
    DWORD TimeDateStamp;
    DWORD Age;
    BYTE PDBFileName[1];
} PDB20, *PPDB20;

/* PDB 7.0 file */
typedef struct t_PDB70 {
    DWORD Signature;
    DWORD ID_A;
    DWORD ID_B;
    DWORD ID_C;
    DWORD ID_D;
    DWORD Age;
    BYTE PDBFileName[1];
} PDB70, *PPDB70;

/* 64 bit QWORD structure */
typedef struct sQWORD {
    DWORD lo;
    DWORD hi;
} QWORD, *PQWORD;

/* header of metadata tables */
typedef struct t_MetaData_Table_Header {
    DWORD Reserved;		// Always 0
    BYTE MajorVersion;
    BYTE MinorVersion;
    BYTE HeapOffsetSizes;
    BYTE Reserved2;
    QWORD Valid;
    QWORD Sorted;
} METADATA_TABLE_HEADER, *PMETADATA_TABLE_HEADER;

#define	STRING_BITMASK		0x01
#define	GUID_BITMASK		0x02
#define	BLOB_BITMASK		0x04

/* stream information struct */
typedef struct t_Stream_Header {
    DWORD Offset;
    DWORD Size;
    BYTE Name[1];
} STREAM_HEADER, *PSTREAM_HEADER;

/* header of the metadata section */
typedef struct t_MetaData_Header {
    DWORD Signature;		// BSJB
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Unknown1;
    DWORD VersionSize;
    PBYTE VersionString;
    WORD Flags;
    WORD NumStreams;
    PBYTE Streams;
} METADATA_HEADER, *PMETADATA_HEADER;

/* meta data table defines  */
#define MODULE					0
#define TYPEREF					1
#define TYPEDEF					2
#define FIELD					4
#define FIELDDEF				4
#define METHODDEF				6
#define PARAM					8
#define PARAMDEF				8
#define INTERFACEIMPL				9
#define MEMBERREF				10
#define CONSTANT				11
#define CUSTOMATTRIBUTE				12
#define FIELDMARSHAL				13
#define DECLSECURITY				14
#define CLASSLAYOUT				15
#define FIELDLAYOUT				16
#define STANDALONESIG				17
#define EVENTMAP				18
#define EVENT					20
#define PROPERTYMAP				21
#define PROPERTY				23
#define METHODSEMANTICS				24
#define METHODIMPL				25
#define MODULEREF				26
#define TYPESPEC				27
#define IMPLMAP					28
#define FIELDRVA				29
#define ASSEMBLY				32
#define ASSEMBLYPROCESSOR			33
#define ASSEMBLYOS				34
#define ASSEMBLYREF				35
#define ASSEMBLYREFPROCESSOR			36
#define ASSEMBLYREFOS				37
#define FILE					38
#define EXPORTEDTYPE				39
#define MANIFESTRESOURCE			40
#define NESTEDCLASS				41
#define UNUSED					64	//@@

typedef struct t_flagToStr {
    DWORD m_flag;
    LPCSTR m_str;
} FLAGTOSTR, *PFLAGTOSTR;

/* metadata table entry type struct */
typedef struct t_IndexType {
    INT TypeIDs[32];
    BYTE NumIDs;
    BYTE BytesNeeded;

} TYPEINDEX, *PTYPEINDEX;

#define NUM_INDEX_TYPES			30

/* info struct for a metadata table */
typedef struct t_TableInfo {
    DWORD NumRows;
    DWORD RowSize;
    LPCSTR Name;
} TABLE_INFO, *PTABLE_INFO;

/* metadata table entry type enumerations */
enum enum_Types {
    eTypeDef,
    eTypeRef,
    eTypeSpec,
    eFieldDef,
    eParamDef,
    eProperty,
    eMethodDef,
    eInterfaceImpl,
    eMemberRef,
    eModule,
    eEvent,
    eStandAloneSig,
    eModuleRef,
    eAssembly,
    eAssemblyRef,
    eFile,
    eExportedType,
    eManifestResource,
    eTypeDefOrRef,
    eHasConstant,
    eHasCustomAttribute,
    eHasFieldMarshal,
    eHasDeclSecurity,
    eMemberRefParent,
    eHasSemantics,
    eMethodDefOrRef,
    eMemberForwarded,
    eImplementation,
    eCustomAttributeType,
    eResolutionScope,
};

/* Some commonly used globals */
ULONG_PTR g_baseAddr = 0;
PIMAGE_DOS_HEADER g_pDosHeader = NULL;
PIMAGE_NT_HEADERS g_pNTHeader = NULL;
PIMAGE_SECTION_HEADER g_pFirstSection = NULL;
BOOL g_is64bit = FALSE;

PBYTE g_StringsPtr = NULL;
PBYTE g_BlobPtr = NULL;
PBYTE g_GUIDPtr = NULL;
PBYTE g_USPtr = NULL;
PBYTE g_TablesPtr = NULL;

PSTREAM_HEADER g_TablesHdr = NULL;
PSTREAM_HEADER g_StringsHdr = NULL;
PSTREAM_HEADER g_BlobHdr = NULL;
PSTREAM_HEADER g_GUIDHdr = NULL;
PSTREAM_HEADER g_USHdr = NULL;

BYTE g_StringOffsetSize;
BYTE g_GUIDOffsetSize;
BYTE g_BlobOffsetSize;

/* Metadata table information.  65 of them, not all are used */
TABLE_INFO g_tableInfo[] = {
    {0, 0, "Module"}
    ,				// 0
    {0, 0, "TypeRef"}
    ,				// 1
    {0, 0, "TypeDef"}
    ,				// 2
    {0, 0, ""}
    ,
    {0, 0, "Field"}
    ,				// 4
    {0, 0, ""}
    ,
    {0, 0, "MethodDef"}
    ,				// 6
    {0, 0, ""}
    ,
    {0, 0, "Param"}
    ,				// 8
    {0, 0, "InterfaceImpl"}
    ,				// 9
    {0, 0, "MemberRef"}
    ,				// 10
    {0, 0, "Constant"}
    ,				// 11
    {0, 0, "CustomAttribute"}
    ,				// 12
    {0, 0, "FieldMarshal"}
    ,				// 13
    {0, 0, "DeclSecurity"}
    ,				// 14
    {0, 0, "ClassLayout"}
    ,				// 15
    {0, 0, "FieldLayout"}
    ,				// 16
    {0, 0, "StandAloneSig"}
    ,				// 17
    {0, 0, "EventMap"}
    ,				// 18
    {0, 0, ""}
    ,
    {0, 0, "Event"}
    ,				// 20
    {0, 0, "PropertyMap"}
    ,				// 21
    {0, 0, ""}
    ,
    {0, 0, "Property"}
    ,				// 23
    {0, 0, "MethodSemantics"}
    ,				// 24
    {0, 0, "MethodImpl"}
    ,				// 25
    {0, 0, "ModuleRef"}
    ,				// 26
    {0, 0, "TypeSpec"}
    ,				// 27
    {0, 0, "ImplMap"}
    ,				// 28
    {0, 0, "FieldRVA"}
    ,				// 29
    {0, 0, ""}
    ,
    {0, 0, ""}
    ,
    {0, 0, "Assembly"}
    ,				// 32
    {0, 0, "AssemblyProcessor"}
    ,				// 33
    {0, 0, "AssemblyOS"}
    ,				// 34
    {0, 0, "AssemblyRef"}
    ,				// 35
    {0, 0, "AssemblyRefProcessor"}
    ,				// 36
    {0, 0, "AssemblyRefOS"}
    ,				// 37
    {0, 0, "File"}
    ,				// 38
    {0, 0, "ExportedType"}
    ,				// 39
    {0, 0, "ManifestResource"}
    ,				// 40
    {0, 0, "NestedClass"}
    ,				// 41
    {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    ,
    {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    ,
    {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
    , {0, 0, ""}
};

/* Metadata table entry types, matches enums in header*/
TYPEINDEX g_types[] = {
    {{TYPEDEF}
	    , 1, 0}
    ,
    {{TYPEREF}
	    , 1, 0}
    ,
    {{TYPESPEC}
	    , 1, 0}
    ,
    {{FIELDDEF}
	    , 1, 0}
    ,
    {{PARAMDEF}
	    , 1, 0}
    ,
    {{PROPERTY}
	    , 1, 0}
    ,
    {{METHODDEF}
	    , 1, 0}
    ,
    {{INTERFACEIMPL}
	    , 1, 0}
    ,
    {{MEMBERREF}
	    , 1, 0}
    ,
    {{MODULE}
	    , 1, 0}
    ,
    {{EVENT}
	    , 1, 0}
    ,
    {{STANDALONESIG}
	    , 1, 0}
    ,
    {{MODULEREF}
	    , 1, 0}
    ,
    {{ASSEMBLY}
	    , 1, 0}
    ,
    {{ASSEMBLYREF}
	    , 1, 0}
    ,
    {{FILE}
	    , 1, 0}
    ,
    {{EXPORTEDTYPE}
	    , 1, 0}
    ,
    {{MANIFESTRESOURCE}
	    , 1, 0}
    ,
    {{TYPEDEF, TYPEREF, TYPESPEC}
	    , 3, 0}
    ,
    {{FIELDDEF, PARAMDEF, PROPERTY}
	    , 3, 0}
    ,
    {{METHODDEF, FIELDDEF, TYPEREF, TYPEDEF, PARAMDEF, INTERFACEIMPL,
			    MEMBERREF,
			    MODULE, PROPERTY, EVENT, STANDALONESIG, MODULEREF, TYPESPEC,	//PERMISSION??
			    ASSEMBLY, ASSEMBLYREF, FILE, EXPORTEDTYPE,
		    MANIFESTRESOURCE}
	    , 19, 0}
    ,
    {{FIELDDEF, PARAMDEF}
	    , 2, 0}
    ,
    {{TYPEDEF, METHODDEF, ASSEMBLY}
	    , 3, 0}
    ,
    {{TYPEDEF, TYPEREF, MODULEREF, METHODDEF, TYPESPEC}
	    , 5, 0}
    ,
    {{EVENT, PROPERTY}
	    , 2, 0}
    ,
    {{METHODDEF, MEMBERREF}
	    , 2, 0}
    ,
    {{FIELDDEF, METHODDEF}
	    , 2, 0}
    ,
    {{FILE, ASSEMBLYREF, EXPORTEDTYPE}
	    , 2, 0}
    ,
    {{UNUSED, UNUSED, METHODDEF, MEMBERREF, UNUSED}
	    , 5, 0}
    ,
    {{MODULE, MODULEREF, ASSEMBLYREF, TYPEREF}
	    , 4, 0}
};

/* possible debug directory types */
static char *debugType[12] = {
    "IMAGE_DEBUG_TYPE_UNKNOWN",
    "IMAGE_DEBUG_TYPE_COFF",
    "IMAGE_DEBUG_TYPE_CODEVIEW",
    "IMAGE_DEBUG_TYPE_FPO",
    "IMAGE_DEBUG_TYPE_MISC",
    "IMAGE_DEBUG_TYPE_EXCEPTION",
    "IMAGE_DEBUG_TYPE_FIXUP",
    "IMAGE_DEBUG_TYPE_OMAP_TO_SRC",
    "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC",
    "IMAGE_DEBUG_TYPE_BORLAND",
    "IMAGE_DEBUG_TYPE_RESERVED10",
    "IMAGE_DEBUG_TYPE_CLSID"
};

/* All the possible file characteristics */
FLAGTOSTR imgFileFlags[] = {
    {0x0001, "IMAGE_FILE_RELOCS_STRIPPED"}
    ,
    {0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE"}
    ,
    {0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED"}
    ,
    {0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"}
    ,
    {0x0010, "IMAGE_FILE_AGGRESIVE_WS_TRIM"}
    ,
    {0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE"}
    ,
    {0x0080, "IMAGE_FILE_BYTES_REVERSED_LO"}
    ,
    {0x0100, "IMAGE_FILE_32BIT_MACHINE"}
    ,
    {0x0200, "IMAGE_FILE_DEBUG_STRIPPED"}
    ,
    {0x0400, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"}
    ,
    {0x0800, "IMAGE_FILE_NET_RUN_FROM_SWAP"}
    ,
    {0x1000, "IMAGE_FILE_SYSTEM"}
    ,
    {0x2000, "IMAGE_FILE_DLL"}
    ,
    {0x4000, "IMAGE_FILE_UP_SYSTEM_ONLY"}
    ,
    {0x8000, "IMAGE_FILE_BYTES_REVERSED_HI"}
    ,
};

#define NUM_FILE_CHARACTERISTICS		15

/* All the possible data directories */
FLAGTOSTR dataDirs[] = {
    {0, "IMAGE_DIRECTORY_ENTRY_EXPORT"}
    ,
    {1, "IMAGE_DIRECTORY_ENTRY_IMPORT"}
    ,
    {2, "IMAGE_DIRECTORY_ENTRY_RESOURCE"}
    ,
    {3, "IMAGE_DIRECTORY_ENTRY_EXCEPTION"}
    ,
    {4, "IMAGE_DIRECTORY_ENTRY_SECURITY"}
    ,
    {5, "IMAGE_DIRECTORY_ENTRY_BASERELOC"}
    ,
    {6, "IMAGE_DIRECTORY_ENTRY_DEBUG"}
    ,
    {7, "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE"}
    ,
    {8, "IMAGE_DIRECTORY_ENTRY_GLOBALPTR"}
    ,
    {9, "IMAGE_DIRECTORY_ENTRY_TLS"}
    ,
    {10, "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"}
    ,
    {11, "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"}
    ,
    {12, "IMAGE_DIRECTORY_ENTRY_IAT"}
    ,
    {13, "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"}
    ,
    {14, "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"}
    ,
    {15, "UNUSED"}
    ,
};

static PIMAGE_DATA_DIRECTORY get_data_dir(DWORD);
static void read_Module_TableRow(PBYTE *);
static LPVOID rva_to_ptr(DWORD);
static void read_meta_data_header(PMETADATA_HEADER, PBYTE);
static BOOL read_tables(PBYTE);
static BOOL get_stream_pointers(PMETADATA_HEADER, PBYTE);

/**
* Patch the bound import directory
* RET: TRUE if sucess, else FALSE
*/
static BOOL
patch_bound()
{
    PIMAGE_DATA_DIRECTORY pDataDir = NULL;
    PIMAGE_BOUND_IMPORT_DESCRIPTOR pBImportDesc = NULL;
    PIMAGE_BOUND_FORWARDER_REF pForwRef = NULL;
    DWORD i, numForward;
    /* get data directory pointer */
    pDataDir = get_data_dir(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
    if (pDataDir == NULL || pDataDir->Size == 0)
	return FALSE;
    /* get first bound import descriptor. rva_to_ptr? */
    pBImportDesc = MAKE_PTR(PIMAGE_BOUND_IMPORT_DESCRIPTOR, g_baseAddr,
	    pDataDir->VirtualAddress);
    /* patch all import descriptors */
    while (pBImportDesc->TimeDateStamp) {
	pForwRef = MAKE_PTR(PIMAGE_BOUND_FORWARDER_REF, pBImportDesc,
		sizeof(IMAGE_BOUND_FORWARDER_REF));
	numForward = pBImportDesc->NumberOfModuleForwarderRefs;

	/* Patch it! */
	pBImportDesc->TimeDateStamp = 0;
	/* patch any forwarded imports too */
	for (i = 0; i < numForward; i++) {
	    /* Patch it! */
	    pForwRef->TimeDateStamp = 0;

	    pForwRef++;
	    pBImportDesc =
		    MAKE_PTR(PIMAGE_BOUND_IMPORT_DESCRIPTOR, pBImportDesc,
		    sizeof(IMAGE_BOUND_FORWARDER_REF));
	}
	pBImportDesc++;
    }
    return TRUE;
}

/**
* calculate bits needed to represent the number of rows in a table
* IN: 'p_dword' number of rows
* RET: bits needed
*/
static INT
row_bits_needed(DWORD p_dword)
{
    INT i, b = 32;
    for (i = 31; i >= 0; i--, b--) {
	if (p_dword & (1 << i))
	    break;
    }
    return b;
}

/**
* calculate bits needed for encoding. if there are 5 different
* possible indices in a type then we need 3 bits
* IN: 'p_numIndex' number of indices
* RET: bits needed
*/
static INT
enc_bits_needed(BYTE p_numIndex)
{
    INT i;
    for (i = 7; i >= 0; i--) {
	if ((p_numIndex - 1) & (1 << i))
	    return i + 1;
    }
    return 0;
}

/**
* Patch the metadata given the metadata header Used by .NET executables.
* com descriptor is in the .rdata section.
* This function is also called when we are patching an .NET OBJ file
*/
static void
patch_metadata(PMETADATA_HEADER p_metaDataHdr)
{
    METADATA_HEADER MetaHdr;
    /* read metadata header */
    read_meta_data_header(&MetaHdr, (PBYTE) p_metaDataHdr);
    /* read the stream headers and save their pointers */
    get_stream_pointers(&MetaHdr, (PBYTE) p_metaDataHdr);
    /* read all the tables */
    read_tables(g_TablesPtr);
    /* Patch GUIDs! */
    memset(g_GUIDPtr, 0x00, g_GUIDHdr->Size);
}

/**
* Patch the com descriptor. Used by .NET executables.
* com descriptor is in the .rdata section
* RET: TRUE if sucess, else FALSE
*/
static BOOL
patch_com_descriptor()
{
    PIMAGE_DATA_DIRECTORY pDataDir = NULL;
    PIMAGE_COR20_HEADER pComHead = NULL;
    PMETADATA_HEADER pMetaHeadPtr = NULL;

    PCHAR dataPtr = NULL;
    PDWORD dwPtr = NULL;
    /* get data directory pointer */
    pDataDir = get_data_dir(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    if (pDataDir == NULL || pDataDir->Size == 0)
	return FALSE;
    /* get pointer to com runtime header */
    pComHead = (PIMAGE_COR20_HEADER) rva_to_ptr(pDataDir->VirtualAddress);
    if (pComHead == NULL) {
	return FALSE;
    }
    /* get pointer to metadata header */
    pMetaHeadPtr =
	    (PMETADATA_HEADER) rva_to_ptr(pComHead->MetaData.
	    VirtualAddress);
    /* patch the metadata */
    patch_metadata(pMetaHeadPtr);

    return TRUE;
}

/**
* Patch a word of metadata
* IN/OUT: 'p_bytePtr' pointer to metadata
* RET: word read
*/
static WORD
patch_word(PBYTE * p_bytePtr, WORD p_value)
{
    PWORD pWord = (PWORD) (*p_bytePtr);
    WORD word = *pWord;

    *pWord = p_value;

    (*p_bytePtr) = (*p_bytePtr) + 2;
    return word;
}

/**
* Patch a CodeView debug directory
* IN: 'p_pCV' pointer to CV dir
*/
static void
patch_debug_cv(LPVOID p_pCV)
{
    DWORD signature;
    signature = *((LPDWORD) p_pCV);

    if (signature == CV_TYPE_NV10) {
	PPDB20 info = (PPDB20) p_pCV;
	/* Patch it */
	info->TimeDateStamp = 0;
	info->Age = 0;
    } else if (signature == CV_TYPE_RSDS) {
	PPDB70 info = (PPDB70) p_pCV;
	/* Patch it */
	info->ID_A = info->ID_B = info->ID_C = info->ID_D = 0;
	info->Age = 0;
    } else if (signature == CV_TYPE_NV09) {
    } else if (signature == CV_TYPE_NV11) {
    } else {
	/* Unknown CodeView signature */
    }
}

/**
* Patch the debug directory
* RET: TRUE if sucess, else FALSE
*/
static BOOL
patch_debug()
{
    PIMAGE_DATA_DIRECTORY pDataDir;
    PIMAGE_DEBUG_DIRECTORY pDebugDir;
    DWORD num, i;

    /* get data directory entry */
    pDataDir = get_data_dir(IMAGE_DIRECTORY_ENTRY_DEBUG);
    if (pDataDir == NULL || pDataDir->Size == 0)
	return FALSE;
    /* get pointer to first debug directory */
    pDebugDir =
	    (PIMAGE_DEBUG_DIRECTORY) rva_to_ptr(pDataDir->VirtualAddress);
    if (pDebugDir == NULL)
	return FALSE;
    /* Iterate through all the debug directories */
    num = pDataDir->Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (i = 0; i < num; i++, pDebugDir++) {
	/* Patch it */
	pDebugDir->TimeDateStamp = 0;
	pDebugDir->MajorVersion = pDebugDir->MinorVersion = 0;

	switch (pDebugDir->Type) {
	    case IMAGE_DEBUG_TYPE_CODEVIEW:
		patch_debug_cv(MAKE_PTR(PVOID, g_baseAddr,
				pDebugDir->PointerToRawData));
		break;
	    case IMAGE_DEBUG_TYPE_COFF:
		break;
	    default:
		break;
	};
    }

    return TRUE;
}

/**
* Patch the export table
* RET: TRUE if sucess, else FALSE
*/
static BOOL
patch_export()
{
    PIMAGE_DATA_DIRECTORY pDataDir;
    PIMAGE_EXPORT_DIRECTORY pExportDir;

    /* get pointer to data directory */
    pDataDir = get_data_dir(IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (pDataDir == NULL || pDataDir->Size == 0)
	return FALSE;
    /* get pointer to export directory */
    pExportDir =
	    (PIMAGE_EXPORT_DIRECTORY) rva_to_ptr(pDataDir->VirtualAddress);
    if (pExportDir == NULL) {
	return FALSE;
    }
    /* Patch it! */
    pExportDir->TimeDateStamp = 0;
    pExportDir->MajorVersion = pExportDir->MinorVersion = 0;

    return TRUE;
}

/**
* Patch the import table
* RET: TRUE if sucess, else FALSE
*/
static BOOL
patch_import()
{
    PIMAGE_DATA_DIRECTORY pDataDir = NULL;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;
    /* get data directory entry */
    pDataDir = get_data_dir(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (pDataDir == NULL || pDataDir->Size == 0)
	return FALSE;
    /* get pointer to first import descriptor */
    pImportDesc =
	    (PIMAGE_IMPORT_DESCRIPTOR) rva_to_ptr(pDataDir->
	    VirtualAddress);
    if (pImportDesc == NULL) {
	return FALSE;
    }
    /* patch all import descriptors until a NULL entry is found */
    while (pImportDesc->Characteristics) {
	// Patch it!
	pImportDesc->TimeDateStamp = 0;
	pImportDesc++;
    }
    return TRUE;
}

/**
* Patch the load configuration directory
* RET: TRUE if sucess, else FALSE
*/
static BOOL
patch_loadconfig()
{
    PIMAGE_DATA_DIRECTORY pDataDir;
    PIMAGE_LOAD_CONFIG_DIRECTORY pCfgDir;

    /* get data directroy entry */
    pDataDir = get_data_dir(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if (pDataDir == NULL || pDataDir->Size == 0)
	return FALSE;
    /* get load config directory pointer */
    pCfgDir =
	    (PIMAGE_LOAD_CONFIG_DIRECTORY) rva_to_ptr(pDataDir->
	    VirtualAddress);
    if (pCfgDir == NULL) {
	return FALSE;
    }

    /* Patch it! */
    pCfgDir->TimeDateStamp = 0;
    pCfgDir->MajorVersion = pCfgDir->MinorVersion = 0;

    return TRUE;
}

/**
* Patch the export table
* RET: TRUE if sucess, else FALSE
*/
static BOOL
patch_obj(PIMAGE_FILE_HEADER p_pFileHdr)
{
    PIMAGE_SECTION_HEADER pSection;
    INT i;

    p_pFileHdr->TimeDateStamp = 0;

    /* Get first section */
    pSection = MAKE_PTR(PIMAGE_SECTION_HEADER,
	    p_pFileHdr->SizeOfOptionalHeader, (p_pFileHdr + 1));

    for (i = 0; i < p_pFileHdr->NumberOfSections; i++) {
	/* check if its CV4 type or symbol information */
	if (_strcmpi(pSection[i].Name, ".debug$T") == 0 ||
		_strcmpi(pSection[i].Name, ".debug$S") == 0) {
	    PBYTE pByte = MAKE_PTR(LPVOID, pSection[i].PointerToRawData,
		    g_baseAddr);
	    /*
	     * Zero out the whole section because no docs on it can
	     * be found at this moment. It's only debug info and it
	     * won't end up in the final EXE anyway, so no harm done.
	     */
	    memset(pByte, 0x00, pSection[i].SizeOfRawData);

	    /* Check if it's a metadata header .NET OBJs */
	} else if (_strcmpi(pSection[i].Name, ".cormeta") == 0) {
	    PMETADATA_HEADER pMetaDataHdr = MAKE_PTR(PMETADATA_HEADER,
		    pSection[i].PointerToRawData,
		    g_baseAddr);
	    patch_metadata(pMetaDataHdr);
	}
    }

    return TRUE;
}

/**
* Read a byte of metadata
* IN/OUT: 'p_bytePtr' pointer to metadata
* RET: byte read
*/
static BYTE
read_byte(PBYTE * p_bytePtr)
{
    BYTE byte = *((PBYTE) (*p_bytePtr));
    (*p_bytePtr)++;
    return byte;
}

/**
* Read a word of metadata
* IN/OUT: 'p_bytePtr' pointer to metadata
* RET: word read
*/
static WORD
read_word(PBYTE * p_bytePtr)
{
    WORD word = *((PWORD) (*p_bytePtr));
    (*p_bytePtr) = (*p_bytePtr) + 2;
    return word;
}

/**
* read a dword of metadata
* IN/OUT: 'p_bytePtr' pointer to metadata
* RET: dword read
*/
static DWORD
read_dword(PBYTE * p_bytePtr)
{
    DWORD dword = *((PDWORD) (*p_bytePtr));
    (*p_bytePtr) = (*p_bytePtr) + 4;
    return dword;
}

/**
* Read an index using the calculated size of the index type
* IN: 'p_typeID' index type id
* IN/OUT: 'p_bytePtr' pointer to metadata
* RET: value read. either a WORD or DWORD
*/
static DWORD
read_index(INT p_typeID, PBYTE * p_bytePtr)
{
    DWORD numToRead = g_types[p_typeID].BytesNeeded;
    if (numToRead == 2)
	return read_word(p_bytePtr);
    else if (numToRead == 4)
	return read_dword(p_bytePtr);
    return 0;
}

/**
* Read a stream header
* IN/OUT: 'p_bytePtr' pointer to metadata
* RET: pointer to stream header read
*/
static PSTREAM_HEADER
read_stream_header(PBYTE * p_bytePtr)
{
    PSTREAM_HEADER headPtr = (PSTREAM_HEADER) (*p_bytePtr);
    size_t size;
    (*p_bytePtr) += 8;
    size = strlen(&headPtr->Name[0]);
    size += (4 - (size % 4));
    (*p_bytePtr) += size;
    return headPtr;
}

/**
* Read a string from string heap
* IN: 'p_offset' offset into string heap
* RET: string at offset
*/
static PCSTR
read_heap_string(DWORD p_offset)
{
    return (g_StringsPtr + p_offset);
}

/**
* Read a string offset
* IN/OUT: 'p_bytePtr' pointer to metadata
* RET: offset read.
*/
static DWORD
read_string_offset(PBYTE * p_bytePtr)
{
    return (DWORD) (g_StringOffsetSize ==
	    2) ? read_word(p_bytePtr) : read_dword(p_bytePtr);
}

/**
* Read a blob offset
* IN/OUT: 'p_bytePtr' pointer to metadata
* RET: offset read.
*/
static DWORD
read_blob_offset(PBYTE * p_bytePtr)
{
    return (DWORD) (g_BlobOffsetSize ==
	    2) ? read_word(p_bytePtr) : read_dword(p_bytePtr);
}

/**
* Read a GUID offset
* IN/OUT: 'p_bytePtr' pointer to metadata
* RET: offset read.
*/
static DWORD
read_GUID_offset(PBYTE * p_bytePtr)
{
    return (DWORD) (g_GUIDOffsetSize ==
	    2) ? read_word(p_bytePtr) : read_dword(p_bytePtr);
}

/**
* Seek a number of bytes into metadata
* IN/OUT: 'p_bytePtr' pointer to metadata
*/
static void
seek_bytes(PBYTE * p_bytePtr, INT p_num)
{
    (*p_bytePtr) = (*p_bytePtr) + p_num;
}

/**
* The following functions are for reading rows of certain tables
* and they all have the same number of arguments.
* IN/OUT: 'p_bytePtr' pointer to metadata
*/
static void
read_Module_TableRow(PBYTE * p_bytePtr)
{
    WORD Generation;
    DWORD Name;
    DWORD Mvid;
    DWORD EncId;
    DWORD EncBaseId;

    Generation = read_word(p_bytePtr);
    Name = read_string_offset(p_bytePtr);
    Mvid = read_GUID_offset(p_bytePtr);
    EncId = read_GUID_offset(p_bytePtr);
    EncBaseId = read_GUID_offset(p_bytePtr);
}

static void
read_TypeRef_TableRow(PBYTE * p_bytePtr)
{
    DWORD ResolutionScope;
    DWORD TypeName;
    DWORD TypeNamespace;

    ResolutionScope = read_index(eResolutionScope, p_bytePtr);
    TypeName = read_string_offset(p_bytePtr);
    TypeNamespace = read_string_offset(p_bytePtr);
}

static void
read_TypeDef_TableRow(PBYTE * p_bytePtr)
{
    DWORD Flags;
    DWORD TypeName;
    DWORD TypeNamespace;
    DWORD Extends;
    DWORD FieldList;
    DWORD MethodList;

    Flags = read_dword(p_bytePtr);
    TypeName = read_string_offset(p_bytePtr);
    TypeNamespace = read_string_offset(p_bytePtr);
    Extends = read_index(eTypeDefOrRef, p_bytePtr);
    FieldList = read_index(eFieldDef, p_bytePtr);
    MethodList = read_index(eMethodDef, p_bytePtr);
}

static void
read_Field_TableRow(PBYTE * p_bytePtr)
{
    DWORD Flags;
    DWORD Name;
    DWORD Signature;

    Flags = read_word(p_bytePtr);
    Name = read_string_offset(p_bytePtr);
    Signature = read_blob_offset(p_bytePtr);
}

static void
read_MethodDef_TableRow(PBYTE * p_bytePtr)
{
    DWORD RVA;
    DWORD ImplFlags;
    DWORD Flags;
    DWORD Name;
    DWORD Signature;
    DWORD ParamList;

    RVA = read_dword(p_bytePtr);
    ImplFlags = read_word(p_bytePtr);
    Flags = read_word(p_bytePtr);
    Name = read_string_offset(p_bytePtr);
    Signature = read_blob_offset(p_bytePtr);
    ParamList = read_index(eParamDef, p_bytePtr);
}

static void
read_Param_TableRow(PBYTE * p_bytePtr)
{
    WORD Flags;
    WORD Sequence;
    DWORD Name;

    Flags = read_word(p_bytePtr);
    Sequence = read_word(p_bytePtr);
    Name = read_string_offset(p_bytePtr);
}

static void
read_InterfaceImpl_TableRow(PBYTE * p_bytePtr)
{
    DWORD Class;
    DWORD Interface;

    Class = read_index(eTypeDef, p_bytePtr);
    Interface = read_index(eTypeDefOrRef, p_bytePtr);
}

static void
read_MemberRef_TableRow(PBYTE * p_bytePtr)
{
    DWORD Class;
    DWORD Name;
    DWORD Signature;

    Class = read_index(eMemberRefParent, p_bytePtr);
    Name = read_string_offset(p_bytePtr);
    Signature = read_blob_offset(p_bytePtr);
}

static void
read_Constant_TableRow(PBYTE * p_bytePtr)
{
    WORD Type;
    DWORD Parent;
    DWORD Value;

    Type = read_word(p_bytePtr);
    Parent = read_index(eHasConstant, p_bytePtr);
    Value = read_blob_offset(p_bytePtr);
}

static void
read_CustomAttribute_TableRow(PBYTE * p_bytePtr)
{
    DWORD Parent;
    DWORD Type;
    DWORD Value;

    Parent = read_index(eHasCustomAttribute, p_bytePtr);
    Type = read_index(eCustomAttributeType, p_bytePtr);
    Value = read_blob_offset(p_bytePtr);
}

static void
read_FieldMarshal_TableRow(PBYTE * p_bytePtr)
{
    DWORD Parent;
    DWORD NativeType;

    Parent = read_index(eHasFieldMarshal, p_bytePtr);
    NativeType = read_blob_offset(p_bytePtr);
}

static void
read_DeclSecurity_TableRow(PBYTE * p_bytePtr)
{
    WORD Action;
    DWORD Parent;
    DWORD PermissionSet;

    Action = read_word(p_bytePtr);
    Parent = read_index(eHasDeclSecurity, p_bytePtr);
    PermissionSet = read_blob_offset(p_bytePtr);
}

static void
read_ClassLayout_TableRow(PBYTE * p_bytePtr)
{
    WORD PackingSize;
    DWORD ClassSize;
    DWORD Parent;

    PackingSize = read_word(p_bytePtr);
    ClassSize = read_dword(p_bytePtr);
    Parent = read_index(eTypeDef, p_bytePtr);
}

static void
read_FieldLayout_TableRow(PBYTE * p_bytePtr)
{
    DWORD Offset;
    DWORD Field;

    Offset = read_dword(p_bytePtr);
    Field = read_index(eFieldDef, p_bytePtr);
}

static void
read_StandAloneSig_TableRow(PBYTE * p_bytePtr)
{
    DWORD Signature;

    Signature = read_blob_offset(p_bytePtr);
}

static void
read_EventMap_TableRow(PBYTE * p_bytePtr)
{
    DWORD Parent;
    DWORD EventList;

    Parent = read_index(eTypeDef, p_bytePtr);
    EventList = read_index(eEvent, p_bytePtr);
}

static void
read_Event_TableRow(PBYTE * p_bytePtr)
{
    DWORD EventFlags;
    DWORD Name;
    DWORD EventType;

    EventFlags = read_word(p_bytePtr);
    Name = read_string_offset(p_bytePtr);
    EventType = read_index(eTypeDefOrRef, p_bytePtr);
}

static void
read_PropertyMap_TableRow(PBYTE * p_bytePtr)
{
    DWORD Parent;
    DWORD PropertyList;

    Parent = read_index(eTypeDef, p_bytePtr);
    PropertyList = read_index(eProperty, p_bytePtr);
}

static void
read_Property_TableRow(PBYTE * p_bytePtr)
{
    WORD Flags;
    DWORD Name;
    DWORD Type;

    Flags = read_word(p_bytePtr);
    Name = read_string_offset(p_bytePtr);
    Type = read_blob_offset(p_bytePtr);
}

static void
read_MethodSemantics_TableRow(PBYTE * p_bytePtr)
{
    WORD Semantics;
    DWORD Method;
    DWORD Association;

    Semantics = read_word(p_bytePtr);
    Method = read_index(eMethodDef, p_bytePtr);
    Association = read_index(eHasSemantics, p_bytePtr);
}

static void
read_MethodImpl_TableRow(PBYTE * p_bytePtr)
{
    DWORD Class;
    DWORD MethodBody;
    DWORD MethodDeclaration;

    Class = read_index(eTypeDef, p_bytePtr);
    MethodBody = read_index(eMethodDefOrRef, p_bytePtr);
    MethodDeclaration = read_index(eMethodDefOrRef, p_bytePtr);
}

static void
read_ModuleRef_TableRow(PBYTE * p_bytePtr)
{
    DWORD Name;

    Name = read_string_offset(p_bytePtr);
}

static void
read_TypeSpec_TableRow(PBYTE * p_bytePtr)
{
    DWORD Signature;

    Signature = read_blob_offset(p_bytePtr);
}

static void
read_ImplMap_TableRow(PBYTE * p_bytePtr)
{
    WORD MappingFlags;
    DWORD MemberForwarded;
    DWORD ImportName;
    DWORD ImportScope;

    MappingFlags = read_word(p_bytePtr);
    MemberForwarded = read_index(eMemberForwarded, p_bytePtr);
    ImportName = read_string_offset(p_bytePtr);
    ImportScope = read_index(eModuleRef, p_bytePtr);
}

static void
read_FieldRVA_TableRow(PBYTE * p_bytePtr)
{
    DWORD RVA;
    DWORD Field;

    RVA = read_dword(p_bytePtr);
    Field = read_index(eFieldDef, p_bytePtr);
}

static void
read_Assembly_TableRow(PBYTE * p_bytePtr)
{
    DWORD HashAlgId;
    WORD MajorVersion;
    WORD MinorVersion;
    WORD BuildNumber;
    WORD RevisionNumber;
    DWORD Flags;
    DWORD PublicKey;
    DWORD Name;
    DWORD Culture;

    HashAlgId = read_dword(p_bytePtr);
    MajorVersion = read_word(p_bytePtr);
    MinorVersion = read_word(p_bytePtr);
    BuildNumber = patch_word(p_bytePtr, 0x0000);	// Patch this!
    RevisionNumber = patch_word(p_bytePtr, 0x0000);	// Patch this!
    Flags = read_dword(p_bytePtr);
    PublicKey = read_blob_offset(p_bytePtr);
    Name = read_string_offset(p_bytePtr);
    Culture = read_string_offset(p_bytePtr);
}

static void
read_AssemblyProcessor_TableRow(PBYTE * p_bytePtr)
{
    DWORD Processor;
    Processor = read_dword(p_bytePtr);
}

static void
read_AssemblyOS_TableRow(PBYTE * p_bytePtr)
{
    DWORD OSPlatformID;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;

    OSPlatformID = read_dword(p_bytePtr);
    OSMajorVersion = read_dword(p_bytePtr);
    OSMinorVersion = read_dword(p_bytePtr);
}

static void
read_AssemblyRef_TableRow(PBYTE * p_bytePtr)
{
    WORD MajorVersion;
    WORD MinorVersion;
    WORD BuildNumber;
    WORD RevisionNumber;
    DWORD Flags;
    DWORD PublicKeyOrToken;
    DWORD Name;
    DWORD Culture;
    DWORD HashValue;

    MajorVersion = read_word(p_bytePtr);
    MinorVersion = read_word(p_bytePtr);
    BuildNumber = read_word(p_bytePtr);
    RevisionNumber = read_word(p_bytePtr);
    Flags = read_dword(p_bytePtr);
    PublicKeyOrToken = read_blob_offset(p_bytePtr);
    Name = read_string_offset(p_bytePtr);
    Culture = read_string_offset(p_bytePtr);
    HashValue = read_blob_offset(p_bytePtr);
}

static void
read_File_TableRow(PBYTE * p_bytePtr)
{
    DWORD Flags;
    DWORD Name;
    DWORD HashValue;

    Flags = read_dword(p_bytePtr);
    Name = read_string_offset(p_bytePtr);
    HashValue = read_blob_offset(p_bytePtr);
}

static void
read_ExportedType_TableRow(PBYTE * p_bytePtr)
{
    DWORD Flags;
    DWORD TypeDefId;
    DWORD TypeName;
    DWORD TypeNamespace;
    DWORD Implementation;

    Flags = read_dword(p_bytePtr);
    TypeDefId = read_dword(p_bytePtr);
    TypeName = read_string_offset(p_bytePtr);
    TypeNamespace = read_string_offset(p_bytePtr);
    Implementation = read_index(eImplementation, p_bytePtr);
}

static void
read_ManifestResource_TableRow(PBYTE * p_bytePtr)
{
    DWORD Offset;
    DWORD Flags;
    DWORD Name;
    DWORD Implementation;

    Offset = read_dword(p_bytePtr);
    Flags = read_dword(p_bytePtr);
    Name = read_string_offset(p_bytePtr);
    Implementation = read_index(eImplementation, p_bytePtr);
}

static void
read_NestedClass_TableRow(PBYTE * p_bytePtr)
{
    DWORD NestedClass;
    DWORD EnclosingClass;

    NestedClass = read_index(eTypeDef, p_bytePtr);
    EnclosingClass = read_index(eTypeDef, p_bytePtr);
}

/**
* Calculate the size of a certain index type 
* IN/OUT: 'p_pType' pointer type to calculate size of
*/
static void
calc_index_size(PTYPEINDEX p_pType)
{
    INT i, num = 0;
    for (i = 0; i < p_pType->NumIDs; i++) {
	INT n = row_bits_needed(g_tableInfo[p_pType->TypeIDs[i]].NumRows);
	if (n > num)
	    num = n;
    }
    num += enc_bits_needed(p_pType->NumIDs);
    p_pType->BytesNeeded = (num > 16) ? 4 : 2;
}

/**
* Precalculate all our index type sizes when we know
* the number of rows in each table.
*/
static void
precalc_type_sizes()
{
    INT i;
    for (i = 0; i < NUM_INDEX_TYPES; i++)
	calc_index_size(&g_types[i]);
}

/**
* calculate  number of tables
* IN: 'p_Valid' 64 bits, 1 for existing table, 0 for non existing
* RET: number of tables
*/
static BYTE
calc_num_tables(QWORD p_Valid)
{
    INT i, c = 0;
    for (i = 0; i < 32; i++) {
	if ((p_Valid.hi & (1 << i)))
	    c++;
	if ((p_Valid.lo & (1 << i)))
	    c++;
    }
    return c;
}

/**
* check if a table with a certain id exists in an exe
* IN: 'p_Valid' 64 bits, 1 for existing table, 0 for non existing
* IN: 'i' id of table to check
* RET: TRUE if exists, else FALSE
*/
static BOOL
is_valid_table(QWORD p_Valid, INT i)
{
    return (i < 32) ? ((p_Valid.lo & (1 << i)) !=
	    0) : ((p_Valid.hi & (1 << (i - 32))) != 0);
}

/**
* Read all the tables. phew. patch the ones that needs patching.
* IN: 'p_TablesPtr' pointer to start of tables
*/
static BOOL
read_tables(PBYTE p_TablesPtr)
{
    PMETADATA_TABLE_HEADER pTableHead;
    PDWORD pRowSizePtr;
    PBYTE pTables;
    DWORD i;
    /* get pointer to metadata table header */
    pTableHead = (PMETADATA_TABLE_HEADER) p_TablesPtr;
    /* get number of bytes that the heap offsets are */
    g_StringOffsetSize =
	    (pTableHead->HeapOffsetSizes & STRING_BITMASK) ? 4 : 2;
    g_GUIDOffsetSize =
	    (pTableHead->HeapOffsetSizes & GUID_BITMASK) ? 4 : 2;
    g_BlobOffsetSize =
	    (pTableHead->HeapOffsetSizes & BLOB_BITMASK) ? 4 : 2;
    /* get pointer to array of section sizes */
    pRowSizePtr =
	    MAKE_PTR(PDWORD, pTableHead, sizeof(METADATA_TABLE_HEADER));
    for (i = 0; i < 64; i++) {
	if (is_valid_table(pTableHead->Valid, i))
	    g_tableInfo[i].NumRows = *pRowSizePtr++;
    }
    /* calculate the sizes of the metadata table entry types */
    precalc_type_sizes();
    /* get pointer to the tables */
    pTables = (PBYTE) pRowSizePtr;
    /* Read the tables. */
    for (i = 0; i < 64; i++) {
	/* check if this table exists in file */
	if (is_valid_table(pTableHead->Valid, i)) {
	    DWORD row;

	    if (strcmp(g_tableInfo[i].Name, "Module") == 0) {
		read_Module_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "TypeRef") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_TypeRef_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "TypeDef") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_TypeDef_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "Field") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_Field_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "MethodDef") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_MethodDef_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "Param") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_Param_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "InterfaceImpl") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_InterfaceImpl_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "MemberRef") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_MemberRef_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "Constant") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_Constant_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "CustomAttribute") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_CustomAttribute_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "FieldMarshal") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_FieldMarshal_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "DeclSecurity") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_DeclSecurity_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "ClassLayout") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_ClassLayout_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "FieldLayout") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_FieldLayout_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "StandAloneSig") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_StandAloneSig_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "EventMap") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_EventMap_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "Event") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_Event_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "PropertyMap") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_PropertyMap_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "Property") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_Property_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "MethodSemantics") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_MethodSemantics_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "MethodImpl") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_MethodImpl_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "ModuleRef") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_ModuleRef_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "TypeSpec") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_TypeSpec_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "ImplMap") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_ImplMap_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "FieldRVA") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_FieldRVA_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "Assembly") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_Assembly_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name,
			    "AssemblyProcessor") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_AssemblyProcessor_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "AssemblyOS") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_AssemblyOS_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "AssemblyRef") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_AssemblyRef_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "File") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_File_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "ExportedType") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_ExportedType_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name,
			    "ManifestResource") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_ManifestResource_TableRow(&pTables);
	    } else if (strcmp(g_tableInfo[i].Name, "NestedClass") == 0) {
		for (row = 0; row < g_tableInfo[i].NumRows; row++)
		    read_NestedClass_TableRow(&pTables);
	    }
	}
    }
    return TRUE;
}

/**
* read stream headers and save pointers in global variables
* IN: 'p_metaHdr' metadata header
* IN: 'p_metaHdrStart' pointer to start of meta header.
*		cant use the one of 'p_metaHdr' since its a copy of the mapped one.
*/
static BOOL
get_stream_pointers(PMETADATA_HEADER p_metaHdr, PBYTE p_metaHdrStart)
{
    INT i;
    PBYTE streamPtr = p_metaHdr->Streams;

    for (i = 0; i < p_metaHdr->NumStreams; i++) {
	PSTREAM_HEADER head;
	head = read_stream_header(&streamPtr);

	/* Seems like the table is called #- in OBJ files and #~ in EXEs */
	if (strcmp(&head->Name[0], "#~") == 0
		|| strcmp(&head->Name[0], "#-") == 0) {
	    g_TablesHdr = head;
	    g_TablesPtr = MAKE_PTR(PBYTE, p_metaHdrStart, head->Offset);
	} else if (strcmp(&head->Name[0], "#Strings") == 0) {
	    g_StringsHdr = head;
	    g_StringsPtr = MAKE_PTR(PBYTE, p_metaHdrStart, head->Offset);
	} else if (strcmp(&head->Name[0], "#US") == 0) {
	    g_USHdr = head;
	    g_USPtr = MAKE_PTR(PBYTE, p_metaHdrStart, head->Offset);
	} else if (strcmp(&head->Name[0], "#GUID") == 0) {
	    g_GUIDHdr = head;
	    g_GUIDPtr = MAKE_PTR(PBYTE, p_metaHdrStart, head->Offset);
	} else if (strcmp(&head->Name[0], "#Blob") == 0) {
	    g_BlobHdr = head;
	    g_BlobPtr = MAKE_PTR(PBYTE, p_metaHdrStart, head->Offset);
	}
    }

    return TRUE;
}

/**
* read the metadata header
* OUT: 'p_metaHead' pointer to header to fill
* IN: 'p_startHead' pointer to start of metadata header
*/
static void
read_meta_data_header(PMETADATA_HEADER p_metaHead, PBYTE p_startHead)
{
    p_metaHead->Signature = read_dword(&p_startHead);
    p_metaHead->MajorVersion = read_word(&p_startHead);
    p_metaHead->MinorVersion = read_word(&p_startHead);
    p_metaHead->Unknown1 = read_dword(&p_startHead);
    p_metaHead->VersionSize = read_dword(&p_startHead);
    p_metaHead->VersionString = p_startHead;

    seek_bytes(&p_startHead, p_metaHead->VersionSize);

    p_metaHead->Flags = read_word(&p_startHead);
    p_metaHead->NumStreams = read_word(&p_startHead);
    p_metaHead->Streams = p_startHead;
}

/**
* Find the section containing a certain RVA
* IN: 'p_RVA' relative virtual address
* RET: pointer to section, or NULL
*/
static PIMAGE_SECTION_HEADER
find_section(DWORD p_RVA)
{
    DWORD i;
    PIMAGE_SECTION_HEADER pSectionHead = NULL;

    assert(g_pFirstSection);
    assert(g_pNTHeader);

    pSectionHead = g_pFirstSection;
    for (i = 0; i < g_pNTHeader->FileHeader.NumberOfSections;
	    i++, pSectionHead++) {
	DWORD startRVA = pSectionHead->VirtualAddress;
	DWORD endRVA =
		pSectionHead->VirtualAddress +
		pSectionHead->Misc.VirtualSize;
	if (p_RVA >= startRVA && p_RVA < endRVA)
	    return pSectionHead;
    }
    return NULL;
}

/**
* Convert an RVA to a usuable pointer
* IN: 'p_RVA' relative virtual address
* RET: a pointer, or NULL
*/
static LPVOID
rva_to_ptr(DWORD p_RVA)
{
    PIMAGE_SECTION_HEADER pSection;
    pSection = find_section(p_RVA);
    if (pSection == NULL)
	return NULL;
    return MAKE_PTR(LPVOID, g_baseAddr,
	    (p_RVA - (pSection->VirtualAddress -
			    pSection->PointerToRawData)));
}

/**
* Get a pointer to a data directory of the PE
* IN: 'p_DataDir' the ID of the dir we want
* RET: pointer to data directory
*/
static PIMAGE_DATA_DIRECTORY
get_data_dir(DWORD p_DataDir)
{
    PIMAGE_DATA_DIRECTORY pDataDir = NULL;

    assert(p_DataDir < IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    assert(g_baseAddr && g_pDosHeader);

    if (g_is64bit) {
	PIMAGE_NT_HEADERS64 pNTHead =
		MAKE_PTR(PIMAGE_NT_HEADERS64, g_baseAddr,
		g_pDosHeader->e_lfanew);
	pDataDir = &pNTHead->OptionalHeader.DataDirectory[p_DataDir];
    } else {
	PIMAGE_NT_HEADERS32 pNTHead =
		MAKE_PTR(PIMAGE_NT_HEADERS32, g_baseAddr,
		g_pDosHeader->e_lfanew);
	pDataDir = &pNTHead->OptionalHeader.DataDirectory[p_DataDir];
    }
    return pDataDir;
}

/**
* Patch the optional header. At the same time find out if this is a
* 32 or 64 bit file.
* IN: 'p_pNTHeader' pointer to the nt header structure
* RET: TRUE if this is a 64 bit file, else FALSE
*/
static BOOL
patch_optional_header(PIMAGE_NT_HEADERS p_pNTHeader)
{
    BOOL is64Bit = FALSE;
    /* Check if its 64 or 32 bit */
    is64Bit = (p_pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
	    || (p_pNTHeader->FileHeader.Machine ==
	    IMAGE_FILE_MACHINE_ALPHA64)
	    || (p_pNTHeader->FileHeader.Machine ==
	    IMAGE_FILE_MACHINE_AMD64);
    /* Patch it! */
    p_pNTHeader->FileHeader.TimeDateStamp = 0;
    if (is64Bit == TRUE) {
	PIMAGE_NT_HEADERS64 pNT64 = (PIMAGE_NT_HEADERS64) p_pNTHeader;
	/* Patch it! */
	pNT64->OptionalHeader.CheckSum = 0;
    } else {
	PIMAGE_NT_HEADERS32 pNT32 = (PIMAGE_NT_HEADERS32) p_pNTHeader;
	/* Patch it! */
	pNT32->OptionalHeader.CheckSum = 0;
    }
    return is64Bit;
}

/**
* Patch resource directories recursivly
* IN: 'p_pResDir' directory to patch
* IN: 'p_resBase' base address of resources
* IN: 'p_level' the current directory depth we are at
*/
static void
patch_res_dir(PIMAGE_RESOURCE_DIRECTORY p_pResDir, ULONG_PTR p_resBase,
	INT p_level)
{
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry;
    DWORD numEntries, i;
    static WORD rootID;

    /* Patch it! */
    /* Seems only to be filled with unique info in VB EXEs ? */
    p_pResDir->TimeDateStamp = 0;

    p_pResDir->MajorVersion = p_pResDir->MinorVersion = 0;

    /* calculate total number of entries in this directory */
    numEntries = p_pResDir->NumberOfIdEntries +
	    p_pResDir->NumberOfNamedEntries;
    /* get pointer to first entry */
    pEntry = MAKE_PTR(PIMAGE_RESOURCE_DIRECTORY_ENTRY,
	    p_pResDir, sizeof(IMAGE_RESOURCE_DIRECTORY));
    /* iterate trough entries */
    for (i = 0; i < numEntries; i++, pEntry++) {
	if (p_level == 0)
	    rootID = pEntry->Id;
	/* if entry is a directroy then patch recurse */
	if (pEntry->DataIsDirectory != 0) {
	    PIMAGE_RESOURCE_DIRECTORY pDir =
		    MAKE_PTR(PIMAGE_RESOURCE_DIRECTORY, p_resBase,
		    pEntry->OffsetToDirectory);
	    patch_res_dir(pDir, p_resBase, p_level + 1);
	} else {
	    /* if its an data entry then check if we want to patch it */
	    if (rootID == (WORD) RT_VERSION) {
		PBYTE pResData = NULL;
		PIMAGE_RESOURCE_DATA_ENTRY pResEntry;
		pResEntry = MAKE_PTR(PIMAGE_RESOURCE_DATA_ENTRY, p_resBase,
			pEntry->OffsetToData);
		pResData = (PBYTE) rva_to_ptr(pResEntry->OffsetToData);

		/* Patch it! */
		memset(pResData, 0x00, pResEntry->Size);
	    }
	}
    }
}

/**
* Patch the resource directory
* RET: TRUE if sucess, else FALSE
*/
static BOOL
patch_resource()
{
    PIMAGE_DATA_DIRECTORY pDataDir = NULL;
    PIMAGE_RESOURCE_DIRECTORY pResDir = NULL;
    /* get data directory entry for resources */
    pDataDir = get_data_dir(IMAGE_DIRECTORY_ENTRY_RESOURCE);
    if (pDataDir == NULL || pDataDir->Size == 0)
	return FALSE;
    /* get first resource directory */
    pResDir =
	    (PIMAGE_RESOURCE_DIRECTORY) rva_to_ptr(pDataDir->
	    VirtualAddress);
    if (pResDir == NULL) {
	return FALSE;
    }

    /* recurse the directory structure */
    patch_res_dir(pResDir, (ULONG_PTR) pResDir, 0);

    return TRUE;
}

off_t
get_pe_size(PIMAGE_FILE_HEADER pFileHdr)
{
    unsigned long pe_size;
    IMAGE_OPTIONAL_HEADER *pOptHeader;
    IMAGE_SECTION_HEADER *pSecHdr;
    unsigned long i;

    if (g_is64bit) {
	// TODO - get 64-bit version working.
	assert(0);
    } else {
	PIMAGE_NT_HEADERS32 pNT32;

	pNT32 = (PIMAGE_NT_HEADERS32) g_pNTHeader;
	pOptHeader = &(pNT32->OptionalHeader);
	pSecHdr = (IMAGE_SECTION_HEADER *)(((LPBYTE)pOptHeader) + 
	    pFileHdr->SizeOfOptionalHeader);
    }

    pSecHdr = (PIMAGE_SECTION_HEADER)(((PUCHAR)pOptHeader) +
	pFileHdr->SizeOfOptionalHeader);

    pe_size = pOptHeader->SizeOfHeaders;

    for (i = 0; i < pFileHdr->NumberOfSections; i++, pSecHdr++) {
	unsigned long nSection;
	
	nSection = pSecHdr->PointerToRawData + pSecHdr->SizeOfRawData;
	if (nSection > pe_size)
	    pe_size = nSection;
    }

    return pe_size;
}

/**
* Patch a memory mapped file
* IN: 'p_baseAddress' base address of mapping
*/
int
unstamp(void *p_baseAddress, off_t *p_len)
{
    PIMAGE_FILE_HEADER pFileHdr;

    g_baseAddr = (ULONG_PTR) p_baseAddress;
    g_pDosHeader = (PIMAGE_DOS_HEADER) g_baseAddr;

    if (g_pDosHeader->e_magic == IMAGE_DOS_SIGNATURE) {

	pFileHdr = 
	    (PIMAGE_FILE_HEADER)(((LPBYTE)p_baseAddress) + 
	    g_pDosHeader->e_lfanew + 
	    sizeof(IMAGE_NT_SIGNATURE));

	g_pNTHeader = MAKE_PTR(PIMAGE_NT_HEADERS, g_baseAddr,
		g_pDosHeader->e_lfanew);

	g_pDosHeader->e_csum = 0;

	g_is64bit = patch_optional_header(g_pNTHeader);
	if (g_pNTHeader->Signature == IMAGE_NT_SIGNATURE) {
	    /*
	     * If any baggage was appended to the PE file, e.g
	     * version stamping or data for a self-extracting program,
	     * clip it out of the area to be examined by shrinking
	     * the length back to the file's "official" size.
	     */
	    if (p_len && !g_is64bit)
		*p_len = get_pe_size(pFileHdr);

	    /* save a pointer to the first section in PE for later use */
	    g_pFirstSection = MAKE_PTR(PIMAGE_SECTION_HEADER, g_pNTHeader,
		    (g_is64bit ? sizeof(IMAGE_NT_HEADERS64) :
			    sizeof(IMAGE_NT_HEADERS32))
		    );

	    __try {
		/* Patch sections known to contain timestamps */
		patch_export();
		patch_import();	/* DateTimeStamp unused? */
		patch_resource();	/* DateTimeStamp unused? */
		patch_bound();
		patch_debug();
		patch_loadconfig();
		patch_com_descriptor();	/* For .NET EXEs */
	    }
	    __except(1) {
		return -1;
	    }
	}
    } else {
	pFileHdr = (PIMAGE_FILE_HEADER) p_baseAddress;

	/* Check if it's an OBJ file */
	if (pFileHdr->Machine == IMAGE_FILE_MACHINE_I386 ||
		pFileHdr->Machine == IMAGE_FILE_MACHINE_ALPHA ||
		pFileHdr->Machine == IMAGE_FILE_MACHINE_IA64 ||
		pFileHdr->Machine == IMAGE_FILE_MACHINE_ALPHA64 ||
		pFileHdr->Machine == IMAGE_FILE_MACHINE_AMD64) {
	    __try {
		patch_obj(pFileHdr);
	    }
	    __except(1) {
		return -1;
	    }
	}
    }

    return 0;
}
