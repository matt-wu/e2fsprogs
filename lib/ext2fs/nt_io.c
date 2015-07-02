/*
 * nt_io.c --- This is the Nt I/O interface to the I/O manager.
 *
 * Implements a one-block write-through cache.
 *
 * Copyright (C) 1993, 1994, 1995 Theodore Ts'o.
 * Copyright (C) 1998 Andrey Shedel (andreys@ns.cr.cyco.com)
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Library
 * General Public License, version 2.
 * %End-Header%
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


//
// I need some warnings to disable...
//


#pragma warning(disable:4514) // unreferenced inline function has been removed
#pragma warning(push,4)

#pragma warning(disable:4201) // nonstandard extension used : nameless struct/union)
#pragma warning(disable:4214) // nonstandard extension used : bit field types other than int
#pragma warning(disable:4115) // named type definition in parentheses

#include <err.h>
#include <fcntl.h>
#include <ntifs.h>
#include <ntdddisk.h>
#include <ntstatus.h>

#pragma warning(pop)

#define __try
#define __leave       goto errorout
#define __finally     errorout:

#define DEBUG(format, ...) do {                 \
            /* DEBUG(format, __VA_ARGS__); */  \
        } while(0)

//
// Some native APIs.
//

NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosError(
    IN NTSTATUS Status
   );

NTSYSAPI
NTSTATUS
NTAPI
NtClose(
    IN HANDLE Handle
   );


NTSYSAPI
NTSTATUS
NTAPI
NtOpenFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions
    );

NTSYSAPI
NTSTATUS
NTAPI
NtFlushBuffersFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock
   );


NTSYSAPI
NTSTATUS
NTAPI
NtReadFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtWriteFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtDeviceIoControlFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG IoControlCode,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtFsControlFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG IoControlCode,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength
    );


NTSYSAPI
NTSTATUS
NTAPI
NtDelayExecution(
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Interval
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationFile(
    IN HANDLE  FileHandle,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    OUT PVOID  FileInformation,
    IN ULONG  Length,
    IN FILE_INFORMATION_CLASS  FileInformationClass
    );


//
// useful macros
//
#ifndef BooleanFlagOn
#define BooleanFlagOn(Flags,SingleFlag) ((BOOLEAN)((((Flags) & (SingleFlag)) != 0)))
#endif

//
// Include Win32 error codes.
//

#include <winerror.h>

//
// standard stuff
//

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>

#include <sys/types.h>
#include "ext2_fs.h"
#include <err.h>

#include "et/com_err.h"
#include "ext2fs/ext2fs.h"
#include "ext2fs/ext2_err.h"




//
// For checking structure magic numbers...
//


#define EXT2_CHECK_MAGIC(struct, code) \
	  if ((struct)->magic != (code)) return (code)

#define EXT2_ET_MAGIC_NT_IO_CHANNEL  0x10ed

//
// file structure
//

typedef struct file {

        HANDLE          f_handle;
        unsigned int    f_flags;
        int             f_fd;
        mode_t          f_mode;
        __u32           f_count;

        __int64         f_size;

        PWCHAR          f_u_name;
        PUCHAR          f_name;

        DISK_GEOMETRY   f_d_geometry;
        PARTITION_INFORMATION f_d_partinfo;
        FILE_FS_SIZE_INFORMATION f_v_fssize;

        BOOLEAN         f_device; /* disk device */
        BOOLEAN         f_volume; /* volume deivce */

} file_t;

//
// Private data block
//

typedef struct _NT_PRIVATE_DATA {
	int	   magic;
	int	   Flags;
    file_t *file;
	PCHAR  Buffer;
	__int64 BufferBlockNumber;
	ULONG  BufferSize;
    __int64 Offset;

#if 0
    PVOLUME_DISK_EXTENTS Extent;
    DISK_GEOMETRY DrvGeometry;
    PARTITION_INFORMATION PartInfo;
#endif

	BOOLEAN OpenedReadonly;
	BOOLEAN Written;
}NT_PRIVATE_DATA, *PNT_PRIVATE_DATA;


//
// Standard interface prototypes
//

static errcode_t nt_open(const char *name, int flags, io_channel *channel);
static errcode_t nt_close(io_channel channel);
static errcode_t nt_set_blksize(io_channel channel, int blksize);
static errcode_t nt_read_blk(io_channel channel, unsigned long block,
			       int count, void *data);
static errcode_t nt_write_blk(io_channel channel, unsigned long block,
				int count, const void *data);
static errcode_t nt_read_blk64(io_channel channel, unsigned __int64 block,
			       int count, void *data);
static errcode_t nt_write_blk64(io_channel channel, unsigned __int64 block,
				int count, const void *data);
static errcode_t nt_flush(io_channel channel);

static struct struct_io_manager struct_nt_manager = {
	.magic		    = EXT2_ET_MAGIC_IO_MANAGER,
	.name		    = "NT I/O Manager",
	.open		    = nt_open,
	.close		    = nt_close,
	.set_blksize	= nt_set_blksize,
	.read_blk	    = nt_read_blk,
	.write_blk	    = nt_write_blk,
	.read_blk64	    = nt_read_blk64,
	.write_blk64    = nt_write_blk64,
	.flush		    = nt_flush
};



//
// This is a code to convert Win32 errors to unix err
//

typedef struct {
	ULONG WinError;
	int errcode;
}ERROR_ENTRY;

static ERROR_ENTRY ErrorTable[] = {
        {  ERROR_INVALID_FUNCTION,       EINVAL    },
        {  ERROR_FILE_NOT_FOUND,         ENOENT    },
        {  ERROR_PATH_NOT_FOUND,         ENOENT    },
        {  ERROR_TOO_MANY_OPEN_FILES,    EMFILE    },
        {  ERROR_ACCESS_DENIED,          EACCES    },
        {  ERROR_INVALID_HANDLE,         EBADF     },
        {  ERROR_ARENA_TRASHED,          ENOMEM    },
        {  ERROR_NOT_ENOUGH_MEMORY,      ENOMEM    },
        {  ERROR_INVALID_BLOCK,          ENOMEM    },
        {  ERROR_BAD_ENVIRONMENT,        E2BIG     },
        {  ERROR_BAD_FORMAT,             ENOEXEC   },
        {  ERROR_INVALID_ACCESS,         EINVAL    },
        {  ERROR_INVALID_DATA,           EINVAL    },
        {  ERROR_INVALID_DRIVE,          ENOENT    },
        {  ERROR_CURRENT_DIRECTORY,      EACCES    },
        {  ERROR_NOT_SAME_DEVICE,        EXDEV     },
        {  ERROR_NO_MORE_FILES,          ENOENT    },
        {  ERROR_LOCK_VIOLATION,         EACCES    },
        {  ERROR_BAD_NETPATH,            ENOENT    },
        {  ERROR_NETWORK_ACCESS_DENIED,  EACCES    },
        {  ERROR_BAD_NET_NAME,           ENOENT    },
        {  ERROR_FILE_EXISTS,            EEXIST    },
        {  ERROR_CANNOT_MAKE,            EACCES    },
        {  ERROR_FAIL_I24,               EACCES    },
        {  ERROR_INVALID_PARAMETER,      EINVAL    },
        {  ERROR_NO_PROC_SLOTS,          EAGAIN    },
        {  ERROR_DRIVE_LOCKED,           EACCES    },
        {  ERROR_BROKEN_PIPE,            EPIPE     },
        {  ERROR_DISK_FULL,              ENOSPC    },
        {  ERROR_INVALID_TARGET_HANDLE,  EBADF     },
        {  ERROR_INVALID_HANDLE,         EINVAL    },
        {  ERROR_WAIT_NO_CHILDREN,       ECHILD    },
        {  ERROR_CHILD_NOT_COMPLETE,     ECHILD    },
        {  ERROR_DIRECT_ACCESS_HANDLE,   EBADF     },
        {  ERROR_NEGATIVE_SEEK,          EINVAL    },
        {  ERROR_SEEK_ON_DEVICE,         EACCES    },
        {  ERROR_DIR_NOT_EMPTY,          ENOTEMPTY },
        {  ERROR_NOT_LOCKED,             EACCES    },
        {  ERROR_BAD_PATHNAME,           ENOENT    },
        {  ERROR_MAX_THRDS_REACHED,      EAGAIN    },
        {  ERROR_LOCK_FAILED,            EACCES    },
        {  ERROR_ALREADY_EXISTS,         EEXIST    },
        {  ERROR_FILENAME_EXCED_RANGE,   ENOENT    },
        {  ERROR_NESTING_NOT_ALLOWED,    EAGAIN    },
        {  ERROR_NOT_ENOUGH_QUOTA,       ENOMEM    }
};




static
unsigned
_MapDosError (
    IN ULONG WinError
   )
{
	int i;

	//
	// Lookup
	//

	for (i = 0; i < (sizeof(ErrorTable)/sizeof(ErrorTable[0])); ++i)
	{
		if (WinError == ErrorTable[i].WinError)
		{
			return ErrorTable[i].errcode;
		}
	}

	//
	// not in table. Check ranges
	//

	if ((WinError >= ERROR_WRITE_PROTECT) &&
		(WinError <= ERROR_SHARING_BUFFER_EXCEEDED))
	{
		return EACCES;
	}
	else if ((WinError >= ERROR_INVALID_STARTING_CODESEG) &&
			 (WinError <= ERROR_INFLOOP_IN_RELOC_CHAIN))
	{
		return ENOEXEC;
	}
	else
	{
		return EINVAL;
	}
}







//
// Function to map NT status to dos error.
//

static
__inline
unsigned
_MapNtStatus(
    IN NTSTATUS Status
   )
{
	return _MapDosError(RtlNtStatusToDosError(Status));
}




/*
 * global opened files or devices
 *
 * only support 16 files opened concurrently
 */
#define MAX_OPENED_FILES (16)
static file_t *g_files_array[MAX_OPENED_FILES];

const CHAR *nt_native_prefix[] = {
        "\\??\\", "\\DosDevices\\",
        "\\SystemRoot\\", "\\Device\\",
        NULL
};

#define is_drv_letter_valid(x) (((x) >= 0 && (x) <= 9) || \
                ( ((x)|0x20) <= 'z' && ((x)|0x20) >= 'a'))

#ifndef is_flag_set
#define is_flag_set(x,f) (((x)&(f))==(f))
#endif

#ifndef set_flag
#define set_flag(x,f)    ((x) |= (f))
#endif

#ifndef clear_flag
#define clear_flag(x,f)  ((x) &= ~(f))
#endif

/*
 * Universal memory allocator API
 */
enum nt_alloc_flags {
        /* allocation is not allowed to block */
        NT_ALLOC_ATOMIC = 0x1,
        /* allocation is allowed to block */
        NT_ALLOC_WAIT   = 0x2,
        /* allocation should return zeroed memory */
        NT_ALLOC_ZERO   = 0x4,
        /* allocation is allowed to call file-system code to free/clean
         * memory */
        NT_ALLOC_FS     = 0x8,
        /* allocation is allowed to do io to free/clean memory */
        NT_ALLOC_IO     = 0x10,
        /* don't report allocation failure to the console */
        NT_ALLOC_NOWARN = 0x20,
        /* standard allocator flag combination */
        NT_ALLOC_STD    = NT_ALLOC_FS | NT_ALLOC_IO,
        NT_ALLOC_USER   = NT_ALLOC_WAIT | NT_ALLOC_FS | NT_ALLOC_IO,
};

static void * nt_alloc(size_t nr_bytes, u_int32_t flags)
{
    void *ptr = malloc(nr_bytes);

    if (ptr && flags & NT_ALLOC_ZERO) {
        memset(ptr, 0, nr_bytes);
    }

    return ptr;
}


static void nt_free (void *buf)
{
    free(buf);
}


static NTSTATUS
filp_dev_query(HANDLE Handle,  PDISK_GEOMETRY DrvGeometry, PPARTITION_INFORMATION PartInfo)
{
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;

    Status = NtDeviceIoControlFile(Handle, NULL, NULL, NULL, &Iosb,
                                   IOCTL_DISK_GET_DRIVE_GEOMETRY,
                                   DrvGeometry, sizeof(DISK_GEOMETRY),
                                   DrvGeometry, sizeof(DISK_GEOMETRY));
    if (!NT_SUCCESS(Status)) {
        goto errorout;
    }

    Status = NtDeviceIoControlFile(Handle, NULL, NULL, NULL, &Iosb,
                                   IOCTL_DISK_GET_PARTITION_INFO,
                                   PartInfo, sizeof(PARTITION_INFORMATION),
                                   PartInfo, sizeof(PARTITION_INFORMATION));
    if (!NT_SUCCESS(Status)) {
        goto errorout;
    }

errorout:

    return Status;
}

static NTSTATUS
filp_vol_query(HANDLE Handle,  PFILE_FS_SIZE_INFORMATION FsSizeInfo)
{
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    Status = NtQueryVolumeInformationFile(
                        Handle, &Iosb, FsSizeInfo,
                        sizeof(FILE_FS_SIZE_INFORMATION),
                        FileFsSizeInformation
                        );
    if (!NT_SUCCESS(Status)) {
        goto errorout;
    }

errorout:

    return Status;
}


/*
 * filp_close
 *     To close the opened file and release the filp structure
 *
 * Arguments:
 *   fp:   the pointer of the file_t strcture
 *
 * Return Value:
 *   ZERO: on success
 *   Non-Zero: on failure
 *
 * Notes: 
 *   N/A
 */

static int
filp_close (file_t * fp)
{
    NTSTATUS status;

    ASSERT (fp != NULL);
    ASSERT (fp->f_handle != NULL);

    DEBUG("filp_close: %s/%x closed.\n", fp->f_name, fp->f_handle);

    if (--fp->f_count > 0)
        return 0;

    if (fp->f_fd >= 8192 && fp->f_fd < 8192 + MAX_OPENED_FILES)
        g_files_array[fp->f_fd - 8192] = NULL;
 
    /* release the file handle */
    status = NtClose (fp->f_handle);
    ASSERT (NT_SUCCESS (status));

    /* free the memory of temporary name strings */
    if (fp->f_name)
        nt_free (fp->f_name);
    if (fp->f_u_name)
        nt_free (fp->f_u_name);
        
    /* free the file flip structure */
    nt_free (fp);
    return 0;
}

/*
 * filp_open
 *     To open or create a file in kernel mode
 *
 * Arguments:
 *   name:  name of the file to be opened or created, no dos path prefix
 *   flags: open/creation attribute options
 *   mode:  access mode/permission to open or create
 *   err:   error code
 *
 * Return Value:
 *   the pointer to the file_t or NULL if it fails
 *
 * Notes: 
 *   N/A
 */

static file_t *
filp_open (const char *name, int flags, int mode,  errcode_t *err)
{
    file_t *fp = NULL;

    NTSTATUS Status;

    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatus;
    ACCESS_MASK DesiredAccess;
    ULONG CreateDisposition;
    ULONG ShareAccess;
    ULONG CreateOptions;
    FILE_STANDARD_INFORMATION StandardInfo;

    USHORT NameLength = 0;
    USHORT PrefixLength = 0;

    UNICODE_STRING UnicodeName;
    PWCHAR UnicodeString = NULL;
    
    ANSI_STRING AnsiName;
    PUCHAR AnsiString = NULL;


    ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;

    /* resolve flags & modes */
    if (is_flag_set (flags, O_WRONLY)) {
        DesiredAccess = (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE);
    } else if (is_flag_set (flags, O_RDWR)) {
        DesiredAccess = (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE);
    } else {
        DesiredAccess = (GENERIC_READ | SYNCHRONIZE);
    }

    if (is_flag_set (flags, EXT2_FLAG_EXCLUSIVE)) {
        ShareAccess = 0;
    }

    if (is_flag_set (flags, O_CREAT)) {
        if (is_flag_set (flags, O_EXCL)) {
            CreateDisposition = FILE_CREATE;
        } else {
            CreateDisposition = FILE_OPEN_IF;
        }
    } else {
        CreateDisposition = FILE_OPEN;
    }

    if (is_flag_set (flags, O_TRUNC)) {
        if (is_flag_set (flags, O_EXCL)) {
            CreateDisposition = FILE_OVERWRITE;
        } else {
            CreateDisposition = FILE_OVERWRITE_IF;
        }
    }

     CreateOptions = FILE_SYNCHRONOUS_IO_NONALERT;

    if (is_flag_set (flags, O_DIRECTORY)) {
        set_flag (CreateOptions, FILE_DIRECTORY_FILE);
    }

    if (is_flag_set (flags, O_SYNC)) {
        set_flag (CreateOptions, FILE_WRITE_THROUGH);
    }

    if (is_flag_set (flags, O_DIRECT)) {
        set_flag (CreateOptions, FILE_NO_INTERMEDIATE_BUFFERING);
    }

    /* Initialize the unicode path name for the specified file */
    NameLength = (USHORT) strlen (name);

    /* Check file & path name */
    if (name[0] != '\\') {
        if (NameLength < 1 || name[1] != ':' ||
            !is_drv_letter_valid (name[0])) {
            /* invalid file path name */
            if (err)
                *err = EINVAL;
            return NULL;
        }
        PrefixLength = (USHORT) strlen (nt_native_prefix[0]);
    } else {
        int i, j;

        for (i = 0; nt_native_prefix[i] != NULL; i++) {
            j = strlen (nt_native_prefix[i]);
            if (NameLength > j &&
                _strnicmp (nt_native_prefix[i], name, j) == 0) {
                break;
            }
        }
        if (i >= 4) {
            if (err)
                *err = EINVAL;
            return NULL;
        }
    }

    AnsiString =  nt_alloc (sizeof(CHAR) * (NameLength+PrefixLength+1),
                             NT_ALLOC_ZERO);
    if (NULL == AnsiString) {
        if (err)
            *err = ENOMEM;
        return NULL;
    }

    if (PrefixLength) {
        RtlCopyMemory (&AnsiString[0], nt_native_prefix[0],
                       PrefixLength);
    }

    RtlCopyMemory (&AnsiString[PrefixLength], name, NameLength);
    NameLength += PrefixLength;
    AnsiName.MaximumLength = NameLength + 1;
    AnsiName.Length = NameLength;
    AnsiName.Buffer = AnsiString;

    int i;
    for (i = 0; i < MAX_OPENED_FILES; i++) {
        fp = g_files_array[i];
        if (fp && strlen(AnsiString) == strlen(fp->f_name) &&
            0 == _strnicmp(fp->f_name, AnsiString, strlen(AnsiString))) {
            fp->f_count += 1;
            nt_free(AnsiString);
            return fp;
        }
    }
    fp = NULL;


    UnicodeString = nt_alloc (sizeof(WCHAR) * (NameLength+PrefixLength+1),
                               NT_ALLOC_ZERO);
    if (NULL == UnicodeString) {
        if (err)
            *err = ENOMEM;
        nt_free (AnsiString);
            return NULL;
    }

    UnicodeName.MaximumLength = (NameLength + 1) * sizeof (WCHAR);
    UnicodeName.Length = 0;
    UnicodeName.Buffer = (PWSTR) UnicodeString;
    RtlAnsiStringToUnicodeString (&UnicodeName, &AnsiName, FALSE);

    /* Setup the object attributes structure for the file. */
    InitializeObjectAttributes (&ObjectAttributes,
                                &UnicodeName,
                                OBJ_CASE_INSENSITIVE, NULL, NULL);

retry:

    /* Now to open or create the file now */
    Status = NtCreateFile (&FileHandle,
                            DesiredAccess,
                            &ObjectAttributes,
                            &IoStatus,
                            0,
                            FILE_ATTRIBUTE_NORMAL,
                            ShareAccess,
                            CreateDisposition, CreateOptions, NULL, 0);

    if (FileHandle == 0 || FileHandle == (HANDLE)-1) {
        if (ShareAccess != 0) {
            Status = STATUS_ACCESS_DENIED;
        } else {
            ShareAccess =  FILE_SHARE_READ |  FILE_SHARE_WRITE;
            goto retry;
        }
    }

    /* Check the returned status of IoStatus... */
    if (!NT_SUCCESS (Status)) {
        DEBUG("filp_open: failed to open %s (flag=%xh %xh).\n", AnsiString, flags, Status);

        if (err)
            *err = _MapDosError(IoStatus.Status);
        nt_free (UnicodeString);
        nt_free (AnsiString);
        return NULL;
    }

    /* Allocate the file_t: libcfs file object */
    fp = nt_alloc (sizeof (file_t), NT_ALLOC_ZERO);
    if (NULL == fp) {
        Status = NtClose (FileHandle);
        ASSERT (NT_SUCCESS (Status));
        if (err)
            *err = ENOMEM;
        nt_free (UnicodeString);
        nt_free (AnsiString);
        return NULL;
    }

    fp->f_handle = FileHandle;
    fp->f_flags = flags;
    fp->f_mode = (mode_t) mode;
    fp->f_count = 1;
    fp->f_name = AnsiString;
    fp->f_u_name = UnicodeString;

    Status = filp_dev_query(FileHandle, &fp->f_d_geometry, &fp->f_d_partinfo);
    if (NT_SUCCESS(Status)) {

        fp->f_device = TRUE;
        fp->f_size = fp->f_d_partinfo.PartitionLength.QuadPart;
        if (fp->f_size == 0) {
    	    fp->f_size = (__int64)fp->f_d_geometry.BytesPerSector *
				fp->f_d_geometry.SectorsPerTrack *
				fp->f_d_geometry.TracksPerCylinder *
				fp->f_d_geometry.Cylinders.QuadPart;
        }

    } else {

        Status = NtQueryInformationFile(FileHandle, &IoStatus,
                                &StandardInfo, sizeof(StandardInfo),
                                FileStandardInformation);
        if (NT_SUCCESS(Status)) {
            fp->f_size = StandardInfo.EndOfFile.QuadPart;
            fp->f_d_geometry.BytesPerSector = 512;
            fp->f_d_geometry.TracksPerCylinder = 2;
            fp->f_d_geometry.SectorsPerTrack = 32;
            fp->f_d_geometry.Cylinders.QuadPart = fp->f_size  / 512 / 32 / 2;
        } else {
            Status = filp_vol_query(FileHandle, &fp->f_v_fssize);
            if (NT_SUCCESS(Status)) {
                fp->f_volume = TRUE;
                fp->f_size = fp->f_v_fssize.TotalAllocationUnits.QuadPart;
                fp->f_size = fp->f_size * fp->f_v_fssize.BytesPerSector *
                             fp->f_v_fssize.SectorsPerAllocationUnit;            
                fp->f_d_geometry.BytesPerSector = fp->f_v_fssize.BytesPerSector;
                fp->f_d_geometry.TracksPerCylinder = 1;
                fp->f_d_geometry.SectorsPerTrack = fp->f_v_fssize.SectorsPerAllocationUnit;
                fp->f_d_geometry.Cylinders.QuadPart = fp->f_v_fssize.TotalAllocationUnits.QuadPart;
            }
        }
    }

    for (i = 0; i < MAX_OPENED_FILES; i++) {
        if (NULL == g_files_array[i])
            break;
    }
    if (i >= MAX_OPENED_FILES) {
        filp_close(fp);
        if (err)
            *err = EMFILE;
        return NULL;
    }
    g_files_array[i] = fp;
    fp->f_fd = i + 8192;

    if (err)
        *err = 0;

    DEBUG("filp_open: %s opened (flag=%xh %xh).\n", fp->f_name, flags, fp->f_handle);
    return fp;
}




//
// Flush device
//

static NTSTATUS filp_flush(file_t *fp)
{
	IO_STATUS_BLOCK iosb;
    return NtFlushBuffersFile(fp->f_handle, &iosb);
}


//
// lock drive
//

static NTSTATUS filp_lock(file_t *fp)
{
	IO_STATUS_BLOCK iosb;
    if (fp->f_device | fp->f_volume)
	    return NtFsControlFile(fp->f_handle, 0, 0, 0, &iosb, FSCTL_LOCK_VOLUME, 0, 0, 0, 0);
    return STATUS_SUCCESS;
}


//
// unlock drive
//

static NTSTATUS filp_unlock(file_t *fp)
{
	IO_STATUS_BLOCK iosb;
    if (fp->f_device | fp->f_volume)
    	return NtFsControlFile(fp->f_handle, 0, 0, 0, &iosb, FSCTL_UNLOCK_VOLUME, 0, 0, 0, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS filp_dismount(file_t *fp)
{
	IO_STATUS_BLOCK iosb;
    if (fp->f_device | fp->f_volume)
    	return NtFsControlFile(fp->f_handle, 0, 0, 0, &iosb, FSCTL_DISMOUNT_VOLUME, 0, 0, 0, 0);
    return STATUS_SUCCESS;
}


//
// is mounted
//

static BOOLEAN filp_is_mounted(file_t *fp)
{
	IO_STATUS_BLOCK iosb;
    if (fp->f_device | fp->f_volume) {
	    NtFsControlFile(fp->f_handle, 0, 0, 0, &iosb, FSCTL_IS_VOLUME_MOUNTED, 0, 0, 0, 0);
        return (BOOLEAN)(STATUS_SUCCESS == iosb.Status);
    }

    return FALSE;
}


//
// Make NT name from any recognized name
//

static PCSTR filp_build_name(IN PCSTR Device, IN PSTR NormalizedDeviceNameBuffer)
{
	int PartitionNumber = -1;
	UCHAR DiskNumber;
	PSTR p;


	//
	// Do not try to parse NT name
	//

	if('\\' == *Device)
		return Device;


    //
    // Driver Letter or a path: X: or X:\...
    //

    if (':' == *(Device + 1) || 
        (('a' <= (*Device | 0x20) ) &&
         ('z' >= (*Device | 0x20))) ) {

        strcpy(NormalizedDeviceNameBuffer, "\\DosDevices\\");
	    strcat(NormalizedDeviceNameBuffer, Device);
            return NormalizedDeviceNameBuffer;
    }

	//
	// Strip leading '/dev/' if any
	//

	if(('/' == *(Device)) &&
		('d' == (*(Device + 1) | 0x20)) &&
		('e' == (*(Device + 2) | 0x20)) &&
		('v' == (*(Device + 3) | 0x20)) &&
		('/' == *(Device + 4) ))
	{
		Device += 5;
	}

	if('\0' == *Device)
	{
		return NULL;
	}


	//
	// forms: sda[n], hda[n], fd[n]
	//

	if('d' != (*(Device + 1) | 0x20))
	{
		return NULL;
	}

	if('h' == (*Device | 0x20) || 's' == (*Device | 0x20))
	{
		if (  ((*(Device + 2) | 0x20) < 'a') || ((*(Device + 2) | 0x20) > 'z') ||
               (*(Device + 3) <= '0') || (*(Device + 3) > '9') ||
             ((*(Device + 4) != '\0') && ((*(Device + 4) < '0') || (*(Device + 4) > '9')))
           )
		{
			return NULL;
		}

		DiskNumber = (UCHAR)((*(Device + 2) | 0x20) - 'a');

		if(*(Device + 3) != '\0')
		{
			PartitionNumber = atoi(Device + 3);
		}

	}
	else if('f' == *Device)
	{
		//
		// 3-d letted should be a digit.
		//

		if((*(Device + 3) != '\0') ||
		   (*(Device + 2) < '0') || (*(Device + 2) > '9'))
		{
			return NULL;
		}

		DiskNumber = (UCHAR)(*(Device + 2) - '0');

	}
	else
	{
		//
		// invalid prefix
		//

		return NULL;
	}



	//
	// Prefix
	//

	strcpy(NormalizedDeviceNameBuffer, "\\Device\\");

	//
	// Media name
	//

	switch(*Device | 0x20)
	{

	case 'f':
		strcat(NormalizedDeviceNameBuffer, "Floppy");
		break;

	case 'h':
    case 's':
		strcat(NormalizedDeviceNameBuffer, "Harddisk");
		break;
	}


	p = NormalizedDeviceNameBuffer + strlen(NormalizedDeviceNameBuffer);
    if (DiskNumber > 9)
        *p++ = '0' + DiskNumber / 10;
	*p = '0' + DiskNumber % 10;


	//
	// Partition nr.
	//

	if(PartitionNumber >= 0)
	{
		strcat(NormalizedDeviceNameBuffer, "\\Partition0");

		p = NormalizedDeviceNameBuffer + strlen(NormalizedDeviceNameBuffer) - 1;
        if (PartitionNumber > 9)
            *p++ = '0' +  PartitionNumber/10;
		*p = '0' +  PartitionNumber % 10;
	}

    DEBUG("Device %s mapped to %s.\n", Device, NormalizedDeviceNameBuffer);
	return NormalizedDeviceNameBuffer;
}


//
// Open device by name.
//

static file_t *filp_open_device(const char *name, int flags, mode_t mode, errcode_t *err)
{
    file_t *fp = NULL;
	NTSTATUS status;
    CHAR devname[1024] = {0};


	if(NULL == name)
	{
		//
		// Set not found
		//

		if(ARGUMENT_PRESENT(err))
			*err = ENOENT;

		return fp;
	}


	//
	// Make name
	//

	name = filp_build_name(name, devname);

	if(NULL == name)
	{
		//
		// Set not found
		//

		if(ARGUMENT_PRESENT(err))
			*err = ENOENT;

		return fp;
	}

    
    //
	// Try to open it
	//

    fp = filp_open(name, flags, mode, err);

	return fp;
}


//
// Raw block io. Sets dos err
//

static
BOOLEAN filp_read(file_t *fp, LARGE_INTEGER offset,
                  ULONG bytes, void *buffer, errcode_t *err)
{
	IO_STATUS_BLOCK iosb = {0};
	NTSTATUS        status;

    DEBUG("filp_read: reading %lu bytes from %llu of %s.\n",
            bytes, offset.QuadPart, fp->f_name);


	//
	// Should be aligned
	//

	ASSERT(0 == (bytes % fp->f_d_geometry.BytesPerSector));
	ASSERT(0 == (Offset.LowPart % fp->f_d_geometry.BytesPerSector));


	//
	// perform io
	//
	status = NtReadFile(fp->f_handle, NULL, NULL, NULL,
	 		            &iosb, (PVOID)buffer, bytes,
                        &offset, NULL);

	//
	// translate error
	//

    if (status == STATUS_SUCCESS)
	{
        DEBUG("filp_read: read %lu bytes from %llu of %s.\n",
                (ULONG)iosb.Information, offset.QuadPart, fp->f_name);
        if (err)
		    *err = 0;
		return TRUE;
	}

    DEBUG("filp_read: failed to read %s(%xh) err: %xh\n",
            fp->f_name, fp->f_handle, status);
    if (err)
	    *err = _MapNtStatus(status);

	return FALSE;
}

static
BOOLEAN filp_write(file_t *fp, LARGE_INTEGER offset,
                   ULONG bytes, const void *buffer, errcode_t *err)
{
	IO_STATUS_BLOCK iosb = {0};
	NTSTATUS        status;

    DEBUG("filp_write:  writing %lu bytes to %llu of %s.\n",
            bytes, offset.QuadPart, fp->f_name);

	//
	// Should be aligned
	//

	ASSERT(0 == (bytes % fp->f_d_geometry.BytesPerSector));
	ASSERT(0 == (offset.LowPart % fp->f_d_geometry.BytesPerSector));


	//
	// perform io
	//
	status = NtWriteFile(fp->f_handle, NULL, NULL, NULL,
	 		             &iosb, (PVOID)buffer, bytes,
                         &offset, NULL);

	//
	// translate error
	//

	if (status == STATUS_SUCCESS)
	{
        DEBUG("filp_write:  %lu bytes written to %llu of %s.\n",
                (ULONG)iosb.Information, offset.QuadPart, fp->f_name);

        if (err)
		    *err = 0;
		return TRUE;
	}

    DEBUG("filp_write: failed to write %s(%xh) err: %xh\n",
            fp->f_name, fp->f_handle, status);
    if (err)
	    *err = _MapNtStatus(status);

	return FALSE;
}

static
BOOLEAN
_SetPartType(
    IN HANDLE Handle,
    IN UCHAR Type
   )
{
	IO_STATUS_BLOCK IoStatusBlock;
	return STATUS_SUCCESS == NtDeviceIoControlFile(
												   Handle, NULL, NULL, NULL, &IoStatusBlock, IOCTL_DISK_SET_PARTITION_INFO,
												   &Type, sizeof(Type),
												   NULL, 0);
}



//--------------------- interface part

//
// Interface functions.
// Is_mounted is set to 1 if the device is mounted, 0 otherwise
//

errcode_t
ext2fs_check_if_mounted(const char *file, int *mount_flags)
{
    file_t *fp;
    errcode_t err = 0;
	*mount_flags = 0;

    return 0;

    fp = filp_open_device(file, O_RDONLY, 0, &err);
    if (fp) {
	    __try {
	        *mount_flags = filp_is_mounted(fp) ? EXT2_MF_MOUNTED : 0;
	    } __finally {
		    filp_close(fp);
	    }
    }

	return err;
}



errcode_t ext2fs_check_mount_point(const char *device, int *mount_flags,
                                          char *mtpt, int mtlen)
{
    errcode_t err = ext2fs_check_if_mounted(device, mount_flags);
    if (mtlen > 0) {
        memset(mtpt, 0, mtlen);
    }
    return err;
}

//
// Returns the number of blocks in a partition
//

errcode_t
ext2fs_get_device_size2(const char *file, int blocksize,
	 			        blk64_t *retblocks)
{
    file_t   *fp;
    __int64   size = 0;
    errcode_t err = 0;

    fp = filp_open_device(file, O_RDONLY, 0, &err);
    if (fp) {
	    __try {
	        size = fp->f_size;
            err = 0;
	    } __finally {
		    filp_close(fp);
	    }
    }
    DEBUG("ext2fs_get_device_size2: dev:%s fp:%p s:%llu.\n", file, fp, size);

	*retblocks = (blk64_t)size / blocksize;
	return err;
}


errcode_t
ext2fs_get_device_size(const char *file, int blocksize,
				 blk_t *retblocks)
{
    blk64_t blks = 0;
    errcode_t err;
    err = ext2fs_get_device_size2(file, blocksize, &blks);
    *retblocks = (blk_t) blks;
    return err;
}

/*
 * Returns the logical sector size of a device
 */
errcode_t ext2fs_get_device_sectsize(const char *file, int *sectsize)
{
    file_t *fp;
    errcode_t err = 0;

    *sectsize = 512;

    fp = filp_open_device(file, O_RDONLY, 0, &err);
    if (fp) {
	    __try {
            *sectsize = fp->f_d_geometry.BytesPerSector;
	    } __finally {
		    filp_close(fp);
	    }
    }
    return err;
}

/*
 * Return desired alignment for direct I/O
*/
int ext2fs_get_dio_alignment(int fd)
{
    file_t *fp;

    if (fd < 8192 || fd >= 8192 + MAX_OPENED_FILES)
        return 0;
    fp = g_files_array[fd - 8192];
    if (!fp)
        return 0;

    return fp->f_d_geometry.BytesPerSector;
}

/*
 * Returns the physical sector size of a device
 */
errcode_t ext2fs_get_device_phys_sectsize(const char *file, int *sectsize)
{
    return ext2fs_get_device_sectsize(file, sectsize);
}

#ifndef __x86_64__
size_t  _EXFUN(strnlen,(const char *s, size_t l))
{
    size_t i = 0;
    while (i < l && s[i]) {
        i++;
    }

    return i;
}
#endif

int ext2fs_open_file(const char *pathname, int flags, mode_t mode)
{
    file_t *fp;
    errcode_t err = 0;

    fp = filp_open_device(pathname, flags, mode, &err);
    if (!fp)
        return -err;

    DEBUG("ext2fs_open_file: %s opened at slot %d (%p)\n", pathname, fp->f_fd - 8192, fp);
    return fp->f_fd;
}

int ext2fs_close_file(int fd)
{
    file_t *fp;

    if (fd < 8192 || fd >= 8192 + MAX_OPENED_FILES)
        return -EINVAL;
    fp = g_files_array[fd - 8192];
    if (fp) {
        filp_close(fp);
    }

    DEBUG("ext2fs_close_file: fd %d (%p) closed.\n", fd - 8192, fp);
    return 0;
}

int ext2fs_fstat(int fd, ext2fs_struct_stat *buf)
{
    file_t *fp;

    if (fd < 8192 || fd >= 8192 + MAX_OPENED_FILES)
        return -EINVAL;
    fp = g_files_array[fd - 8192];
    if (fp) {
        buf->st_dev = fd;
        buf->st_size = fp->f_size;
        if (fp->f_device | fp->f_volume) {
            buf->st_mode = S_IFBLK;
        } else {
            buf->st_ino = fd;
            buf->st_mode = S_IFREG;
        }
        buf->st_mode +=  S_IRWXO + S_IRWXG +  S_IRWXU;
        buf->st_blksize = fp->f_d_geometry.BytesPerSector;
        buf->st_blocks = fp->f_size / buf->st_blksize;
    }
    return 0;

}

int ext2fs_stat(const char *path, ext2fs_struct_stat *buf)
{
    int fd, err;

    fd = ext2fs_open_file(path, O_RDONLY, 0);
    if (fd < 8192 || fd >= 8192 + 16)
        return -EINVAL;
    err = ext2fs_fstat(fd, buf);
    ext2fs_close_file(fd);

    return err;
}

errcode_t ext2fs_sync_device(int fd, int flushb)
{
    file_t *fp;

    if (fd < 8192 || fd >= 8192 + MAX_OPENED_FILES)
        return -EINVAL;
    fp = g_files_array[fd - 8192];
    if (fp) {
        filp_flush(fp);
    }
    return 0;
}

//
// Table elements
//


static
errcode_t
nt_open(const char *name, int flags, io_channel *channel)
{
	io_channel      io = NULL;
	PNT_PRIVATE_DATA NtData = NULL;
	errcode_t err = 0;


    if (BooleanFlagOn(flags, EXT2_FLAG_RW)) {
        flags = O_RDWR |  O_DIRECT | EXT2_FLAG_RW;
    } else {
        flags = O_RDONLY | O_DIRECT;
    }

	//
	// Check name
	//

	if (NULL == name)
	{
		return EXT2_ET_BAD_DEVICE_NAME;
	}

	__try {

		//
		// Allocate channel handle
		//

		io = (io_channel) malloc(sizeof(struct struct_io_channel));

		if (NULL == io)
		{
			err = ENOMEM;
			__leave;
		}

		RtlZeroMemory(io, sizeof(struct struct_io_channel));
		io->magic = EXT2_ET_MAGIC_IO_CHANNEL;

		NtData = (PNT_PRIVATE_DATA)malloc(sizeof(NT_PRIVATE_DATA));
		if (NULL == NtData)
		{
			err = ENOMEM;
			__leave;
		}

        memset(NtData, 0, sizeof(NT_PRIVATE_DATA));
		io->manager = unix_io_manager;
		io->name = malloc(strlen(name) + 1);
		if (NULL == io->name)
		{
			err = ENOMEM;
			__leave;
		}
        memset(io->name, 0, strlen(name) + 1);
		strcpy(io->name, name);
		io->private_data = NtData;
		io->block_size = 4096;
		io->read_error = 0;
		io->write_error = 0;
		io->refcount = 1;

		//
		// Initialize data
		//

		RtlZeroMemory(NtData, sizeof(NT_PRIVATE_DATA));

		NtData->magic = EXT2_ET_MAGIC_NT_IO_CHANNEL;
		NtData->BufferBlockNumber = -1;
		NtData->BufferSize = 4096;
		NtData->Buffer = malloc(NtData->BufferSize);
		if (NULL == NtData->Buffer)
		{
			err = ENOMEM;
			__leave;
		}

		//
		// Open it
		//

        NtData->file = filp_open_device(name, flags, 0, &err);
        if (!NtData->file) {
			__leave;
		}


        if (BooleanFlagOn(flags, EXT2_FLAG_RW)) {
            /* flush dirty cache to disk */
            filp_flush(NtData->file);
        } else {
            NtData->OpenedReadonly = TRUE;
        }


		//
		// Lock/dismount
		//


		if(NT_SUCCESS(filp_lock(NtData->file))) {
		} else {
            filp_dismount(NtData->file);
			filp_close(NtData->file);

            NtData->file = filp_open_device(name, flags, 0, &err);
            if (!NtData->file) {
			    __leave;
		    }
            filp_lock(NtData->file);
        }


		//
		// Done
		//

        err = 0;
		*channel = io;
	}
	__finally {

		if(0 != err)
		{
			//
			// Cleanup
			//

			if (NULL != io)
			{
				if(NULL != io->name)
				{
					free(io->name);
				}

				free(io);
			}

			if (NULL != NtData)
			{
				if(NULL != NtData->file)
				{
					filp_unlock(NtData->file);
					filp_close(NtData->file);
				}

				if(NULL != NtData->Buffer)
				{
					free(NtData->Buffer);
				}

				free(NtData);
			}
		}
	}

	return err;
}


//
// Close api
//

static
errcode_t
nt_close(io_channel channel)
{
	PNT_PRIVATE_DATA NtData = NULL;

	if(NULL == channel)
	{
		return 0;
	}

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	NtData = (PNT_PRIVATE_DATA) channel->private_data;
	EXT2_CHECK_MAGIC(NtData, EXT2_ET_MAGIC_NT_IO_CHANNEL);

	if (--channel->refcount > 0)
	{
		return 0;
	}

	if(NULL != channel->name)
	{
		free(channel->name);
	}


	free(channel);

	if (NULL != NtData)
	{
		if(NULL != NtData->file)
		{
            //
            // Do dismount anyway
            //

            filp_dismount(NtData->file);

			filp_close(NtData->file);
		}

		if(NULL != NtData->Buffer)
		{
			free(NtData->Buffer);
		}

		free(NtData);
	}

	return 0;
}



//
// set block size
//

static
errcode_t
nt_set_blksize(io_channel channel, int blksize)
{
	PNT_PRIVATE_DATA NtData = NULL;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	NtData = (PNT_PRIVATE_DATA) channel->private_data;
	EXT2_CHECK_MAGIC(NtData, EXT2_ET_MAGIC_NT_IO_CHANNEL);

	if (channel->block_size != blksize)
	{
		channel->block_size = blksize;

        if (NtData->Buffer) {
		    free(NtData->Buffer);
            NtData->Buffer = NULL;
        }
		NtData->BufferBlockNumber = -1;
		NtData->BufferSize = channel->block_size;
		ASSERT(0 == (NtData->BufferSize % 512));

		NtData->Buffer = malloc(NtData->BufferSize);
		if (NULL == NtData->Buffer)
		{
			return ENOMEM;
		}

	}

	return 0;
}


//
// read block
//

static
errcode_t
nt_read_blk64(io_channel channel, unsigned __int64 block,
			  int count, void *buf)
{
	PVOID BufferToRead;
	ULONG SizeToRead;
	ULONG Size;
	LARGE_INTEGER Offset;
	PNT_PRIVATE_DATA NtData = NULL;
	errcode_t err = 0;

    DEBUG("nt_read_blk64: block: %llu/%d.\n", block, count);

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	NtData = (PNT_PRIVATE_DATA) channel->private_data;
	EXT2_CHECK_MAGIC(NtData, EXT2_ET_MAGIC_NT_IO_CHANNEL);

	//
	// If it's in the cache, use it!
	//
	if ((1 == count) &&
		(block == NtData->BufferBlockNumber) &&
		(NtData->BufferBlockNumber != -1))
	{
		memcpy(buf, NtData->Buffer, channel->block_size);
		return 0;
	}

	Size = (count < 0) ? (ULONG)(-count) : (ULONG)(count * channel->block_size);

	Offset.QuadPart = (__int64)block;
    Offset.QuadPart = Offset.QuadPart * channel->block_size;
    Offset.QuadPart = Offset.QuadPart + NtData->Offset;

	//
	// If not fit to the block
	//

	if(Size <= NtData->BufferSize)
	{
		//
		// Update the cache
		//

		NtData->BufferBlockNumber = block;
		BufferToRead = NtData->Buffer;
		SizeToRead = NtData->BufferSize;
	}
	else
	{
		SizeToRead = Size;
		BufferToRead = buf;
		ASSERT(0 == (SizeToRead % channel->block_size));
	}

	if(!filp_read(NtData->file, Offset, SizeToRead, BufferToRead, &err))
	{

		if (channel->read_error)
		{
			return (channel->read_error)(channel, block, count, buf,
					       Size, 0, err);
		}
		else
		{
			return err;
		}
	}

	if(BufferToRead != buf)
	{
		ASSERT(Size <= SizeToRead);
		memcpy(buf, BufferToRead, Size);
	} else {
        if (NtData->BufferBlockNumber != -1 && count > 1 &&
            block <= NtData->BufferBlockNumber &&
            block + count > NtData->BufferBlockNumber) {
            NtData->BufferBlockNumber = -1;
        }
    }

    DEBUG("nt_read_blk64: done.\n");
	return 0;
}


//
// write block
//

static
errcode_t
nt_write_blk64(io_channel channel, unsigned __int64 block,
			   int count, const void *buf)
{
	ULONG SizeToWrite;
	LARGE_INTEGER Offset;
	PNT_PRIVATE_DATA NtData = NULL;
	errcode_t err = 0;

    DEBUG("nt_write_blk64: start writing to block %llu/%d.\n", block, count);

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	NtData = (PNT_PRIVATE_DATA) channel->private_data;
	EXT2_CHECK_MAGIC(NtData, EXT2_ET_MAGIC_NT_IO_CHANNEL);

	if(NtData->OpenedReadonly)
	{
		return EACCES;
	}

	NtData->BufferBlockNumber = -1;

	if (count == 1)
	{
		SizeToWrite = channel->block_size;
	}
	else
	{

		if (count < 0)
		{
			SizeToWrite = (ULONG)(-count);
		}
		else
		{
			SizeToWrite = (ULONG)(count * channel->block_size);
		}
	}

	Offset.QuadPart = (__int64)block;
    Offset.QuadPart = Offset.QuadPart * channel->block_size;
    Offset.QuadPart = Offset.QuadPart + NtData->Offset;

    DEBUG("nt_write_blk64: 2 o:%llu s:%lu p:%p d:%p.\n", Offset.QuadPart, SizeToWrite, buf, NtData);
	if(!filp_write(NtData->file, Offset, SizeToWrite, buf, &err))
	{
		if (channel->write_error)
		{
			return (channel->write_error)(channel, block, count, buf,
						SizeToWrite, 0, err);
		}
		else
		{
			return err;
		}
	}

    DEBUG("nt_write_blk64: 3 o:%llu s:%lu p:%p d:%p.\n", Offset.QuadPart, SizeToWrite, buf, NtData);

	//
	// Stash a copy.
	//
	if(SizeToWrite >= NtData->BufferSize)
	{
		NtData->BufferBlockNumber = block;
		memcpy(NtData->Buffer, buf, NtData->BufferSize);
	}
	NtData->Written = TRUE;

    DEBUG("nt_write_blk64: block %llu written.\n", block);
	return 0;

}

static
errcode_t
nt_read_blk(io_channel channel, unsigned long block,
			       int count, void *buf)
{
    return nt_read_blk64(channel, (unsigned __int64) block, count, buf);
}

static
errcode_t
nt_write_blk(io_channel channel, unsigned long block,
				int count, const void *buf)
{
    return nt_write_blk64(channel, (unsigned __int64) block, count, buf);
}

//
// Flush data buffers to disk.  Since we are currently using a
// write-through cache, this is a no-op.
//

static
errcode_t
nt_flush(io_channel channel)
{
	PNT_PRIVATE_DATA NtData = NULL;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	NtData = (PNT_PRIVATE_DATA) channel->private_data;
	EXT2_CHECK_MAGIC(NtData, EXT2_ET_MAGIC_NT_IO_CHANNEL);

	if(NtData->OpenedReadonly)
	{
		return 0; // EACCESS;
	}


	//
	// Flush file buffers.
	//

	filp_flush(NtData->file);

#if 0

	//
	// Test and correct partition type.
	//

	if(NtData->Written)
	{
		_SetPartType(NtData->Handle, 0x83);
	}
#endif

	return 0;
}

io_manager unix_io_manager  = &struct_nt_manager;

