/*-------------------------------------------------------------------------
 *
 * buffile.c
 *	  Management of large buffered files, primarily temporary files.
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/storage/file/buffile.c
 *
 * NOTES:
 *
 * BufFiles provide a very incomplete emulation of stdio atop virtual Files
 * (as managed by fd.c).  Currently, we only support the buffered-I/O
 * aspect of stdio: a read or write of the low-level File occurs only
 * when the buffer is filled or emptied.  This is an even bigger win
 * for virtual Files than for ordinary kernel files, since reducing the
 * frequency with which a virtual File is touched reduces "thrashing"
 * of opening/closing file descriptors.
 *
 * Note that BufFile structs are allocated with palloc(), and therefore
 * will go away automatically at transaction end.  If the underlying
 * virtual File is made with OpenTemporaryFile, then all resources for
 * the file are certain to be cleaned up even if processing is aborted
 * by ereport(ERROR).  The data structures required are made in the
 * palloc context that was current when the BufFile was created, and
 * any external resources such as temp files are owned by the ResourceOwner
 * that was current at that time.
 *
 * BufFile also supports temporary files that exceed the OS file size limit
 * (by opening multiple fd.c temporary files).  This is an essential feature
 * for sorts and hashjoins on large amounts of data.
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "executor/instrument.h"
#include "pgstat.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include "storage/buffile.h"
#include "storage/buf_internals.h"
#include "storage/encryption.h"
#include "utils/datetime.h"
#include "utils/resowner.h"

/*
 * We break BufFiles into gigabyte-sized segments, regardless of RELSEG_SIZE.
 * The reason is that we'd like large temporary BufFiles to be spread across
 * multiple tablespaces when available.
 */
#define MAX_PHYSICAL_FILESIZE	0x40000000
#define BUFFILE_SEG_SIZE		(MAX_PHYSICAL_FILESIZE / BLCKSZ)

/*
 * This data structure represents a buffered file that consists of one or
 * more physical files (each accessed through a virtual file descriptor
 * managed by fd.c).
 */
struct BufFile
{
	int			numFiles;		/* number of physical files in set */
	/* all files except the last have length exactly MAX_PHYSICAL_FILESIZE */
	File	   *files;			/* palloc'd array with numFiles entries */
	off_t	   *offsets;		/* palloc'd array with numFiles entries */
#ifdef USE_OPENSSL
	/*
	 * If the file is encrypted, only the whole buffer can be loaded / dumped
	 * --- see BufFileLoadBuffer() for more info --- whether it's space is
	 * used up or not. Therefore we need to keep track of the actual on-disk
	 * size buffer of each component file, as it would be if there was no
	 * encryption.
	 *
	 * List would make coding simpler, however would not contribute to
	 * performance. Random access is important here.
	 */
	off_t	*useful;

	/*
	 * The array may need to be expanded independent from extendBufFile(), so
	 * store the number of elements here.
	 */
	int		nuseful;
#endif

	/*
	 * offsets[i] is the current seek position of files[i].  We use this to
	 * avoid making redundant FileSeek calls.
	 */

	bool		isTemp;			/* can only add files if this is TRUE */
	bool		isInterXact;	/* keep open over transactions? */
	bool		dirty;			/* does buffer need to be written? */

	/*
	 * resowner is the ResourceOwner to use for underlying temp files.  (We
	 * don't need to remember the memory context we're using explicitly,
	 * because after creation we only repalloc our arrays larger.)
	 */
	ResourceOwner resowner;

	/*
	 * "current pos" is position of start of buffer within the logical file.
	 * Position as seen by user of BufFile is (curFile, curOffset + pos).
	 */
	int			curFile;		/* file index (0..n) part of current pos */
	off_t		curOffset;		/* offset part of current pos */
	int			pos;			/* next read/write position in buffer */
	int			nbytes;			/* total # of valid bytes in buffer */
	char		buffer[BLCKSZ];
#ifdef USE_OPENSSL
	char		tweakBase[TWEAK_SIZE];
#endif
};

static BufFile *makeBufFile(File firstfile);
static void extendBufFile(BufFile *file);
static void BufFileLoadBuffer(BufFile *file);
static void BufFileDumpBuffer(BufFile *file);
static int	BufFileFlush(BufFile *file);
#ifdef USE_OPENSSL
static void BufFileTweak(char *tweak, BufFile *file, int curFile, off_t offset);
static void ensureBufFileUsefulArraySize(BufFile *file, int required);
#endif

/*
 * Create a BufFile given the first underlying physical file.
 * NOTE: caller must set isTemp and isInterXact if appropriate.
 */
static BufFile *
makeBufFile(File firstfile)
{
	BufFile    *file = (BufFile *) palloc(sizeof(BufFile));

	file->numFiles = 1;
	file->files = (File *) palloc(sizeof(File));
	file->files[0] = firstfile;
	file->offsets = (off_t *) palloc(sizeof(off_t));
	file->offsets[0] = 0L;
#ifdef USE_OPENSSL
	file->useful = (off_t *) palloc(sizeof(off_t));
	file->useful[0] = 0L;
	file->nuseful = 1;

	if (data_encrypted)
	{
		/*
		 * The unused (trailing) part of the buffer should not contain
		 * undefined data: if we encrypt such a buffer and flush it to disk,
		 * the encrypted form of that "undefined part" can get zeroed due to
		 * seek and write beyond EOF. If such a buffer gets loaded and
		 * decrypted, the change of the undefined part to zeroes can affect
		 * the valid part if it does not end at block boundary. By setting the
		 * whole buffer to zeroes we ensure that the unused part always
		 * contains zeroes.
		 */
		MemSet(file->buffer, 0, BLCKSZ);
	}
#endif
	file->isTemp = false;
	file->isInterXact = false;
	file->dirty = false;
	file->resowner = CurrentResourceOwner;
	file->curFile = 0;
	file->curOffset = 0L;
	file->pos = 0;
	file->nbytes = 0;

	return file;
}

/*
 * Add another component temp file.
 */
static void
extendBufFile(BufFile *file)
{
	File		pfile;
	ResourceOwner oldowner;

	/* Be sure to associate the file with the BufFile's resource owner */
	oldowner = CurrentResourceOwner;
	CurrentResourceOwner = file->resowner;

	Assert(file->isTemp);
	pfile = OpenTemporaryFile(file->isInterXact);
	Assert(pfile >= 0);

	CurrentResourceOwner = oldowner;

	file->files = (File *) repalloc(file->files,
									(file->numFiles + 1) * sizeof(File));
	file->offsets = (off_t *) repalloc(file->offsets,
									   (file->numFiles + 1) * sizeof(off_t));
#ifdef USE_OPENSSL
	ensureBufFileUsefulArraySize(file, file->numFiles + 1);
#endif
	file->files[file->numFiles] = pfile;
	file->offsets[file->numFiles] = 0L;
	file->numFiles++;
}

/*
 * Create a BufFile for a new temporary file (which will expand to become
 * multiple temporary files if more than MAX_PHYSICAL_FILESIZE bytes are
 * written to it).
 *
 * If interXact is true, the temp file will not be automatically deleted
 * at end of transaction.
 *
 * Note: if interXact is true, the caller had better be calling us in a
 * memory context, and with a resource owner, that will survive across
 * transaction boundaries.
 */
BufFile *
BufFileCreateTemp(bool interXact)
{
	BufFile    *file;
	File		pfile;

	pfile = OpenTemporaryFile(interXact);
	Assert(pfile >= 0);

	file = makeBufFile(pfile);
	file->isTemp = true;
	file->isInterXact = interXact;

	if (data_encrypted)
	{
#ifdef USE_OPENSSL
		TimestampTz ts = GetCurrentTimestamp();

		memset(file->tweakBase, 0, sizeof(file->tweakBase));
		memcpy(file->tweakBase + sizeof(uint32), &MyProcPid, sizeof(MyProcPid));
		memcpy(file->tweakBase + sizeof(uint32) + sizeof(MyProcPid), &ts, sizeof(ts));
#else
		elog(FATAL,
			 "data encryption cannot be used because SSL is not supported by this build\n"
			 "Compile with --with-openssl to use SSL connections.");
#endif	/* USE_OPENSSL */
	}

	return file;
}

#ifdef NOT_USED
/*
 * Create a BufFile and attach it to an already-opened virtual File.
 *
 * This is comparable to fdopen() in stdio.  This is the only way at present
 * to attach a BufFile to a non-temporary file.  Note that BufFiles created
 * in this way CANNOT be expanded into multiple files.
 */
BufFile *
BufFileCreate(File file)
{
#ifdef USE_OPENSSL
	if (data_encrypted)
	{
		elog(ERROR,
			 "Non-temporary BufFile not implemented for encrypted data.");
	}
#endif
	return makeBufFile(file);
}
#endif

/*
 * Close a BufFile
 *
 * Like fclose(), this also implicitly FileCloses the underlying File.
 */
void
BufFileClose(BufFile *file)
{
	int			i;

	/* flush any unwritten data */
	BufFileFlush(file);
	/* close the underlying file(s) (with delete if it's a temp file) */
	for (i = 0; i < file->numFiles; i++)
		FileClose(file->files[i]);
	/* release the buffer space */
	pfree(file->files);
	pfree(file->offsets);
#ifdef USE_OPENSSL
	pfree(file->useful);
#endif
	pfree(file);
}

/*
 * BufFileLoadBuffer
 *
 * Load some data into buffer, if possible, starting from curOffset.
 * At call, must have dirty = false, nbytes = 0.
 * On exit, nbytes is number of bytes loaded.
 */
static void
BufFileLoadBuffer(BufFile *file)
{
	File		thisfile;

	/*
	 * Only whole multiple of ENCRYPTION_BLOCK can be encrypted / decrypted,
	 * but we choose to use BLCKSZ (i.e. BufFile buffer) as the unit. The
	 * point is that curOffset is a component of the encryption tweak, and all
	 * data within particular call of encrypt_block() / decrypt_block() must
	 * have the same tweak. So whichever unit we choose we must stick on it
	 * and never encrypt / decrypt multiple units at a time.
	 *
	 * BLCKSZ also seems better choice than ENCRYPTION_BLOCK for performance
	 * purposes. We assume that alignment to BLCKSZ implies alignment to
	 * ENCRYPTION_BLOCK.
	 */
	Assert((file->curOffset % BLCKSZ == 0 &&
			file->curOffset % ENCRYPTION_BLOCK == 0) ||
		   !data_encrypted);

	/*
	 * Advance to next component file if necessary and possible.
	 *
	 * This path can only be taken if there is more than one component, so it
	 * won't interfere with reading a non-temp file that is over
	 * MAX_PHYSICAL_FILESIZE.
	 */
	if (file->curOffset >= MAX_PHYSICAL_FILESIZE &&
		file->curFile + 1 < file->numFiles)
	{
		file->curFile++;
		file->curOffset = 0L;
	}

	/*
	 * See makeBufFile().
	 *
	 * Actually here we only handle the case of FileRead() returning zero
	 * bytes below. In contrast, if the buffer contains any data but it's not
	 * full, it should already have the trailing zeroes (encrypted) on
	 * disk. And as the encrypted buffer is always loaded in its entirety
	 * (i.e. EOF should only appear at buffer boundary if the data is
	 * encrypted), all unused bytes of the buffer should eventually be zeroes
	 * after the decryption.
	 */
	if (data_encrypted)
		MemSet(file->buffer, 0, BLCKSZ);

	/*
	 * May need to reposition physical file.
	 */
	thisfile = file->files[file->curFile];
	if (file->curOffset != file->offsets[file->curFile])
	{
		if (FileSeek(thisfile, file->curOffset, SEEK_SET) != file->curOffset)
			return;				/* seek failed, read nothing */
		file->offsets[file->curFile] = file->curOffset;
	}

	/*
	 * Read whatever we can get, up to a full bufferload.
	 */
	file->nbytes = FileRead(thisfile,
							file->buffer,
							sizeof(file->buffer),
							WAIT_EVENT_BUFFILE_READ);

	if (file->nbytes < 0)
		file->nbytes = 0;

	/*
	 * BLCKSZ is the I/O unit for encrypted data. (For non-encrypted data this
	 * condition applies to all but the last buffer in the file.)q
	 */
	Assert(file->nbytes % BLCKSZ == 0 || !data_encrypted);

	file->offsets[file->curFile] += file->nbytes;
	/* we choose not to advance curOffset here */

	if (data_encrypted && file->nbytes > 0)
	{
#ifdef USE_OPENSSL
		char tweak[TWEAK_SIZE];
		int	nbytes = file->nbytes;

		/*
		 * The encrypted component file can only consist of whole number of
		 * our encryption units. (Only the whole buffers are dumped / loaded.)
		 */
		Assert(nbytes % BLCKSZ == 0);

		BufFileTweak(tweak, file, file->curFile, file->curOffset);

		/*
		 * The whole block is encrypted / decrypted at once as explained
		 * above.
		 */
		decrypt_block(file->buffer, file->buffer, BLCKSZ, tweak);

#ifdef	USE_ASSERT_CHECKING
		/*
		 * The unused part of the buffer which we've read from disk and
		 * decrypted should only contain zeroes, as explained in front of the
		 * MemSet() call.
		 */
		{
			int	i;

			for (i = file->nbytes; i < BLCKSZ; i++)
				Assert(file->buffer[i] == 0);
		}
#endif	/* USE_ASSERT_CHECKING */
#else
		elog(FATAL,
			 "data encryption cannot be used because SSL is not supported by this build\n"
			 "Compile with --with-openssl to use SSL connections.");
#endif /* USE_OPENSSL */
	}
	pgBufferUsage.temp_blks_read++;
}

/*
 * BufFileDumpBuffer
 *
 * Dump buffer contents starting at curOffset.
 * At call, should have dirty = true, nbytes > 0.
 * On exit, dirty is cleared if successful write, and curOffset is advanced.
 */
static void
BufFileDumpBuffer(BufFile *file)
{
	int			wpos = 0;
	int			bytestowrite;
	File		thisfile;
	char		*write_ptr;

	/*
	 * See comments in BufFileLoadBuffer();
	 */
	Assert((file->curOffset % BLCKSZ == 0 &&
			file->curOffset % ENCRYPTION_BLOCK == 0) ||
		   !data_encrypted);

	/*
	 * Caller's responsibility.
	 */
	Assert(file->pos <= file->nbytes);

	if (data_encrypted)
	{
#ifdef USE_OPENSSL
		char tweak[TWEAK_SIZE];

		BufFileTweak(tweak, file, file->curFile, file->curOffset);

		/*
		 * The amount of data encrypted must be a multiple of
		 * ENCRYPTION_BLOCK. We meet this condition simply by encrypting the
		 * whole buffer.
		 *
		 * XXX Alternatively we could get the encrypted chunk length by
		 * rounding file->nbytes up to the nearest multiple of
		 * ENCRYPTION_BLOCK, and for decryption use the
		 * file->useful[file->curFile] value to find out how many blocks
		 * should be decrypted. That would reduce I/O if the buffer is mostly
		 * empty, but (BLCKSZ / ENCRYPTION_BLOCK) calls of encrypt_block()
		 * would be needed for full buffers. See BufFileLoadBuffer() for
		 * explanation why we must stick on the unit of data amount encrypted
		 * / decrypted.
		 */
		if (encryption_buf_size < BLCKSZ)
			enlarge_encryption_buffer(BLCKSZ);
		encrypt_block(file->buffer, encryption_buffer, BLCKSZ, tweak);
		write_ptr = encryption_buffer;
#else
		elog(FATAL,
			 "data encryption cannot be used because SSL is not supported by this build\n"
			 "Compile with --with-openssl to use SSL connections.");
#endif /* USE_OPENSSL */
	}
	else
		write_ptr = file->buffer;

	/*
	 * Unlike BufFileLoadBuffer, we must dump the whole buffer even if it
	 * crosses a component-file boundary; so we need a loop.
	 */
	while (wpos < file->nbytes)
	{
		/*
		 * Advance to next component file if necessary and possible.
		 */
		if (file->curOffset >= MAX_PHYSICAL_FILESIZE && file->isTemp)
		{
			while (file->curFile + 1 >= file->numFiles)
				extendBufFile(file);
			file->curFile++;
			file->curOffset = 0L;
		}

		if (!data_encrypted)
		{
			/*
			 * Enforce per-file size limit only for temp files, else just try
			 * to write as much as asked...
			 */
			bytestowrite = file->nbytes - wpos;
			if (file->isTemp)
			{
				off_t		availbytes = MAX_PHYSICAL_FILESIZE - file->curOffset;

				if ((off_t) bytestowrite > availbytes)
					bytestowrite = (int) availbytes;
			}
		}
		else
		{
			/*
			 * This condition plus the alignment of curOffset to BLCKSZ
			 * (checked above) ensure that the encrypted buffer never crosses
			 * component file boundary.
			 */
			StaticAssertStmt((MAX_PHYSICAL_FILESIZE % BLCKSZ) == 0,
							 "BLCKSZ is not whole multiple of MAX_PHYSICAL_FILESIZE");

			/*
			 * Encrypted data is dumped all at once.
			 *
			 * Here we don't have to check availbytes because --- according to
			 * the assertions above --- currOffset should be lower than
			 * MAX_PHYSICAL_FILESIZE by non-zero multiple of BLCKSZ.
			 */
			bytestowrite = BLCKSZ;
		}

		/*
		 * May need to reposition physical file.
		 */
		thisfile = file->files[file->curFile];

		/*
		 * Note: if the current offset is beyond EOF, the following write will
		 * result in a hole that will be filled with zeroes. For non-empty
		 * buffers we handle this by MemSet(file->buffer, 0, BLCKSZ)
		 * elsewhere, however we do not have to care about buffers fully
		 * contained in the hole: neither encrypt_block() nor decrypt_block()
		 * tries to process a chunk that only contains zeroes. Thus the zeroes
		 * constituting the hole should appear in the buffer as soon as it's
		 * loaded from disk.
		 */
		if (file->curOffset != file->offsets[file->curFile])
		{
			if (FileSeek(thisfile, file->curOffset, SEEK_SET) != file->curOffset)
				return;			/* seek failed, give up */

			file->offsets[file->curFile] = file->curOffset;
		}
		bytestowrite = FileWrite(thisfile,
								 write_ptr + wpos,
								 bytestowrite,
								 WAIT_EVENT_BUFFILE_WRITE);
		if (bytestowrite <= 0 ||
			(data_encrypted && bytestowrite != BLCKSZ))
			return;				/* failed to write */

		file->offsets[file->curFile] += bytestowrite;
		file->curOffset += bytestowrite;
		pgBufferUsage.temp_blks_written++;

		wpos += bytestowrite;
	}
	file->dirty = false;

	if (!data_encrypted)
	{
		/*
		 * At this point, curOffset has been advanced to the end of the
		 * buffer, ie, its original value + nbytes.  We need to make it point
		 * to the logical file position, ie, original value + pos, in case
		 * that is less (as could happen due to a small backwards seek in a
		 * dirty buffer!)
		 */
		file->curOffset -= (file->nbytes - file->pos);
		if (file->curOffset < 0)	/* handle possible segment crossing */
		{
			file->curFile--;
			Assert(file->curFile >= 0);
			file->curOffset += MAX_PHYSICAL_FILESIZE;
		}

		/*
		 * Now we can set the buffer empty without changing the logical
		 * position
		 */
		file->pos = 0;
		file->nbytes = 0;
	}
	else
	{
		/*
		 * curOffset should be at buffer boundary and buffer is the smallest
		 * I/O unit for encrypted data.
		 */
		Assert(file->curOffset % BLCKSZ == 0);

		if (file->pos >= BLCKSZ)
		{
			Assert(file->pos == BLCKSZ);

			/*
			 * curOffset points to the beginning of the next buffer, so just
			 * reset pos and nbytes.
			 */
			file->pos = 0;
			file->nbytes = 0;

			/* See makeBufFile() */
			if (data_encrypted)
				MemSet(file->buffer, 0, BLCKSZ);
		}
		else
		{
			/*
			 * Move curOffset to the beginning of the just-written buffer and
			 * preserve pos.
			 */
			file->curOffset -= BLCKSZ;

			/*
			 * At least pos bytes should be written even if the first change
			 * since now appears at pos == nbytes, but in fact the whole
			 * buffer will be written regardless pos. This is the price we pay
			 * for the choosing BLCKSZ as the I/O unit for encrypted data.
			 */
			file->nbytes = BLCKSZ;
		}
	}
}

/*
 * BufFileRead
 *
 * Like fread() except we assume 1-byte element size.
 */
size_t
BufFileRead(BufFile *file, void *ptr, size_t size)
{
	size_t		nread = 0;
	size_t		nthistime;

	if (file->dirty)
	{
		if (BufFileFlush(file) != 0)
			return 0;			/* could not flush... */
		Assert(!file->dirty);
	}

	while (size > 0)
	{
		int	avail;

		if (file->pos >= file->nbytes)
		{
			/*
			 * Neither read nor write nor seek should leave pos greater than
			 * nbytes, regardless the data is encrypted or not.
			 */
			Assert(file->pos == file->nbytes || file->nbytes == 0);

			/*
			 * The Assert() above implies that pos is a whole multiple of
			 * BLCKSZ, so curOffset has meet the same encryption-specific
			 * requirement too.
			 */
			Assert(file->curOffset % BLCKSZ == 0 || !data_encrypted);

			/* Try to load more data into buffer. */
			if (!data_encrypted || file->pos % BLCKSZ == 0)
			{
				file->curOffset += file->pos;
				file->pos = 0;
				file->nbytes = 0;
				BufFileLoadBuffer(file);
				if (file->nbytes <= 0)
					break;			/* no more data available */
			}
			else
			{
				int	nbytes_orig = file->nbytes;

				/*
				 * Given that ENCRYPTION_BLOCK is the I/O unit for encrypted
				 * data (see comments in BufFileLoadBuffer()), we cannot add
				 * pos to curOffset because that would make it point outside
				 * block boundary. The only thing we can do is to reload the
				 * whole buffer and see if more data is eventually there than
				 * the previous load has fetched.
				 */
				BufFileLoadBuffer(file);
				if (file->nbytes <= nbytes_orig)
					break;		/* no more data available */
			}
		}

		avail = file->nbytes;
		nthistime = avail - file->pos;

		/*
		 * The buffer can contain trailing zeroes because BLCKSZ is the I/O
		 * unit for encrypted data. These are not available for reading.
		 */
		if (data_encrypted)
		{
#ifdef USE_OPENSSL
			off_t	useful = file->useful[file->curFile];

			/*
			 * The criterion is whether the useful data end within the
			 * currently loaded buffer.
			 */
			if (useful < file->curOffset + BLCKSZ)
			{
				/*
				 * Compute the number of bytes available in the current
				 * buffer.
				 */
				avail = useful - file->curOffset;
				Assert(avail >= 0);

				/*
				 * An empty buffer can exist, e.g. after a seek to the end of
				 * the last component file.
				 */
				if (avail == 0)
					break;

				/*
				 * Seek beyond the current EOF, which was not followed by
				 * write, could have resulted in position outside the useful
				 * data
				 */
				if (file->pos > avail)
					break;

				nthistime = avail - file->pos;
				Assert(nthistime >= 0);

				/*
				 * Have we reached the end of the valid data?
				 */
				if (nthistime == 0)
					break;
			}
#else
		elog(FATAL,
			 "data encryption cannot be used because SSL is not supported by this build\n"
			 "Compile with --with-openssl to use SSL connections.");
#endif	/* USE_OPENSSL */
		}

		if (nthistime > size)
			nthistime = size;
		Assert(nthistime > 0);

		memcpy(ptr, file->buffer + file->pos, nthistime);

		file->pos += nthistime;
		ptr = (void *) ((char *) ptr + nthistime);
		size -= nthistime;
		nread += nthistime;
	}

	return nread;
}

/*
 * BufFileWrite
 *
 * Like fwrite() except we assume 1-byte element size.
 */
size_t
BufFileWrite(BufFile *file, void *ptr, size_t size)
{
	size_t		nwritten = 0;
	size_t		nthistime;

	while (size > 0)
	{
		if (file->pos >= BLCKSZ)
		{
			/* Buffer full, dump it out */
			if (file->dirty)
			{
				BufFileDumpBuffer(file);
				if (file->dirty)
					break;		/* I/O error */
			}
			else
			{
				/*
				 * Hmm, went directly from reading to writing?
				 *
				 * As pos should be exactly BLCKSZ, there is nothing special
				 * to do about data_encrypted. Except for zeroing the buffer.
				 */
				Assert(file->pos == BLCKSZ);

				file->curOffset += file->pos;
				file->pos = 0;
				file->nbytes = 0;

				/* See makeBufFile() */
				if (data_encrypted)
					MemSet(file->buffer, 0, BLCKSZ);
			}

			/*
			 * If curOffset changed above, it should still meet the assumption
			 * that buffer is the I/O unit for encrypted data.
			 */
			Assert(file->curOffset % BLCKSZ == 0 || !data_encrypted);
		}

		nthistime = BLCKSZ - file->pos;
		if (nthistime > size)
			nthistime = size;
		Assert(nthistime > 0);

		memcpy(file->buffer + file->pos, ptr, nthistime);

		file->dirty = true;
		file->pos += nthistime;
		if (file->nbytes < file->pos)
			file->nbytes = file->pos;

		if (data_encrypted)
		{
#ifdef USE_OPENSSL
			off_t	new_offset;
			int		fileno;

			/*
			 * curFile does not necessarily correspond to the offset: it can
			 * still have the initial value if BufFileSeek() skipped the first
			 * previous file w/o dumping anything of it. Therefore we must
			 * compute the correct fileno here.
			 */
			fileno = file->curOffset / MAX_PHYSICAL_FILESIZE;

			/*
			 * fileno can point to a segment that does not exist on disk yet.
			 */
			ensureBufFileUsefulArraySize(file, fileno + 1);

			/*
			 * Update the offset of the underlying component file if we've
			 * added any useful data.
			 */
			new_offset  = file->curOffset + file->pos;

			/*
			 * Make sure the offset is relative to the correct component
			 * file. BufFileDumpBuffer() should have adjusted that during
			 * sequential write, but if we've just used BufFileSeek() to jump
			 * to segment boundary w/o writing, the value is relative to the
			 * start of the *previous* segment.
			 */
			if (file->curOffset % MAX_PHYSICAL_FILESIZE == 0)
				new_offset %= MAX_PHYSICAL_FILESIZE;

			/*
			 * Adjust the number of useful bytes in the file if needed. This
			 * has to happen immediately, independent from
			 * BufFileDumpBuffer().
			 */
			if (new_offset > file->useful[fileno])
				file->useful[fileno] = new_offset;
#else
			elog(FATAL,
				 "data encryption cannot be used because SSL is not supported by this build\n"
				 "Compile with --with-openssl to use SSL connections.");
#endif	/* USE_OPENSSL */
		}

		ptr = (void *) ((char *) ptr + nthistime);
		size -= nthistime;
		nwritten += nthistime;
	}

	return nwritten;
}

/*
 * BufFileFlush
 *
 * Like fflush()
 */
static int
BufFileFlush(BufFile *file)
{
	if (file->dirty)
	{
		BufFileDumpBuffer(file);
		if (file->dirty)
			return EOF;
	}

	return 0;
}

/*
 * BufFileSeek
 *
 * Like fseek(), except that target position needs two values in order to
 * work when logical filesize exceeds maximum value representable by long.
 * We do not support relative seeks across more than LONG_MAX, however.
 *
 * Result is 0 if OK, EOF if not.  Logical position is not moved if an
 * impossible seek is attempted.
 */
int
BufFileSeek(BufFile *file, int fileno, off_t offset, int whence)
{
	int			newFile;
	off_t		newOffset;

	switch (whence)
	{
		case SEEK_SET:
			if (fileno < 0)
				return EOF;
			newFile = fileno;
			newOffset = offset;
			break;
		case SEEK_CUR:

			/*
			 * Relative seek considers only the signed offset, ignoring
			 * fileno. Note that large offsets (> 1 gig) risk overflow in this
			 * add, unless we have 64-bit off_t.
			 */
			newFile = file->curFile;
			newOffset = (file->curOffset + file->pos) + offset;
			break;
#ifdef NOT_USED
		case SEEK_END:
			/* could be implemented, not needed currently */
			break;
#endif
		default:
			elog(ERROR, "invalid whence: %d", whence);
			return EOF;
	}
	while (newOffset < 0)
	{
		if (--newFile < 0)
			return EOF;
		newOffset += MAX_PHYSICAL_FILESIZE;
	}
	if (newFile == file->curFile &&
		newOffset >= file->curOffset &&
		newOffset <= file->curOffset + file->nbytes)
	{
		/*
		 * Seek is to a point within existing buffer; we can just adjust
		 * pos-within-buffer, without flushing buffer.  Note this is OK
		 * whether reading or writing, but buffer remains dirty if we were
		 * writing.
		 */
		file->pos = (int) (newOffset - file->curOffset);
		return 0;
	}
	/* Otherwise, must reposition buffer, so flush any dirty data */
	if (BufFileFlush(file) != 0)
		return EOF;

	/*
	 * At this point and no sooner, check for seek past last segment. The
	 * above flush could have created a new segment, so checking sooner would
	 * not work (at least not with this code).
	 */
	if (file->isTemp)
	{
		/* convert seek to "start of next seg" to "end of last seg" */
		if (newFile == file->numFiles && newOffset == 0)
		{
			newFile--;
			newOffset = MAX_PHYSICAL_FILESIZE;
		}
		while (newOffset > MAX_PHYSICAL_FILESIZE)
		{
			if (++newFile >= file->numFiles)
				return EOF;
			newOffset -= MAX_PHYSICAL_FILESIZE;
		}
	}
	if (newFile >= file->numFiles)
		return EOF;
	/* Seek is OK! */
	file->curFile = newFile;
	if (!data_encrypted)
	{
		file->curOffset = newOffset;
		file->pos = 0;
		file->nbytes = 0;
	}
	else
	{
		/*
		 * Offset of an encrypted buffer must be a multiple of BLCKSZ.
		 */
		file->pos = newOffset % BLCKSZ;
		file->curOffset = newOffset - file->pos;

		/*
		 * BufFileLoadBuffer() will set nbytes iff it can read something.
		 */
		file->nbytes = 0;

		/*
		 * Load and decrypt the existing part of the buffer.
		 */
		BufFileLoadBuffer(file);
		if (file->nbytes == 0)
		{
			/*
			 * The data requested is not in the file, but this is not an
			 * error.
			 */
			return 0;
		}

		/*
		 * The whole buffer should have been loaded.
		 */
		Assert(file->nbytes == BLCKSZ);
	}
	return 0;
}

void
BufFileTell(BufFile *file, int *fileno, off_t *offset)
{
	*fileno = file->curFile;
	*offset = file->curOffset + file->pos;
}

/*
 * BufFileSeekBlock --- block-oriented seek
 *
 * Performs absolute seek to the start of the n'th BLCKSZ-sized block of
 * the file.  Note that users of this interface will fail if their files
 * exceed BLCKSZ * LONG_MAX bytes, but that is quite a lot; we don't work
 * with tables bigger than that, either...
 *
 * Result is 0 if OK, EOF if not.  Logical position is not moved if an
 * impossible seek is attempted.
 */
int
BufFileSeekBlock(BufFile *file, long blknum)
{
	return BufFileSeek(file,
					   (int) (blknum / BUFFILE_SEG_SIZE),
					   (off_t) (blknum % BUFFILE_SEG_SIZE) * BLCKSZ,
					   SEEK_SET);
}

#ifdef USE_OPENSSL
static void
BufFileTweak(char *tweak, BufFile *file, int curFile, off_t offset)
{
	off_t block = (curFile * (MAX_PHYSICAL_FILESIZE/BLCKSZ)) + offset/BLCKSZ;
	memcpy(tweak, file->tweakBase, TWEAK_SIZE);
	*((off_t*) tweak) = *((off_t*) tweak) ^ block;
}

/*
 * Extend that BufFile.useful array has the required size.
 */
static void
ensureBufFileUsefulArraySize(BufFile *file, int required)
{
	/*
	 * Does the array already have enough space?
	 */
	if (required <= file->nuseful)
		return;

	/*
	 * It shouldn't be possible to jump beyond the end of the last segment,
	 * i.e. skip more than 1 segment.
	 */
	Assert(file->nuseful + 1 == required);

	file->useful = (off_t *) repalloc(file->useful, required * sizeof(off_t));
	file->useful[file->nuseful] = 0L;
	file->nuseful++;
}
#endif

#ifdef NOT_USED
/*
 * BufFileTellBlock --- block-oriented tell
 *
 * Any fractional part of a block in the current seek position is ignored.
 */
long
BufFileTellBlock(BufFile *file)
{
	long		blknum;

	blknum = (file->curOffset + file->pos) / BLCKSZ;
	blknum += file->curFile * BUFFILE_SEG_SIZE;
	return blknum;
}

#endif
