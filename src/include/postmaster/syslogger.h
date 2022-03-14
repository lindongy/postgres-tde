/*-------------------------------------------------------------------------
 *
 * syslogger.h
 *	  Exports from postmaster/syslogger.c.
 *
 * Copyright (c) 2004-2021, PostgreSQL Global Development Group
 *
 * src/include/postmaster/syslogger.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef _SYSLOGGER_H
#define _SYSLOGGER_H

#include <limits.h>				/* for PIPE_BUF */


/*
 * Primitive protocol structure for writing to syslogger pipe(s).  The idea
 * here is to divide long messages into chunks that are not more than
 * PIPE_BUF bytes long, which according to POSIX spec must be written into
 * the pipe atomically.  The pipe reader then uses the protocol headers to
 * reassemble the parts of a message into a single string.  The reader can
 * also cope with non-protocol data coming down the pipe, though we cannot
 * guarantee long strings won't get split apart.
 *
 * We use non-nul bytes in is_last to make the protocol a tiny bit
 * more robust against finding a false double nul byte prologue. But
 * we still might find it in the len and/or pid bytes unless we're careful.
 */

#ifdef PIPE_BUF
/* Are there any systems with PIPE_BUF > 64K?  Unlikely, but ... */
#if PIPE_BUF > 65536
#define PIPE_CHUNK_SIZE  65536
#else
#define PIPE_CHUNK_SIZE  ((int) PIPE_BUF)
#endif
#else							/* not defined */
/* POSIX says the value of PIPE_BUF must be at least 512, so use that */
#define PIPE_CHUNK_SIZE  512
#endif

typedef struct
{
	char		nuls[2];		/* always \0\0 */
	uint16		len;			/* size of this chunk (counts data only) */
	int32		pid;			/* writer's pid */
	unsigned char stream_id;	/* 0 for core, > 0 for extensions */
	char		is_last;		/* last chunk of message? 't' or 'f' ('T' or
								 * 'F' for CSV case) */
	char		data[FLEXIBLE_ARRAY_MEMBER];	/* data payload starts here */
} PipeProtoHeader;

typedef union
{
	PipeProtoHeader proto;
	char		filler[PIPE_CHUNK_SIZE];
} PipeProtoChunk;

#define PIPE_HEADER_SIZE  offsetof(PipeProtoHeader, data)
#define PIPE_MAX_PAYLOAD  ((int) (PIPE_CHUNK_SIZE - PIPE_HEADER_SIZE))

/*
 * The maximum number of log streams the syslogger can collect data from.
 *
 * If increasing this, make sure the new value fits in the stream_id field of
 * PipeProtoHeader.
 */
#define MAXLOGSTREAMS 8

/* GUC options */
extern bool Logging_collector;

/*
 * ereport() associates each message with particular stream so that messages
 * from various sources can be logged to separate files. Each stream can
 * actually end up in multiple files, as specified by log destination
 * (LOG_DESTINATION_STDERR, LOG_DESTINATION_CSVLOG, ...).
 */
typedef struct LogStream
{
	/*
	 * The following variables can take their value from the related GUCs.
	 */
	int			verbosity;
	int			destination;
	char	   *directory;
	char	   *filename;
	int			file_mode;
	int			rotation_age;
	int			rotation_size;
	bool		truncate_on_rotation;
	char	   *line_prefix;

	char	   *id;

	pg_time_t	next_rotation_time;
	bool		rotation_needed;
	int			current_rotation_age;
	FILE	   *syslog_file;
#ifdef EXEC_BACKEND
#ifndef WIN32
	int			syslog_fd;
#else							/* WIN32 */
	long		syslog_fd;
#endif							/* WIN32 */
#endif							/* EXEC_BACKEND */
	FILE	   *csvlog_file;
	char	   *last_file_name;
	char	   *last_csv_file_name;
	char	   *current_dir;
	char	   *current_filename;
} LogStream;

#ifdef EXEC_BACKEND
extern bool log_streams_initialized;

/*
 * directory, filename and line_prefix need to be passed in the EXEC_BACKEND
 * case, so store the actual strings, not just pointers. Since there's no size
 * limit on line_prefix, put it at the end of the structure.
 */
typedef struct LogStreamFlat
{
	Size		size;
	int			verbosity;
	int			destination;
	char		directory[MAXPGPATH];
	char		filename[MAXPGPATH];
	char		id[MAXPGPATH];
	int			file_mode;
	int			rotation_age;
	int			rotation_size;
	bool		truncate_on_rotation;

#ifndef WIN32
	int			syslog_fd;
#else							/* WIN32 */
	long		syslog_fd;
#endif							/* WIN32 */

	char		line_prefix[FLEXIBLE_ARRAY_MEMBER];
} LogStreamFlat;

/*
 * The structures are stored w/o alignment, so the next one can immediately
 * follow the end of line_prefix.
 */
#define LOG_STREAM_FLAT_SIZE(s) (offsetof(LogStreamFlat, line_prefix) + \
								 strlen((s)->line_prefix) + 1)
#endif							/* EXEC_BACKEND */

extern LogStream log_streams[MAXLOGSTREAMS];
extern int	log_streams_active;

#ifndef WIN32
extern int	syslogPipe[2];
#else
extern HANDLE syslogPipe[2];
#endif


extern int	SysLogger_Start(void);

extern void write_syslogger_file(const char *buffer, int count, int dest,
					 int stream_id);
extern int	get_log_stream(char *id, LogStream **stream_p);

/*
 * Convenience macro to set string attributes of LogStream.
 *
 * String values that caller sets must be allocated in the TopMemoryContext or
 * malloc'd. (The latter is true if pointers to the stream fields are passed
 * to GUC framework).
 */
#define adjust_log_stream_attr(oldval_p, newval) \
	(*(oldval_p) = MemoryContextStrdup(TopMemoryContext, (newval)))

#ifdef EXEC_BACKEND
extern void SysLoggerMain(int argc, char *argv[]) pg_attribute_noreturn();
#endif

extern bool CheckLogrotateSignal(void);
extern void RemoveLogrotateSignalFiles(void);

/*
 * Name of files saving meta-data information about the log
 * files currently in use by the syslogger
 */
#define LOG_METAINFO_DATAFILE  "current_logfiles"
#define LOG_METAINFO_DATAFILE_TMP  LOG_METAINFO_DATAFILE ".tmp"

#endif							/* _SYSLOGGER_H */
