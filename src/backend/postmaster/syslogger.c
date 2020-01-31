/*-------------------------------------------------------------------------
 *
 * syslogger.c
 *
 * The system logger (syslogger) appeared in Postgres 8.0. It catches all
 * stderr output from the postmaster, backends, and other subprocesses
 * by redirecting to a pipe, and writes it to a set of logfiles.
 * It's possible to have size and age limits for the logfile configured
 * in postgresql.conf. If these limits are reached or passed, the
 * current logfile is closed and a new one is created (rotated).
 * The logfiles are stored in a subdirectory (configurable in
 * postgresql.conf), using a user-selectable naming scheme.
 *
 * Author: Andreas Pflug <pgadmin@pse-consulting.de>
 *
 * Copyright (c) 2004-2019, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/postmaster/syslogger.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "common/file_perm.h"
#include "lib/stringinfo.h"
#include "libpq/pqsignal.h"
#include "miscadmin.h"
#include "nodes/pg_list.h"
#include "pgstat.h"
#include "pgtime.h"
#include "postmaster/fork_process.h"
#include "postmaster/postmaster.h"
#include "postmaster/syslogger.h"
#include "storage/dsm.h"
#include "storage/fd.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/pg_shmem.h"
#include "tcop/tcopprot.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/ps_status.h"
#include "utils/timestamp.h"

/*
 * We read() into a temp buffer twice as big as a chunk, so that any fragment
 * left after processing can be moved down to the front and we'll still have
 * room to read a full chunk.
 */
#define READ_BUF_SIZE (2 * PIPE_CHUNK_SIZE)

/* Log rotation signal file path, relative to $PGDATA */
#define LOGROTATE_SIGNAL_FILE	"logrotate"


/*
 * GUC parameters.  Logging_collector cannot be changed after postmaster
 * start, but the rest can change at SIGHUP.
 */
bool		Logging_collector = false;

/*
 * Globally visible state (used by elog.c)
 */
bool		am_syslogger = false;

extern bool redirection_done;

/*
 * Private state
 */

static bool pipe_eof_seen = false;
static bool rotation_disabled = false;
NON_EXEC_STATIC pg_time_t first_syslogger_file_time;

LogStream	log_streams[MAXLOGSTREAMS];

/* At least the core log stream should be active. */
int			log_streams_active = 1;

/*
 * Buffers for saving partial messages from different backends.
 *
 * Keep NBUFFER_LISTS lists of these, with the entry for a given source pid
 * being in the list numbered (pid % NBUFFER_LISTS), so as to cut down on
 * the number of entries we have to examine for any one incoming message.
 * There must never be more than one entry for the same source pid.
 *
 * stream_id is needed because of flush_pipe_input.
 *
 * An inactive buffer is not removed from its list, just held for re-use.
 * An inactive buffer has pid == 0 and undefined contents of data.
 */
typedef struct
{
	int32		pid;			/* PID of source process */
	int32		stream_id;		/* Stream identifier. */
	StringInfoData data;		/* accumulated data, as a StringInfo */
} save_buffer;

#define NBUFFER_LISTS 256
static List *buffer_lists[NBUFFER_LISTS];

/* These must be exported for EXEC_BACKEND case ... annoying */
#ifndef WIN32
int			syslogPipe[2] = {-1, -1};
#else
HANDLE		syslogPipe[2] = {0, 0};
#endif

#ifdef WIN32
static HANDLE threadHandle = 0;
static CRITICAL_SECTION sysloggerSection;
#endif

/*
 * Flags set by interrupt handlers for later service in the main loop.
 */
static volatile sig_atomic_t got_SIGHUP = false;

/* Rotation of all logs requested by pg_rotate_logfile? */
static volatile sig_atomic_t rotation_requested = false;


/* Local subroutines */
#ifdef EXEC_BACKEND
static pid_t syslogger_forkexec(void);
#endif
NON_EXEC_STATIC void SysLoggerMain(int argc, char *argv[]) pg_attribute_noreturn();
static void process_pipe_input(char *logbuffer, int *bytes_in_logbuffer);
static void flush_pipe_input(char *logbuffer, int *bytes_in_logbuffer);
static FILE *logfile_open(const char *filename, const char *mode,
			 bool allow_errors, int stream_id);

#ifdef WIN32
static unsigned int __stdcall pipeThread(void *arg);
#endif
static void logfile_rotate(bool time_based_rotation, int size_rotation_for,
			   int stream_id);
static char *logfile_getname(pg_time_t timestamp, const char *suffix,
				int stream_id);
static void set_next_rotation_time(int stream_id);
static void sigHupHandler(SIGNAL_ARGS);
static void sigUsr1Handler(SIGNAL_ARGS);

static void update_metainfo_datafile(void);


/*
 * Main entry point for syslogger process
 * argc/argv parameters are valid only in EXEC_BACKEND case.
 */
NON_EXEC_STATIC void
SysLoggerMain(int argc, char *argv[])
{
#ifndef WIN32
	char		logbuffer[READ_BUF_SIZE];
	int			bytes_in_logbuffer = 0;
#endif
	pg_time_t	now;
	int			i;
	bool		timeout_valid;

	WaitEventSet *wes;

	now = MyStartTime;

	/*
	 * Initialize configuration parameters and status info.
	 *
	 * XXX Should we only do this for log_stream[0]? get_log_stream() does so
	 * for the extension streams.
	 */
	for (i = 0; i < log_streams_active; i++)
	{
		LogStream  *stream = &log_streams[i];

		stream->rotation_needed = false;
		stream->last_file_name = NULL;
		stream->last_csv_file_name = NULL;
	}

#ifdef EXEC_BACKEND
	for (i = 0; i < log_streams_active; i++)
	{
		LogStream  *stream = &log_streams[i];
		int			fd = stream->syslog_fd;

#ifndef WIN32
		if (fd != -1)
		{
			stream->syslog_file = fdopen(fd, "a");
			setvbuf(stream->syslog_file, NULL, PG_IOLBF, 0);
		}
#else							/* WIN32 */
		if (fd != 0)
		{
			fd = _open_osfhandle(fd, _O_APPEND | _O_TEXT);
			if (fd > 0)
			{
				stream->syslog_file = fdopen(fd, "a");
				setvbuf(stream->syslog_file, NULL, PG_IOLBF, 0);
			}
		}
#endif							/* WIN32 */
	}
#endif							/* EXEC_BACKEND */

	am_syslogger = true;

	init_ps_display("logger", "", "", "");

	/*
	 * If we restarted, our stderr is already redirected into our own input
	 * pipe.  This is of course pretty useless, not to mention that it
	 * interferes with detecting pipe EOF.  Point stderr to /dev/null. This
	 * assumes that all interesting messages generated in the syslogger will
	 * come through elog.c and will be sent to write_syslogger_file.
	 */
	if (redirection_done)
	{
		int			fd = open(DEVNULL, O_WRONLY, 0);

		/*
		 * The closes might look redundant, but they are not: we want to be
		 * darn sure the pipe gets closed even if the open failed.  We can
		 * survive running with stderr pointing nowhere, but we can't afford
		 * to have extra pipe input descriptors hanging around.
		 *
		 * As we're just trying to reset these to go to DEVNULL, there's not
		 * much point in checking for failure from the close/dup2 calls here,
		 * if they fail then presumably the file descriptors are closed and
		 * any writes will go into the bitbucket anyway.
		 */
		close(fileno(stdout));
		close(fileno(stderr));
		if (fd != -1)
		{
			(void) dup2(fd, fileno(stdout));
			(void) dup2(fd, fileno(stderr));
			close(fd);
		}
	}

	/*
	 * Syslogger's own stderr can't be the syslogPipe, so set it back to text
	 * mode if we didn't just close it. (It was set to binary in
	 * SubPostmasterMain).
	 */
#ifdef WIN32
	else
		_setmode(_fileno(stderr), _O_TEXT);
#endif

	/*
	 * Also close our copy of the write end of the pipe.  This is needed to
	 * ensure we can detect pipe EOF correctly.  (But note that in the restart
	 * case, the postmaster already did this.)
	 */
#ifndef WIN32
	if (syslogPipe[1] >= 0)
		close(syslogPipe[1]);
	syslogPipe[1] = -1;
#else
	if (syslogPipe[1])
		CloseHandle(syslogPipe[1]);
	syslogPipe[1] = 0;
#endif

	/*
	 * Properly accept or ignore signals the postmaster might send us
	 *
	 * Note: we ignore all termination signals, and instead exit only when all
	 * upstream processes are gone, to ensure we don't miss any dying gasps of
	 * broken backends...
	 */

	pqsignal(SIGHUP, sigHupHandler);	/* set flag to read config file */
	pqsignal(SIGINT, SIG_IGN);
	pqsignal(SIGTERM, SIG_IGN);
	pqsignal(SIGQUIT, SIG_IGN);
	pqsignal(SIGALRM, SIG_IGN);
	pqsignal(SIGPIPE, SIG_IGN);
	pqsignal(SIGUSR1, sigUsr1Handler);	/* request log rotation */
	pqsignal(SIGUSR2, SIG_IGN);

	/*
	 * Reset some signals that are accepted by postmaster but not here
	 */
	pqsignal(SIGCHLD, SIG_DFL);

	PG_SETMASK(&UnBlockSig);

#ifdef WIN32
	/* Fire up separate data transfer thread */
	InitializeCriticalSection(&sysloggerSection);
	EnterCriticalSection(&sysloggerSection);

	threadHandle = (HANDLE) _beginthreadex(NULL, 0, pipeThread, NULL, 0, NULL);
	if (threadHandle == 0)
		elog(FATAL, "could not create syslogger data transfer thread: %m");
#endif							/* WIN32 */

	/*
	 * Remember active logfiles' name(s).  We recompute 'em from the reference
	 * time because passing down just the pg_time_t is a lot cheaper than
	 * passing a whole file path in the EXEC_BACKEND case.
	 */
	for (i = 0; i < log_streams_active; i++)
	{
		LogStream  *stream = &log_streams[i];

		stream->last_file_name = logfile_getname(first_syslogger_file_time,
												 NULL, i);
		if (stream->csvlog_file != NULL)
			stream->last_csv_file_name = logfile_getname(first_syslogger_file_time,
														 ".csv", i);

		/* remember active logfile parameters */
		stream->current_dir = pstrdup(stream->directory);
		stream->current_filename = pstrdup(stream->filename);
		stream->current_rotation_age = stream->rotation_age;

		/* set next planned rotation time */
		set_next_rotation_time(i);
	}
	update_metainfo_datafile();

	/*
	 * Reset whereToSendOutput, as the postmaster will do (but hasn't yet, at
	 * the point where we forked).  This prevents duplicate output of messages
	 * from syslogger itself.
	 */
	whereToSendOutput = DestNone;

	/*
	 * Set up a reusable WaitEventSet object we'll use to wait for our latch,
	 * and (except on Windows) our socket.
	 *
	 * Unlike all other postmaster child processes, we'll ignore postmaster
	 * death because we want to collect final log output from all backends and
	 * then exit last.  We'll do that by running until we see EOF on the
	 * syslog pipe, which implies that all other backends have exited
	 * (including the postmaster).
	 */
	wes = CreateWaitEventSet(CurrentMemoryContext, 2);
	AddWaitEventToSet(wes, WL_LATCH_SET, PGINVALID_SOCKET, MyLatch, NULL);
#ifndef WIN32
	AddWaitEventToSet(wes, WL_SOCKET_READABLE, syslogPipe[0], NULL, NULL);
#endif

	/* main worker loop */
	for (;;)
	{
		long		cur_timeout;
		WaitEvent	event;
		int	i;

#ifndef WIN32
		int			rc;
#endif

		/* Clear any already-pending wakeups */
		ResetLatch(MyLatch);

		/*
		 * Process any requests or signals received recently.
		 */
		if (got_SIGHUP)
		{
			got_SIGHUP = false;
			ProcessConfigFile(PGC_SIGHUP);

			for (i = 0; i < log_streams_active; i++)
			{
				LogStream  *stream = &log_streams[i];

				/*
				 * Check if the log directory or filename pattern changed in
				 * postgresql.conf. If so, force rotation to make sure we're
				 * writing the logfiles in the right place.
				 */
				if (strcmp(stream->directory, stream->current_dir) != 0)
				{
					pfree(stream->current_dir);
					stream->current_dir = pstrdup(stream->directory);
					stream->rotation_needed = true;

					/*
					 * Also, create new directory if not present; ignore
					 * errors
					 */
					(void) MakePGDirectory(stream->directory);
				}
				if (strcmp(stream->filename, stream->current_filename) != 0)
				{
					pfree(stream->current_filename);
					stream->current_filename = pstrdup(stream->filename);
					stream->rotation_needed = true;
				}

				/*
				 * Force a rotation if CSVLOG output was just turned on or off
				 * and we need to open or close csvlog_file accordingly.
				 */
				if (((stream->destination & LOG_DESTINATION_CSVLOG) != 0) !=
					(stream->csvlog_file != NULL))
					stream->rotation_needed = true;

				/*
				 * If rotation time parameter changed, reset next rotation
				 * time, but don't immediately force a rotation.
				 */
				if (stream->current_rotation_age != stream->rotation_age)
				{
					stream->current_rotation_age = stream->rotation_age;
					set_next_rotation_time(i);
				}
			}

			/*
			 * If we had a rotation-disabling failure, re-enable rotation
			 * attempts after SIGHUP, and force one immediately.
			 */
			if (rotation_disabled)
			{
				rotation_disabled = false;
				rotation_requested = true;
			}

			/*
			 * Force rewriting last log filename when reloading configuration.
			 * Even if rotation_requested is false, log_destination may have
			 * been changed and we don't want to wait the next file rotation.
			 */
			update_metainfo_datafile();
		}

		for (i = 0; i < log_streams_active; i++)
		{
			bool		time_based_rotation = false;
			int			size_rotation_for = 0;
			LogStream  *stream = &log_streams[i];

			if (stream->current_rotation_age > 0 && !rotation_disabled)
			{
				/* Do a logfile rotation if it's time */
				now = (pg_time_t) time(NULL);
				if (now >= stream->next_rotation_time)
				{
					time_based_rotation = true;
					stream->rotation_needed = true;
				}
			}

			if (!rotation_requested && stream->rotation_size > 0 &&
				!rotation_disabled)
			{
				/* Do a rotation if file is too big */
				if (ftell(stream->syslog_file) >=
					stream->rotation_size * 1024L)
				{
					stream->rotation_needed = true;
					size_rotation_for |= LOG_DESTINATION_STDERR;
				}
				if (stream->csvlog_file != NULL &&
					ftell(stream->csvlog_file) >=
					stream->rotation_size * 1024L)
				{
					stream->rotation_needed = true;
					size_rotation_for |= LOG_DESTINATION_CSVLOG;
				}
			}

			/*
			 * Consider rotation if the current file needs it or if rotation
			 * of all files has been requested explicitly.
			 */
			if (stream->rotation_needed || rotation_requested)
			{
				/*
				 * Force rotation when both values are zero. It means the
				 * request was sent by pg_rotate_logfile() or "pg_ctl
				 * logrotate".
				 */
				if (rotation_requested && !time_based_rotation &&
					size_rotation_for == 0)
					size_rotation_for = LOG_DESTINATION_STDERR |
						LOG_DESTINATION_CSVLOG;

				logfile_rotate(time_based_rotation, size_rotation_for, i);
			}
		}

		if (rotation_requested)
			rotation_requested = false;

		/*
		 * Calculate time till next time-based rotation, so that we don't
		 * sleep longer than that.  We assume the value of "now" obtained
		 * above is still close enough.  Note we can't make this calculation
		 * until after calling logfile_rotate(), since it will advance
		 * next_rotation_time.
		 *
		 * Also note that we need to beware of overflow in calculation of the
		 * timeout: with large settings of current_rotation_age,
		 * next_rotation_time could be more than INT_MAX msec in the future.
		 * In that case we'll wait no more than INT_MAX msec, and try again.
		 */
		timeout_valid = false;
		for (i = 0; i < log_streams_active; i++)
		{
			LogStream  *stream = &log_streams[i];

			if (stream->current_rotation_age > 0 && !rotation_disabled)
			{
				pg_time_t	delay;
				long		timeout_tmp;

				delay = stream->next_rotation_time - now;
				if (delay > 0)
				{
					if (delay > INT_MAX / 1000)
						delay = INT_MAX / 1000;
					timeout_tmp = delay * 1000L;	/* msec */
				}
				else
					timeout_tmp = 0;

				/* Looking for the nearest timeout across log files. */
				if (!timeout_valid)
				{
					/* cur_timeout not defined yet. */
					cur_timeout = timeout_tmp;
					timeout_valid = true;
				}
				else
					cur_timeout = Min(cur_timeout, timeout_tmp);
			}
		}
		if (!timeout_valid)
			cur_timeout = -1L;

		/*
		 * Sleep until there's something to do
		 */
#ifndef WIN32
		rc = WaitEventSetWait(wes, cur_timeout, &event, 1,
							  WAIT_EVENT_SYSLOGGER_MAIN);

		if (rc == 1 && event.events == WL_SOCKET_READABLE)
		{
			int			bytesRead;

			bytesRead = read(syslogPipe[0],
							 logbuffer + bytes_in_logbuffer,
							 sizeof(logbuffer) - bytes_in_logbuffer);
			if (bytesRead < 0)
			{
				if (errno != EINTR)
					ereport(LOG,
							(errcode_for_socket_access(),
							 errmsg("could not read from logger pipe: %m")));
			}
			else if (bytesRead > 0)
			{
				bytes_in_logbuffer += bytesRead;
				process_pipe_input(logbuffer, &bytes_in_logbuffer);
				continue;
			}
			else
			{
				/*
				 * Zero bytes read when select() is saying read-ready means
				 * EOF on the pipe: that is, there are no longer any processes
				 * with the pipe write end open.  Therefore, the postmaster
				 * and all backends are shut down, and we are done.
				 */
				pipe_eof_seen = true;

				/* if there's any data left then force it out now */
				flush_pipe_input(logbuffer, &bytes_in_logbuffer);
			}
		}
#else							/* WIN32 */

		/*
		 * On Windows we leave it to a separate thread to transfer data and
		 * detect pipe EOF.  The main thread just wakes up to handle SIGHUP
		 * and rotation conditions.
		 *
		 * Server code isn't generally thread-safe, so we ensure that only one
		 * of the threads is active at a time by entering the critical section
		 * whenever we're not sleeping.
		 */
		LeaveCriticalSection(&sysloggerSection);

		(void) WaitEventSetWait(wes, cur_timeout, &event, 1,
								WAIT_EVENT_SYSLOGGER_MAIN);

		EnterCriticalSection(&sysloggerSection);
#endif							/* WIN32 */

		if (pipe_eof_seen)
		{
			/*
			 * seeing this message on the real stderr is annoying - so we make
			 * it DEBUG1 to suppress in normal use.
			 */
			ereport(DEBUG1,
					(errmsg("logger shutting down")));

			/*
			 * Normal exit from the syslogger is here.  Note that we
			 * deliberately do not close syslog_file before exiting; this is
			 * to allow for the possibility of elog messages being generated
			 * inside proc_exit.  Regular exit() will take care of flushing
			 * and closing stdio channels.
			 */
			proc_exit(0);
		}
	}
}

/*
 * Postmaster subroutine to start a syslogger subprocess.
 */
int
SysLogger_Start(void)
{
	pid_t		sysloggerPid;
	int			i;
	LogStream  *stream;

	if (!Logging_collector)
		return 0;

	/*
	 * If first time through, create the pipe which will receive stderr
	 * output.
	 *
	 * If the syslogger crashes and needs to be restarted, we continue to use
	 * the same pipe (indeed must do so, since extant backends will be writing
	 * into that pipe).
	 *
	 * This means the postmaster must continue to hold the read end of the
	 * pipe open, so we can pass it down to the reincarnated syslogger. This
	 * is a bit klugy but we have little choice.
	 */
#ifndef WIN32
	if (syslogPipe[0] < 0)
	{
		if (pipe(syslogPipe) < 0)
			ereport(FATAL,
					(errcode_for_socket_access(),
					 (errmsg("could not create pipe for syslog: %m"))));
	}
#else
	if (!syslogPipe[0])
	{
		SECURITY_ATTRIBUTES sa;

		memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle = TRUE;

		if (!CreatePipe(&syslogPipe[0], &syslogPipe[1], &sa, 32768))
			ereport(FATAL,
					(errcode_for_file_access(),
					 (errmsg("could not create pipe for syslog: %m"))));
	}
#endif

	/*
	 * Although we can't check here if the streams are initialized in a
	 * sensible way, check at least if user (typically extension) messed any
	 * setting up.
	 */
	for (i = 0; i < log_streams_active; i++)
	{
		stream = &log_streams[i];
		if (stream->directory == NULL || stream->filename == NULL ||
			stream->rotation_age == 0 || stream->rotation_size == 0)
			ereport(FATAL,
					(errmsg("Log stream %d is not properly initialized", i)));
	}

	/*
	 * Create log directories if not present; ignore errors
	 */
	for (i = 0; i < log_streams_active; i++)
		(void) MakePGDirectory(log_streams[i].directory);

	first_syslogger_file_time = time(NULL);
	for (i = 0; i < log_streams_active; i++)
	{
		char	   *filename;

		stream = &log_streams[i];

		/*
		 * The initial logfile is created right in the postmaster, to verify
		 * that the log directory is writable.  We save the reference time so
		 * that the syslogger child process can recompute this file name.
		 *
		 * It might look a bit strange to re-do this during a syslogger
		 * restart, but we must do so since the postmaster closed syslog_file
		 * after the previous fork (and remembering that old file wouldn't be
		 * right anyway).  Note we always append here, we won't overwrite any
		 * existing file.  This is consistent with the normal rules, because
		 * by definition this is not a time-based rotation.
		 */
		filename = logfile_getname(first_syslogger_file_time, NULL, i);
		stream->syslog_file = logfile_open(filename, "a", false, i);
		pfree(filename);

		/*
		 * Likewise for the initial CSV log file, if that's enabled.  (Note
		 * that we open syslogFile even when only CSV output is nominally
		 * enabled, since some code paths will write to syslogFile anyway.)
		 */
		if (stream->destination & LOG_DESTINATION_CSVLOG)
		{
			filename = logfile_getname(first_syslogger_file_time, ".csv", i);

			stream->csvlog_file = logfile_open(filename, "a", false, i);

			pfree(filename);
		}
	}

#ifdef EXEC_BACKEND
	switch ((sysloggerPid = syslogger_forkexec()))
#else
	switch ((sysloggerPid = fork_process()))
#endif
	{
		case -1:
			ereport(LOG,
					(errmsg("could not fork system logger: %m")));
			return 0;

#ifndef EXEC_BACKEND
		case 0:
			/* in postmaster child ... */
			InitPostmasterChild();

			/* Close the postmaster's sockets */
			ClosePostmasterPorts(true);

			/* Drop our connection to postmaster's shared memory, as well */
			dsm_detach_all();
			PGSharedMemoryDetach();

			/* do the work */
			SysLoggerMain(0, NULL);
			break;
#endif

		default:
			/* success, in postmaster */

			/* now we redirect stderr, if not done already */
			if (!redirection_done)
			{
#ifdef WIN32
				int			fd;
#endif

				/*
				 * Leave a breadcrumb trail when redirecting, in case the user
				 * forgets that redirection is active and looks only at the
				 * original stderr target file.
				 *
				 * TODO Also list the extension log directories if there are
				 * some?
				 */
				ereport(LOG,
						(errmsg("redirecting log output to logging collector process"),
						 errhint("Future log output will appear in directory \"%s\".",
								 log_streams[0].directory)));

#ifndef WIN32
				fflush(stdout);
				if (dup2(syslogPipe[1], fileno(stdout)) < 0)
					ereport(FATAL,
							(errcode_for_file_access(),
							 errmsg("could not redirect stdout: %m")));
				fflush(stderr);
				if (dup2(syslogPipe[1], fileno(stderr)) < 0)
					ereport(FATAL,
							(errcode_for_file_access(),
							 errmsg("could not redirect stderr: %m")));
				/* Now we are done with the write end of the pipe. */
				close(syslogPipe[1]);
				syslogPipe[1] = -1;
#else

				/*
				 * open the pipe in binary mode and make sure stderr is binary
				 * after it's been dup'ed into, to avoid disturbing the pipe
				 * chunking protocol.
				 */
				fflush(stderr);
				fd = _open_osfhandle((intptr_t) syslogPipe[1],
									 _O_APPEND | _O_BINARY);
				if (dup2(fd, _fileno(stderr)) < 0)
					ereport(FATAL,
							(errcode_for_file_access(),
							 errmsg("could not redirect stderr: %m")));
				close(fd);
				_setmode(_fileno(stderr), _O_BINARY);

				/*
				 * Now we are done with the write end of the pipe.
				 * CloseHandle() must not be called because the preceding
				 * close() closes the underlying handle.
				 */
				syslogPipe[1] = 0;
#endif
				redirection_done = true;
			}

			/* postmaster will never write the files; close them */
			for (i = 0; i < log_streams_active; i++)
			{
				LogStream  *stream = &log_streams[i];

				fclose(stream->syslog_file);
				stream->syslog_file = NULL;

				if (stream->csvlog_file != NULL)
				{
					fclose(stream->csvlog_file);
					stream->csvlog_file = NULL;
				}
			}
			return (int) sysloggerPid;
	}

	/* we should never reach here */
	return 0;
}


#ifdef EXEC_BACKEND

/*
 * syslogger_forkexec() -
 *
 * Format up the arglist for, then fork and exec, a syslogger process
 */
static pid_t
syslogger_forkexec(void)
{
	char	   *av[10];
	int			ac = 0;
	int			i;

	av[ac++] = "postgres";
	av[ac++] = "--forklog";
	av[ac++] = NULL;			/* filled in by postmaster_forkexec */
	av[ac] = NULL;
	Assert(ac < lengthof(av));

	for (i = 0; i < log_streams_active; i++)
	{
		LogStream  *stream = &log_streams[i];

	/*
	 * Re-open the error output files that were opened by SysLogger_Start().
	 *
	 * We expect this will always succeed, which is too optimistic, but if it
	 * fails there's not a lot we can do to report the problem anyway.  As
	 * coded, we'll just crash on a null pointer dereference after failure...
	 */
#ifndef WIN32
		if (stream->syslog_file != NULL)
			stream->syslog_fd = fileno(stream->syslog_file);
		else
			stream->syslog_fd = -1;
#else							/* WIN32 */
		if (syslog_file != NULL)
			stream->syslog_fd = (long)
				_get_osfhandle(_fileno(stream->syslog_file));
		else
			stream->syslog_fd = 0;
#endif							/* WIN32 */
	}

	return postmaster_forkexec(ac, av);
}
#endif							/* EXEC_BACKEND */


/* --------------------------------
 *		pipe protocol handling
 * --------------------------------
 */

/*
 * Process data received through the syslogger pipe.
 *
 * This routine interprets the log pipe protocol which sends log messages as
 * (hopefully atomic) chunks - such chunks are detected and reassembled here.
 *
 * The protocol has a header that starts with two nul bytes, then has a 16 bit
 * length, the pid of the sending process, stream identifier, and a flag to
 * indicate if it is the last chunk in a message. Incomplete chunks are saved
 * until we read some more, and non-final chunks are accumulated until we get
 * the final chunk.
 *
 * All of this is to avoid 2 problems:
 * . partial messages being written to logfiles (messes rotation), and
 * . messages from different backends being interleaved (messages garbled).
 *
 * The stream identifier is in the header to ensure correct routing into log
 * files, however message chunks of different streams sent by the same backend
 * are not expected to be interleaved.
 *
 * Any non-protocol messages are written out directly. These should only come
 * from non-PostgreSQL sources, however (e.g. third party libraries writing to
 * stderr).
 *
 * logbuffer is the data input buffer, and *bytes_in_logbuffer is the number
 * of bytes present.  On exit, any not-yet-eaten data is left-justified in
 * logbuffer, and *bytes_in_logbuffer is updated.
 */
static void
process_pipe_input(char *logbuffer, int *bytes_in_logbuffer)
{
	char	   *cursor = logbuffer;
	int			count = *bytes_in_logbuffer;
	int			dest = LOG_DESTINATION_STDERR;

	/* While we have enough for a header, process data... */
	while (count >= (int) (offsetof(PipeProtoHeader, data) + 1))
	{
		PipeProtoHeader p;
		int			chunklen;

		/* Do we have a valid header? */
		memcpy(&p, cursor, offsetof(PipeProtoHeader, data));
		if (p.nuls[0] == '\0' && p.nuls[1] == '\0' &&
			p.len > 0 && p.len <= PIPE_MAX_PAYLOAD &&
			p.pid != 0 &&
			p.stream_id >= 0 && p.stream_id < MAXLOGSTREAMS &&
			(p.is_last == 't' || p.is_last == 'f' ||
			 p.is_last == 'T' || p.is_last == 'F'))
		{
			List	   *buffer_list;
			ListCell   *cell;
			save_buffer *existing_slot = NULL,
					   *free_slot = NULL;
			StringInfo	str;

			chunklen = PIPE_HEADER_SIZE + p.len;

			/* Fall out of loop if we don't have the whole chunk yet */
			if (count < chunklen)
				break;

			dest = (p.is_last == 'T' || p.is_last == 'F') ?
				LOG_DESTINATION_CSVLOG : LOG_DESTINATION_STDERR;

			/* Locate any existing buffer for this source pid */
			buffer_list = buffer_lists[p.pid % NBUFFER_LISTS];
			foreach(cell, buffer_list)
			{
				save_buffer *buf = (save_buffer *) lfirst(cell);

				if (buf->pid == p.pid)
				{
					existing_slot = buf;
					break;
				}
				if (buf->pid == 0 && free_slot == NULL)
					free_slot = buf;
			}

			if (p.is_last == 'f' || p.is_last == 'F')
			{
				/*
				 * Save a complete non-final chunk in a per-pid buffer
				 */
				if (existing_slot != NULL)
				{
					/* Add chunk to data from preceding chunks */
					str = &(existing_slot->data);
					appendBinaryStringInfo(str,
										   cursor + PIPE_HEADER_SIZE,
										   p.len);
				}
				else
				{
					/* First chunk of message, save in a new buffer */
					if (free_slot == NULL)
					{
						/*
						 * Need a free slot, but there isn't one in the list,
						 * so create a new one and extend the list with it.
						 */
						free_slot = palloc(sizeof(save_buffer));
						buffer_list = lappend(buffer_list, free_slot);
						buffer_lists[p.pid % NBUFFER_LISTS] = buffer_list;
					}
					free_slot->pid = p.pid;
					free_slot->stream_id = p.stream_id;
					str = &(free_slot->data);
					initStringInfo(str);
					appendBinaryStringInfo(str,
										   cursor + PIPE_HEADER_SIZE,
										   p.len);
				}
			}
			else
			{
				/*
				 * Final chunk --- add it to anything saved for that pid, and
				 * either way write the whole thing out.
				 */
				if (existing_slot != NULL)
				{
					str = &(existing_slot->data);
					appendBinaryStringInfo(str,
										   cursor + PIPE_HEADER_SIZE,
										   p.len);
					write_syslogger_file(str->data, str->len, dest,
										 existing_slot->stream_id);
					/* Mark the buffer unused, and reclaim string storage */
					existing_slot->pid = 0;
					pfree(str->data);
				}
				else
				{
					/* The whole message was one chunk, evidently. */
					write_syslogger_file(cursor + PIPE_HEADER_SIZE, p.len,
										 dest, p.stream_id);
				}
			}

			/* Finished processing this chunk */
			cursor += chunklen;
			count -= chunklen;
		}
		else
		{
			/* Process non-protocol data */

			/*
			 * Look for the start of a protocol header.  If found, dump data
			 * up to there and repeat the loop.  Otherwise, dump it all and
			 * fall out of the loop.  (Note: we want to dump it all if at all
			 * possible, so as to avoid dividing non-protocol messages across
			 * logfiles.  We expect that in many scenarios, a non-protocol
			 * message will arrive all in one read(), and we want to respect
			 * the read() boundary if possible.)
			 */
			for (chunklen = 1; chunklen < count; chunklen++)
			{
				if (cursor[chunklen] == '\0')
					break;
			}
			/* fall back on the stderr log as the destination */
			write_syslogger_file(cursor, chunklen, LOG_DESTINATION_STDERR, 0);
			cursor += chunklen;
			count -= chunklen;
		}
	}

	/* We don't have a full chunk, so left-align what remains in the buffer */
	if (count > 0 && cursor != logbuffer)
		memmove(logbuffer, cursor, count);
	*bytes_in_logbuffer = count;
}

/*
 * Force out any buffered data
 *
 * This is currently used only at syslogger shutdown, but could perhaps be
 * useful at other times, so it is careful to leave things in a clean state.
 */
static void
flush_pipe_input(char *logbuffer, int *bytes_in_logbuffer)
{
	int			i;

	/* Dump any incomplete protocol messages */
	for (i = 0; i < NBUFFER_LISTS; i++)
	{
		List	   *list = buffer_lists[i];
		ListCell   *cell;

		foreach(cell, list)
		{
			save_buffer *buf = (save_buffer *) lfirst(cell);

			if (buf->pid != 0)
			{
				StringInfo	str = &(buf->data);

				write_syslogger_file(str->data, str->len,
									 LOG_DESTINATION_STDERR, buf->stream_id);
				/* Mark the buffer unused, and reclaim string storage */
				buf->pid = 0;
				pfree(str->data);
			}
		}
	}

	/*
	 * Force out any remaining pipe data as-is; we don't bother trying to
	 * remove any protocol headers that may exist in it.
	 */
	if (*bytes_in_logbuffer > 0)
		write_syslogger_file(logbuffer, *bytes_in_logbuffer,
							 LOG_DESTINATION_STDERR, 0);
	*bytes_in_logbuffer = 0;
}

/* --------------------------------
 *		logfile routines
 * --------------------------------
 */

/*
 * Write text to the currently open logfile
 *
 * This is exported so that elog.c can call it when am_syslogger is true.
 * This allows the syslogger process to record elog messages of its own,
 * even though its stderr does not point at the syslog pipe.
 */
void
write_syslogger_file(const char *buffer, int count, int destination,
					 int stream_id)
{
	int			rc;
	FILE	   *logfile;
	LogStream  *stream = &log_streams[stream_id];

	/*
	 * If we're told to write to csvlogFile, but it's not open, dump the data
	 * to syslogFile (which is always open) instead.  This can happen if CSV
	 * output is enabled after postmaster start and we've been unable to open
	 * csvlogFile.  There are also race conditions during a parameter change
	 * whereby backends might send us CSV output before we open csvlogFile or
	 * after we close it.  Writing CSV-formatted output to the regular log
	 * file isn't great, but it beats dropping log output on the floor.
	 *
	 * Think not to improve this by trying to open csvlogFile on-the-fly.  Any
	 * failure in that would lead to recursion.
	 */
	logfile = (destination == LOG_DESTINATION_CSVLOG &&
			   stream->csvlog_file != NULL) ?
		stream->csvlog_file : stream->syslog_file;

	rc = fwrite(buffer, 1, count, logfile);

	/*
	 * Try to report any failure.  We mustn't use ereport because it would
	 * just recurse right back here, but write_stderr is OK: it will write
	 * either to the postmaster's original stderr, or to /dev/null, but never
	 * to our input pipe which would result in a different sort of looping.
	 */
	if (rc != count)
		write_stderr("could not write to log file: %s\n", strerror(errno));
}

/*
 * Extensions can use this function to write their output to separate log
 * files. The value returned is to be used as an argument in the errstream()
 * function, for example:
 *
 * ereport(ERROR,
 *				(errcode(ERRCODE_UNDEFINED_CURSOR),
 *				 errmsg("portal \"%s\" not found", stmt->portalname),
 *				 errstream(stream_id),
 *				 ... other errxxx() fields as needed ...));
 *
 * Caller is expected to pass a pointer to which the function writes a pointer
 * to LogStream structure, which is pre-initialized according to the core log
 * stream. Caller is expected to ensure that the log file path is eventually
 * different from that of the postgres core log.
 *
 * CAUTION: Use adjust_log_stream_attr() to set string attributes of the log
 * stream, as opposed to assigning arbitrary (char *) pointers directly.
 *
 * Note: The "id" argument is necessary so that repeated call of the function
 * from the same library makes no harm. The particular scenario is that shared
 * library can be re-loaded during child process startup due to EXEC_BACKEND
 * technique. Once we have the identifier, we can use it to make error
 * messages more convenient.
 *
 * XXX Do we need a function that validates the log stream after changes are
 * done? Probably not, as shared library developer should know what he is
 * doing.
 */
extern int
get_log_stream(char *id, LogStream **stream_p)
{
	int			result = -1;
	LogStream  *stream,
			   *stream_core;
	int			i;

	if (!process_shared_preload_libraries_in_progress)
		ereport(ERROR,
				(errmsg("get_log_stream() can only be called during shared "
						"library preload"),
				 errhint("Please check if your extension library is in "
						 "\"shared_preload_libraries\"")));

	if (log_streams_active >= MAXLOGSTREAMS)
		ereport(ERROR,
				(errmsg("The maximum number of log streams exceeded")));

	if (id == NULL || strlen(id) == 0)
		ereport(ERROR, (errmsg("stream id must be a non-empty string.")));

	/*
	 * The function is called twice in the EXEC_BACKEND case.
	 */
#ifdef EXEC_BACKEND
	if (log_streams_initialized)
	{
		/*
		 * If 2nd time here, only find the existing id among the extension
		 * streams.
		 */
		Assert(log_streams_active >= 1);
		for (i = 1; i < log_streams_active; i++)
		{
			LogStream  *stream = &log_streams[i];

			if (strcmp(id, stream->id) == 0)
			{
				result = i;
				break;
			}
		}
		Assert(result >= 0);
		*stream_p = &log_streams[result];
		return result;
	}
#endif

	/*
	 * Make sure the id is unique. (The core stream is not supposed to have
	 * id.)
	 */
	for (i = 1; i < log_streams_active; i++)
	{
		LogStream  *stream = &log_streams[i];

		if (strcmp(id, stream->id))
			ereport(ERROR, (errmsg("\"%s\" stream already exists", id)));
	}

	result = log_streams_active++;
	stream = &log_streams[result];
	memset(stream, 0, sizeof(LogStream));

	/*
	 * Set the default values.
	 *
	 * Duplicate the strings so that GUC does not break anything if it frees
	 * the core values.
	 */
	stream_core = &log_streams[0];
	stream->verbosity = stream_core->verbosity;
	stream->destination = stream_core->destination;
	adjust_log_stream_attr(&stream->id, id);
	adjust_log_stream_attr(&stream->filename, stream_core->filename);
	adjust_log_stream_attr(&stream->directory, stream_core->directory);
	adjust_log_stream_attr(&stream->line_prefix, stream_core->line_prefix);
	stream->file_mode = stream_core->file_mode;
	stream->rotation_age = stream_core->rotation_age;
	stream->rotation_size = stream_core->rotation_size;
	stream->truncate_on_rotation = stream_core->truncate_on_rotation;

	*stream_p = stream;
	return result;
}


#ifdef WIN32

/*
 * Worker thread to transfer data from the pipe to the current logfile.
 *
 * We need this because on Windows, WaitforMultipleObjects does not work on
 * unnamed pipes: it always reports "signaled", so the blocking ReadFile won't
 * allow for SIGHUP; and select is for sockets only.
 */
static unsigned int __stdcall
pipeThread(void *arg)
{
	char		logbuffer[READ_BUF_SIZE];
	int			bytes_in_logbuffer = 0;

	for (;;)
	{
		DWORD		bytesRead;
		BOOL		result;

		result = ReadFile(syslogPipe[0],
						  logbuffer + bytes_in_logbuffer,
						  sizeof(logbuffer) - bytes_in_logbuffer,
						  &bytesRead, 0);

		/*
		 * Enter critical section before doing anything that might touch
		 * global state shared by the main thread. Anything that uses
		 * palloc()/pfree() in particular are not safe outside the critical
		 * section.
		 */
		EnterCriticalSection(&sysloggerSection);
		if (!result)
		{
			DWORD		error = GetLastError();

			if (error == ERROR_HANDLE_EOF ||
				error == ERROR_BROKEN_PIPE)
				break;
			_dosmaperr(error);
			ereport(LOG,
					(errcode_for_file_access(),
					 errmsg("could not read from logger pipe: %m")));
		}
		else if (bytesRead > 0)
		{
			bytes_in_logbuffer += bytesRead;
			process_pipe_input(logbuffer, &bytes_in_logbuffer);
		}

		/*
		 * If we've filled the current logfile, nudge the main thread to do a
		 * log rotation.
		 */
		if (Log_RotationSize > 0)
		{
			int	i;

			for (i = 0; i < log_streams_active; i++)
			{
				LogStream  *stream = &log_streams[i];

				if (ftell(stream->syslog_file) >= Log_RotationSize * 1024L ||
					(stream->csvlog_file != NULL &&
					 ftell(stream->csvlog_file) >= Log_RotationSize * 1024L))
				{
					SetLatch(MyLatch);
					break;
				}
			}
		}
		LeaveCriticalSection(&sysloggerSection);
	}

	/* We exit the above loop only upon detecting pipe EOF */
	pipe_eof_seen = true;

	/* if there's any data left then force it out now */
	flush_pipe_input(logbuffer, &bytes_in_logbuffer);

	/* set the latch to waken the main thread, which will quit */
	SetLatch(MyLatch);

	LeaveCriticalSection(&sysloggerSection);
	_endthread();
	return 0;
}
#endif							/* WIN32 */

/*
 * Open a new logfile with proper permissions and buffering options.
 *
 * If allow_errors is true, we just log any open failure and return NULL (with
 * errno still correct for the fopen failure).  Otherwise, errors are treated
 * as fatal.
 *
 * TODO Should we check that no other stream uses the same file? If so,
 * consider the best portable way. (Comparison of the file path is not good
 * because some of the paths may be symlinks.) Can we rely on fileno() to
 * return the same number if the same file is opened by the same process
 * multiple times?
 */
static FILE *
logfile_open(const char *filename, const char *mode, bool allow_errors,
			 int stream_id)
{
	FILE	   *fh;
	mode_t		oumask;
	LogStream  *stream = &log_streams[stream_id];
	int			file_mode = stream->file_mode;

	/*
	 * Note we do not let Log_file_mode disable IWUSR, since we certainly want
	 * to be able to write the files ourselves.
	 */
	oumask = umask((mode_t) ((~(file_mode | S_IWUSR)) & (S_IRWXU | S_IRWXG | S_IRWXO)));
	fh = fopen(filename, mode);
	umask(oumask);

	if (fh)
	{
		setvbuf(fh, NULL, PG_IOLBF, 0);

#ifdef WIN32
		/* use CRLF line endings on Windows */
		_setmode(_fileno(fh), _O_TEXT);
#endif
	}
	else
	{
		int			save_errno = errno;

		ereport(allow_errors ? LOG : FATAL,
				(errcode_for_file_access(),
				 errmsg("could not open log file \"%s\": %m",
						filename)));
		errno = save_errno;
	}

	return fh;
}

/*
 * perform logfile rotation
 */
static void
logfile_rotate(bool time_based_rotation, int size_rotation_for, int stream_id)
{
	char	   *filename;
	char	   *csvfilename = NULL;
	pg_time_t	fntime;
	FILE	   *fh;
	LogStream  *stream = &log_streams[stream_id];

	Assert(stream_id < log_streams_active);

	stream->rotation_needed = false;

	/*
	 * When doing a time-based rotation, invent the new logfile name based on
	 * the planned rotation time, not current time, to avoid "slippage" in the
	 * file name when we don't do the rotation immediately.
	 */
	if (time_based_rotation)
		fntime = stream->next_rotation_time;
	else
		fntime = time(NULL);
	filename = logfile_getname(fntime, NULL, stream_id);
	if (stream->destination & LOG_DESTINATION_CSVLOG)
		csvfilename = logfile_getname(fntime, ".csv", stream_id);

	/*
	 * Decide whether to overwrite or append.  We can overwrite if (a)
	 * Log_truncate_on_rotation is set, (b) the rotation was triggered by
	 * elapsed time and not something else, and (c) the computed file name is
	 * different from what we were previously logging into.
	 *
	 * Note: last_file_name should never be NULL here, but if it is, append.
	 */
	if (time_based_rotation || (size_rotation_for & LOG_DESTINATION_STDERR))
	{
		if (stream->truncate_on_rotation && time_based_rotation &&
			stream->last_file_name != NULL &&
			strcmp(filename, stream->last_file_name) != 0)
			fh = logfile_open(filename, "w", true, stream_id);
		else
			fh = logfile_open(filename, "a", true, stream_id);

		if (!fh)
		{
			/*
			 * ENFILE/EMFILE are not too surprising on a busy system; just
			 * keep using the old file till we manage to get a new one.
			 * Otherwise, assume something's wrong with log directory and stop
			 * trying to create files.
			 */
			if (errno != ENFILE && errno != EMFILE)
			{
				ereport(LOG,
						(errmsg("disabling automatic rotation (use SIGHUP to re-enable)")));
				rotation_disabled = true;
			}

			if (filename)
				pfree(filename);
			if (csvfilename)
				pfree(csvfilename);
			return;
		}

		fclose(stream->syslog_file);
		stream->syslog_file = fh;

		/* instead of pfree'ing filename, remember it for next time */
		if (stream->last_file_name != NULL)
			pfree(stream->last_file_name);
		stream->last_file_name = filename;
		filename = NULL;
	}

	/*
	 * Same as above, but for csv file.  Note that if LOG_DESTINATION_CSVLOG
	 * was just turned on, we might have to open csvlog_file here though it
	 * was not open before.  In such a case we'll append not overwrite (since
	 * last_csv_file_name will be NULL); that is consistent with the normal
	 * rules since it's not a time-based rotation.
	 */
	if ((stream->destination & LOG_DESTINATION_CSVLOG) &&
		(stream->csvlog_file == NULL ||
		 time_based_rotation || (size_rotation_for & LOG_DESTINATION_CSVLOG)))
	{
		if (stream->truncate_on_rotation && time_based_rotation &&
			stream->last_csv_file_name != NULL &&
			strcmp(csvfilename, stream->last_csv_file_name) != 0)
			fh = logfile_open(csvfilename, "w", true, stream_id);
		else
			fh = logfile_open(csvfilename, "a", true, stream_id);

		if (!fh)
		{
			/*
			 * ENFILE/EMFILE are not too surprising on a busy system; just
			 * keep using the old file till we manage to get a new one.
			 * Otherwise, assume something's wrong with log directory and stop
			 * trying to create files.
			 */
			if (errno != ENFILE && errno != EMFILE)
			{
				ereport(LOG,
						(errmsg("disabling automatic rotation (use SIGHUP to re-enable)")));
				rotation_disabled = true;
			}

			if (filename)
				pfree(filename);
			if (csvfilename)
				pfree(csvfilename);
			return;
		}

		if (stream->csvlog_file != NULL)
			fclose(stream->csvlog_file);
		stream->csvlog_file = fh;

		/* instead of pfree'ing filename, remember it for next time */
		if (stream->last_csv_file_name != NULL)
			pfree(stream->last_csv_file_name);
		stream->last_csv_file_name = csvfilename;
		csvfilename = NULL;
	}
	else if (!(stream->destination & LOG_DESTINATION_CSVLOG) &&
			 stream->csvlog_file != NULL)
	{
		/* CSVLOG was just turned off, so close the old file */
		fclose(stream->csvlog_file);
		stream->csvlog_file = NULL;
		if (stream->last_csv_file_name != NULL)
			pfree(stream->last_csv_file_name);
		stream->last_csv_file_name = NULL;
	}

	if (filename)
		pfree(filename);
	if (csvfilename)
		pfree(csvfilename);

	if (stream_id == 0)
		update_metainfo_datafile();

	set_next_rotation_time(stream_id);
}


/*
 * construct logfile name using timestamp information
 *
 * If suffix isn't NULL, append it to the name, replacing any ".log"
 * that may be in the pattern.
 *
 * Result is palloc'd.
 */
static char *
logfile_getname(pg_time_t timestamp, const char *suffix, int stream_id)
{
	char	   *filename;
	int			len;
	LogStream  *stream = &log_streams[stream_id];

	filename = palloc(MAXPGPATH);

	snprintf(filename, MAXPGPATH, "%s/", stream->directory);

	len = strlen(filename);

	/* treat log filename as a strftime pattern */
	pg_strftime(filename + len, MAXPGPATH - len, stream->filename,
				pg_localtime(&timestamp, log_timezone));

	if (suffix != NULL)
	{
		len = strlen(filename);
		if (len > 4 && (strcmp(filename + (len - 4), ".log") == 0))
			len -= 4;
		strlcpy(filename + len, suffix, MAXPGPATH - len);
	}

	return filename;
}

/*
 * Determine the next planned rotation time, and store in next_rotation_time.
 */
static void
set_next_rotation_time(int stream_id)
{
	pg_time_t	now;
	struct pg_tm *tm;
	int			rotinterval;
	LogStream  *stream = &log_streams[stream_id];

	/* nothing to do if time-based rotation is disabled */
	if (stream->rotation_age <= 0)
		return;

	/*
	 * The requirements here are to choose the next time > now that is a
	 * "multiple" of the log rotation interval.  "Multiple" can be interpreted
	 * fairly loosely.  In this version we align to log_timezone rather than
	 * GMT.
	 */
	rotinterval = stream->rotation_age *
		SECS_PER_MINUTE;		/* convert to seconds */
	now = (pg_time_t) time(NULL);
	tm = pg_localtime(&now, log_timezone);
	now += tm->tm_gmtoff;
	now -= now % rotinterval;
	now += rotinterval;
	now -= tm->tm_gmtoff;

	stream->next_rotation_time = now;
}

/*
 * Store the name of the file(s) where the log collector, when enabled, writes
 * log messages.  Useful for finding the name(s) of the current log file(s)
 * when there is time-based logfile rotation.  Filenames are stored in a
 * temporary file and which is renamed into the final destination for
 * atomicity.
 *
 * TODO Should the extension logs be included? If so, how can we generate a
 * unique prefix for them? (stream_id is not suitable because an extension can
 * receive different id after cluster restart).
 */
static void
update_metainfo_datafile(void)
{
	FILE	   *fh;
	mode_t		oumask;
	LogStream  *stream_core = &log_streams[0];
	char	   *last_file_name = stream_core->last_file_name;
	char	   *last_csv_file_name = stream_core->last_csv_file_name;
	LogStream  *log = &log_streams[0];

	if (!(log->destination & LOG_DESTINATION_STDERR) &&
		!(log->destination & LOG_DESTINATION_CSVLOG))
	{
		if (unlink(LOG_METAINFO_DATAFILE) < 0 && errno != ENOENT)
			ereport(LOG,
					(errcode_for_file_access(),
					 errmsg("could not remove file \"%s\": %m",
							LOG_METAINFO_DATAFILE)));
		return;
	}

	/* use the same permissions as the data directory for the new file */
	oumask = umask(pg_mode_mask);
	fh = fopen(LOG_METAINFO_DATAFILE_TMP, "w");
	umask(oumask);

	if (fh)
	{
		setvbuf(fh, NULL, PG_IOLBF, 0);

#ifdef WIN32
		/* use CRLF line endings on Windows */
		_setmode(_fileno(fh), _O_TEXT);
#endif
	}
	else
	{
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not open file \"%s\": %m",
						LOG_METAINFO_DATAFILE_TMP)));
		return;
	}

	if (last_file_name && (log->destination & LOG_DESTINATION_STDERR))
	{
		if (fprintf(fh, "stderr %s\n", last_file_name) < 0)
		{
			ereport(LOG,
					(errcode_for_file_access(),
					 errmsg("could not write file \"%s\": %m",
							LOG_METAINFO_DATAFILE_TMP)));
			fclose(fh);
			return;
		}
	}

	if (last_csv_file_name && (log->destination & LOG_DESTINATION_CSVLOG))
	{
		if (fprintf(fh, "csvlog %s\n", last_csv_file_name) < 0)
		{
			ereport(LOG,
					(errcode_for_file_access(),
					 errmsg("could not write file \"%s\": %m",
							LOG_METAINFO_DATAFILE_TMP)));
			fclose(fh);
			return;
		}
	}
	fclose(fh);

	if (rename(LOG_METAINFO_DATAFILE_TMP, LOG_METAINFO_DATAFILE) != 0)
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not rename file \"%s\" to \"%s\": %m",
						LOG_METAINFO_DATAFILE_TMP, LOG_METAINFO_DATAFILE)));
}

/* --------------------------------
 *		signal handler routines
 * --------------------------------
 */

/*
 * Check to see if a log rotation request has arrived.  Should be
 * called by postmaster after receiving SIGUSR1.
 */
bool
CheckLogrotateSignal(void)
{
	struct stat stat_buf;

	if (stat(LOGROTATE_SIGNAL_FILE, &stat_buf) == 0)
		return true;

	return false;
}

/*
 * Remove the file signaling a log rotation request.
 */
void
RemoveLogrotateSignalFiles(void)
{
	unlink(LOGROTATE_SIGNAL_FILE);
}

/* SIGHUP: set flag to reload config file */
static void
sigHupHandler(SIGNAL_ARGS)
{
	int			save_errno = errno;

	got_SIGHUP = true;
	SetLatch(MyLatch);

	errno = save_errno;
}

/* SIGUSR1: set flag to rotate logfile */
static void
sigUsr1Handler(SIGNAL_ARGS)
{
	int			save_errno = errno;

	rotation_requested = true;
	SetLatch(MyLatch);

	errno = save_errno;
}
