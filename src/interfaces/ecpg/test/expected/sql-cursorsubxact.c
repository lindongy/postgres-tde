/* Processed by ecpg (regression mode) */
/* These include files are added by the preprocessor */
#include <ecpglib.h>
#include <ecpgerrno.h>
#include <sqlca.h>
/* End of automatic include section */
#define ECPGdebug(X,Y) ECPGdebug((X)+100,(Y))

#line 1 "cursorsubxact.pgc"
#include <stdlib.h>
#include <string.h>


#line 1 "regression.h"






#line 4 "cursorsubxact.pgc"


/* exec sql whenever sqlerror  sqlprint ; */
#line 6 "cursorsubxact.pgc"


#define CURNAME "MyCur"
#define CURNAME_BAD "myCur"

#define QUOTED_CURNAME "\"MyCur\""
#define QUOTED_CURNAME_BAD "\"myCur\""

int main(void)
{
/* exec sql begin declare section */
		
		
		

#line 17 "cursorsubxact.pgc"
 char * curname ;
 
#line 18 "cursorsubxact.pgc"
 int id [ 3 ] ;
 
#line 19 "cursorsubxact.pgc"
  struct varchar_1  { int len; char arr[ 50 ]; }  t [ 3 ] ;
/* exec sql end declare section */
#line 20 "cursorsubxact.pgc"


	ECPGdebug(1, stderr);

	{ ECPGconnect(__LINE__, 0, "regress1" , NULL, NULL , NULL, 0); 
#line 24 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 24 "cursorsubxact.pgc"


	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "create table t1 ( id serial primary key , t text )", ECPGt_EOIT, ECPGt_EORT);
#line 26 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 26 "cursorsubxact.pgc"

	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "insert into t1 ( t ) values ( 'a' ) , ( 'b' ) , ( 'c' )", ECPGt_EOIT, ECPGt_EORT);
#line 27 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 27 "cursorsubxact.pgc"

	{ ECPGtrans(__LINE__, NULL, "commit", 0, 0, 0, NULL);
#line 28 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 28 "cursorsubxact.pgc"


	/*
	 * Cursor name passed in a variable unquoted.
	 * It has to be treated as case-insensitive.
	 */

	printf("test case insensitive cursor name\n\n");

	curname = CURNAME;

	ECPGset_var( 0, &( curname ), __LINE__);\
 /* declare $0 cursor for select id , t from t1 */
#line 39 "cursorsubxact.pgc"


	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_unspecified, 1, 1, 0, curname, ECPGst_normal, "declare $0 cursor for select id , t from t1", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, ECPGt_EORT);
#line 41 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 41 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("open %s (case insensitive) failed with SQLSTATE %5s\n", curname, sqlca.sqlstate);
	else
		printf("open %s (case insensitive) succeeded\n", curname);

	curname = CURNAME_BAD;

	{ ECPGclose(__LINE__, 0, 1, NULL, 0, curname, ECPGst_normal, "close $0", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, ECPGt_EORT);
#line 49 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 49 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("close %s (case insensitive)  failed with SQLSTATE %5s\n", curname, sqlca.sqlstate);
	else
		printf("close %s (case insensitive) succeeded\n", curname);

	/*
	 * Cursor name passed in a variable quoted.
	 * It has to be treated as case-sensitive.
	 */

	printf("\ntest case sensitive cursor name\n\n");

	curname = QUOTED_CURNAME;

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_unspecified, 1, 1, 0, curname, ECPGst_normal, "declare $0 cursor for select id , t from t1", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, ECPGt_EORT);
#line 64 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 64 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("open %s (case sensitive) failed with SQLSTATE %5s\n", curname, sqlca.sqlstate);
	else
		printf("open %s (case sensitive) succeeded\n", curname);

	curname = QUOTED_CURNAME_BAD;

	/* Try to close the wrong cursor name, it has to fail with 34000. */
	{ ECPGclose(__LINE__, 0, 1, NULL, 0, curname, ECPGst_normal, "close $0", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, ECPGt_EORT);
#line 73 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 73 "cursorsubxact.pgc"
 
	if (sqlca.sqlcode < 0)
		printf("close %s (case sensitive) failed with SQLSTATE %5s (expected 34000)\n", curname, sqlca.sqlstate);
	else
		printf("close %s (case sensitive) succeeded\n", curname);

	/* Try to close the right cursor name, it has to fail with 25P02 */
	curname = QUOTED_CURNAME;
	{ ECPGclose(__LINE__, 0, 1, NULL, 0, curname, ECPGst_normal, "close $0", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, ECPGt_EORT);
#line 81 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 81 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("close %s (case sensitive) failed with SQLSTATE %5s (expected 25P02)\n", curname, sqlca.sqlstate);
	else
		printf("close %s (case sensitive) succeeded\n", curname);

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 87 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 87 "cursorsubxact.pgc"


	/*
	 * Try a new transaction and watch the cursor name disappear
	 * after ROLLBACK TO SAVEPOINT.
	 */

	printf("\ntest case sensitive cursor name in savepoint\n\n");

	curname = QUOTED_CURNAME;

	{ ECPGtrans(__LINE__, NULL, "savepoint a", 0, 1, 0, "a");
#line 98 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 98 "cursorsubxact.pgc"


	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_unspecified, 1, 1, 0, curname, ECPGst_normal, "declare $0 cursor for select id , t from t1", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, ECPGt_EORT);
#line 100 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 100 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("open %s (case sensitive) failed with SQLSTATE %5s\n", curname, sqlca.sqlstate);
	else
		printf("close %s (case sensitive) succeeded\n", curname);

	/* The cursor name must be forgotten */
	{ ECPGtrans(__LINE__, NULL, "rollback to a", 0, 0, 1, "a");
#line 107 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 107 "cursorsubxact.pgc"


	/* It has to fail with 34000 */
	{ ECPGclose(__LINE__, 0, 1, NULL, 0, curname, ECPGst_normal, "close $0", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, ECPGt_EORT);
#line 110 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 110 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("close %s failed with SQLSTATE %5s (expected 34000)\n", curname, sqlca.sqlstate);
	else
		printf("close %s succeeded unexpectedly, expected sqlstate 34000\n", curname);

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 116 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 116 "cursorsubxact.pgc"


	/*
	 * Try a new transaction and play games with savepoints.
	 */

	printf("\ntest savepoint handling\n\n");

	{ ECPGtrans(__LINE__, NULL, "savepoint a", 0, 1, 0, "a");
#line 124 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 124 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"savepoint a\" failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("\"savepoint a\" succeeded\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_unspecified, 1, 1, 0, curname, ECPGst_normal, "declare $0 cursor for select id , t from t1", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, ECPGt_EORT);
#line 130 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 130 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("open %s (case sensitive) failed with SQLSTATE %5s\n", curname, sqlca.sqlstate);
	else
		printf("open %s (case sensitive) succeeded\n", curname);

	{ ECPGtrans(__LINE__, NULL, "savepoint b", 0, 1, 0, "b");
#line 136 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 136 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"savepoint a\" failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("\"savepoint a\" succeeded\n");

	/* Try to rollback to an unknown savepoint */

	{ ECPGtrans(__LINE__, NULL, "rollback to c", 0, 0, 1, "c");
#line 144 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 144 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"rollback to c\" failed with SQLSTATE %5s (expected 3B001)\n", sqlca.sqlstate);
	else
		printf("\"rollback to c\" succeeded unexpectedly (expected 3B001)\n");

	/* "rollback to a" implicitly rolls back "b" */

	{ ECPGtrans(__LINE__, NULL, "rollback to a", 0, 0, 1, "a");
#line 152 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 152 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"rollback to a\" failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("\"rollback to a\" succeeded\n");

	/* savepoint "b" is now unknown, fails with 3B001 */
	{ ECPGtrans(__LINE__, NULL, "rollback to b", 0, 0, 1, "b");
#line 159 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 159 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"rollback to b\" failed with SQLSTATE %5s (expected 3B001)\n", sqlca.sqlstate);
	else
		printf("\"rollback to b\" succeeded unexpectedly (expected 3B001)\n");

	/* "rollback to a" has to succeed again, it's still alive */

	{ ECPGtrans(__LINE__, NULL, "rollback to a", 0, 0, 1, "a");
#line 167 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 167 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"rollback to a\" failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("\"rollback to a\" succeeded\n");

	/* the cursor was declared under savepoint "a", was forgotten */

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "1", 0, curname, ECPGst_normal, "fetch from $0", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,&(id[0]),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,&(t[0]),(long)50,(long)1,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 175 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 175 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("fetch from %s (case sensitive) failed with SQLSTATE %5s (expected 34000)\n", curname, sqlca.sqlstate);
	else
		printf("fetch from %s (case sensitive) succeeded unexpectedly (expected 34000)\n", curname);

	/* "rollback to a" has to succeed again, it's still alive */

	{ ECPGtrans(__LINE__, NULL, "rollback to a", 0, 0, 1, "a");
#line 183 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 183 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"rollback to a\" failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("\"rollback to a\" succeeded\n");

	/* "release savepoint a" forgets about the savepoint name */

	{ ECPGtrans(__LINE__, NULL, "release savepoint a", 0, 0, 0, "a");
#line 191 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 191 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"release savepoint a\" failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("\"release savepoint a\" succeeded\n");

	/* prove the above */

	{ ECPGtrans(__LINE__, NULL, "rollback to a", 0, 0, 1, "a");
#line 199 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 199 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"rollback to a\" failed with SQLSTATE %5s (expected 3B001)\n", sqlca.sqlstate);
	else
		printf("\"rollback to a\" succeeded unexpectedly (expected 3B001)\n");

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 205 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 205 "cursorsubxact.pgc"


	/*
	 * Test the implicit RELEASE SAVEPOINT if a SAVEPOINT
	 * is used with an already existing name.
	 */

	printf("\ntest implicit \"release savepoint a\" for a second \"savepoint a\"\n\n");

	{ ECPGtrans(__LINE__, NULL, "savepoint a", 0, 1, 0, "a");
#line 214 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 214 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"savepoint a\" failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("\"savepoint a\" succeeded\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_unspecified, 1, 1, 0, curname, ECPGst_normal, "declare $0 cursor for select id , t from t1", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, ECPGt_EORT);
#line 220 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 220 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("open %s (case sensitive) failed with SQLSTATE %5s\n", curname, sqlca.sqlstate);
	else
		printf("open %s (case sensitive) succeeded\n", curname);

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "1", 0, curname, ECPGst_normal, "fetch from $0", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,&(id[0]),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,&(t[0]),(long)50,(long)1,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 226 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 226 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("fetch from %s (case sensitive) failed with SQLSTATE %5s\n", curname, sqlca.sqlstate);
	else
		printf("fetch from %s (case sensitive) result %d '%s'\n", curname, id[0], t[0].arr);

	{ ECPGtrans(__LINE__, NULL, "rollback to a", 0, 0, 1, "a");
#line 232 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 232 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"rollback to a\" failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("\"rollback to a\" succeeded\n");

	/* there's no cursor now */

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "1", 0, curname, ECPGst_normal, "fetch from $0", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,&(id[1]),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,&(t[1]),(long)50,(long)1,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 240 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 240 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("fetch from %s (case sensitive) failed with SQLSTATE %5s (expected 34000)\n", curname, sqlca.sqlstate);
	else
		printf("fetch from %s (case sensitive) unexpectedly succeeded (expected 34000)\n", curname);

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_unspecified, 1, 1, 0, curname, ECPGst_normal, "declare $0 cursor for select id , t from t1", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, ECPGt_EORT);
#line 246 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 246 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("open %s (case sensitive) failed with SQLSTATE %5s (expected 25P02)\n", curname, sqlca.sqlstate);
	else
		printf("open %s (case sensitive) succeeded unexpectedly\n", curname);

	{ ECPGtrans(__LINE__, NULL, "rollback to a", 0, 0, 1, "a");
#line 252 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 252 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"rollback to a\" failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("\"rollback to a\" succeeded\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_unspecified, 1, 1, 0, curname, ECPGst_normal, "declare $0 cursor for select id , t from t1", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, ECPGt_EORT);
#line 258 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 258 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("open %s (case sensitive) failed with SQLSTATE %5s\n", curname, sqlca.sqlstate);
	else
		printf("open %s (case sensitive) succeeded\n", curname);

	{ ECPGtrans(__LINE__, NULL, "release savepoint a", 0, 0, 0, "a");
#line 264 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 264 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("\"release savepoint a\" failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("\"release savepoint a\" succeeded\n");

	/* release savepoint propagated the cursor to the toplevel transaction */

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "1", 0, curname, ECPGst_normal, "fetch from $0", 
	ECPGt_char,&(curname),(long)0,(long)1,(1)*sizeof(char), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,&(id[2]),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,&(t[2]),(long)50,(long)1,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 272 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 272 "cursorsubxact.pgc"

	if (sqlca.sqlcode < 0)
		printf("fetch %s (case sensitive) failed with SQLSTATE %5s\n", curname, sqlca.sqlstate);
	else
		printf("fetch %s (case sensitive) result %d '%s'\n", curname, id[2], t[2].arr);

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 278 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 278 "cursorsubxact.pgc"


	/* Drop the test table */

	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "drop table t1", ECPGt_EOIT, ECPGt_EORT);
#line 282 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 282 "cursorsubxact.pgc"

	{ ECPGtrans(__LINE__, NULL, "commit", 0, 0, 0, NULL);
#line 283 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 283 "cursorsubxact.pgc"


	{ ECPGdisconnect(__LINE__, "ALL");
#line 285 "cursorsubxact.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 285 "cursorsubxact.pgc"


	return 0;
}
