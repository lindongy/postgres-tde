/* Processed by ecpg (regression mode) */
/* These include files are added by the preprocessor */
#include <ecpglib.h>
#include <ecpgerrno.h>
#include <sqlca.h>
/* End of automatic include section */
#define ECPGdebug(X,Y) ECPGdebug((X)+100,(Y))

#line 1 "cursor-ra-swdir.pgc"
/*
 * Test MOVE ABSOLUTE N with alternating positive/negative
 * positions and FETCH FORWARD/BACKWARD another record according
 * to the current value.
 *
 * This code makes the result set size known by reaching the end.
 * in both directions.
 *
 * After reaching the end, the cache_start_pos can be flipped
 * from positive to negative to match the cursor position
 * issued by the application.
 *
 * To watch this effect, execute:
 *
 * egrep -n "(cache populated|tuple already in cache)" \
 *	results/sql-cursor-ra-swdir.stderr
 *
 */
#include <stdlib.h>
#include <string.h>


#line 1 "regression.h"






#line 22 "cursor-ra-swdir.pgc"


/* exec sql whenever sqlerror  sqlprint ; */
#line 24 "cursor-ra-swdir.pgc"


/* declare mycur cursor for select id , t from t1 order by id */
#line 26 "cursor-ra-swdir.pgc"


/* exec sql begin declare section */
	
	

#line 29 "cursor-ra-swdir.pgc"
 int id [ 2 ] ;
 
#line 30 "cursor-ra-swdir.pgc"
  struct varchar_1  { int len; char arr[ 50 ]; }  t [ 2 ] ;
/* exec sql end declare section */
#line 31 "cursor-ra-swdir.pgc"


static void fetch2(int absolute)
{
	/* exec sql begin declare section */
		  
	
#line 36 "cursor-ra-swdir.pgc"
 int absolute1 = absolute ;
/* exec sql end declare section */
#line 37 "cursor-ra-swdir.pgc"


	int	i, rows = 1;
	int	direction = (absolute < 0 ? -1 : 1);

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute_in_var, NULL, 0, "mycur", ECPGst_normal, "fetch absolute $0 from mycur", 
	ECPGt_int,&(absolute1),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,&(id[0]),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,&(t[0]),(long)50,(long)1,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 42 "cursor-ra-swdir.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 42 "cursor-ra-swdir.pgc"

	if (direction > 0)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "1", 0, "mycur", ECPGst_normal, "fetch forward 1 from mycur", ECPGt_EOIT, 
	ECPGt_int,&(id[1]),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,&(t[1]),(long)50,(long)1,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 45 "cursor-ra-swdir.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 45 "cursor-ra-swdir.pgc"

	}
	else
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_backward, "1", 0, "mycur", ECPGst_normal, "fetch backward 1 from mycur", ECPGt_EOIT, 
	ECPGt_int,&(id[1]),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,&(t[1]),(long)50,(long)1,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 49 "cursor-ra-swdir.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 49 "cursor-ra-swdir.pgc"

	}

	rows += sqlca.sqlerrd[2];

	for (i = 0; i < rows; i++)
		printf("absolute: %d id: %d t '%s'\n", absolute + i*direction, id[i], t[i].arr);
}

int main(void)
{
	/* exec sql begin declare section */
		 
	
#line 61 "cursor-ra-swdir.pgc"
 int i , j ;
/* exec sql end declare section */
#line 62 "cursor-ra-swdir.pgc"


	ECPGdebug(1, stderr);

	{ ECPGconnect(__LINE__, 0, "regress1" , NULL, NULL , NULL, 0); 
#line 66 "cursor-ra-swdir.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 66 "cursor-ra-swdir.pgc"


	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "create table t1 ( id serial primary key , t text )", ECPGt_EOIT, ECPGt_EORT);
#line 68 "cursor-ra-swdir.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 68 "cursor-ra-swdir.pgc"

	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "insert into t1 ( t ) values ( 'a' ) , ( 'b' ) , ( 'c' ) , ( 'd' ) , ( 'e' ) , ( 'f' ) , ( 'g' )", ECPGt_EOIT, ECPGt_EORT);
#line 70 "cursor-ra-swdir.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 70 "cursor-ra-swdir.pgc"

	{ ECPGtrans(__LINE__, NULL, "commit", 0, 0, 0, NULL);
#line 71 "cursor-ra-swdir.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 71 "cursor-ra-swdir.pgc"


	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_unspecified, 4, 0, 0, "mycur", ECPGst_normal, "declare mycur cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 73 "cursor-ra-swdir.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 73 "cursor-ra-swdir.pgc"


	printf("Discover total number of tuples and test flipping of cache_start_pos...\n");

	/*
	 * This part verifies that the returned rows are correct
	 * in each direction and allows discovering the total
	 * size of the result set via FETCH ABSOLUTE -1.
	 * The midde of the loop, i.e. positions
	 *	-2, -3, -4, -5 and
	 *	 6,  5,  4,  3
	 * will be served entirely from
	 * the same cache.
	 */
	for (i = 1, j = -1; i <= 7; i++, j--)
	{
		fetch2(i);
		fetch2(j);
	}

	printf("Re-test flipping of cache_start_pos\n");

	/*
	 * Re-test flipping with different positions that also
	 * involve the end of the result set:
	 *	-->      5,  6,  7, (end)
	 *	    -4, -3, -2, -1  <--
	 * After the first fetch, this loop can be served
	 * almost entirely from the same cache except the last
	 * request: fetch2(-3) does:
	 *	FETCH ABSOLUTE -3 (still in the cache)
	 *	FETCH BACKWARD 1 (does a new FETCH)
	 */
	for (i = 5, j = -1; i <= 7; i++, j--)
	{
		fetch2(i);
		fetch2(j);
	}

	{ ECPGclose(__LINE__, 0, 1, NULL, 0, "mycur", ECPGst_normal, "close mycur", ECPGt_EOIT, ECPGt_EORT);
#line 112 "cursor-ra-swdir.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 112 "cursor-ra-swdir.pgc"


	/* Drop the test table */

	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "drop table t1", ECPGt_EOIT, ECPGt_EORT);
#line 116 "cursor-ra-swdir.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 116 "cursor-ra-swdir.pgc"

	{ ECPGtrans(__LINE__, NULL, "commit", 0, 0, 0, NULL);
#line 117 "cursor-ra-swdir.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 117 "cursor-ra-swdir.pgc"


	{ ECPGdisconnect(__LINE__, "ALL");
#line 119 "cursor-ra-swdir.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 119 "cursor-ra-swdir.pgc"


	return 0;
}
