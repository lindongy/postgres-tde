/* Processed by ecpg (regression mode) */
/* These include files are added by the preprocessor */
#include <ecpglib.h>
#include <ecpgerrno.h>
#include <sqlca.h>
/* End of automatic include section */
#define ECPGdebug(X,Y) ECPGdebug((X)+100,(Y))

#line 1 "cursor-ra-fetch.pgc"
#include <stdlib.h>
#include <string.h>


#line 1 "regression.h"






#line 4 "cursor-ra-fetch.pgc"


/* exec sql whenever sqlerror  sqlprint ; */
#line 6 "cursor-ra-fetch.pgc"


int main(void)
{
/* exec sql begin declare section */
		 
		

#line 11 "cursor-ra-fetch.pgc"
 int id [ 8 ] , i ;
 
#line 12 "cursor-ra-fetch.pgc"
  struct varchar_1  { int len; char arr[ 50 ]; }  t [ 8 ] ;
/* exec sql end declare section */
#line 13 "cursor-ra-fetch.pgc"

	int	quit_loop;

	ECPGdebug(1, stderr);

	{ ECPGconnect(__LINE__, 0, "regress1" , NULL, NULL , NULL, 0); 
#line 18 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 18 "cursor-ra-fetch.pgc"


	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "create table t1 ( id serial primary key , t text )", ECPGt_EOIT, ECPGt_EORT);
#line 20 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 20 "cursor-ra-fetch.pgc"

	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "insert into t1 ( t ) values ( 'a' ) , ( 'b' ) , ( 'c' ) , ( 'd' ) , ( 'e' ) , ( 'f' ) , ( 'g' ) , ( 'h' ) , ( 'i' ) , ( 'j' ) , ( 'k' ) , ( 'l' ) , ( 'm' ) , ( 'n' ) , ( 'o' ) , ( 'p' ) , ( 'q' ) , ( 'r' ) , ( 's' ) , ( 't' ) , ( 'u' ) , ( 'v' ) , ( 'w' ) , ( 'x' ) , ( 'y' ) , ( 'z' )", ECPGt_EOIT, ECPGt_EORT);
#line 25 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 25 "cursor-ra-fetch.pgc"

	{ ECPGtrans(__LINE__, NULL, "commit", 0, 0, 0, NULL);
#line 26 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 26 "cursor-ra-fetch.pgc"


	/* declare scroll_cur scroll cursor for select id , t from t1 order by id */
#line 28 "cursor-ra-fetch.pgc"

	/* declare scroll_cur4 scroll cursor for select id , t from t1 order by id */
#line 29 "cursor-ra-fetch.pgc"


	/*
	 * Test FETCH ABSOLUTE N with an interval of 4 using positive positions.
	 * Readahead is 8 so caching is in effect.
	 */

	printf("test scroll_cur for move absolute n (every 4th tuple forward, positive positions)\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 8, 0, 0, "scroll_cur", ECPGst_normal, "declare scroll_cur scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 38 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 38 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	for (i = 1; i < 33; i += 4)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute_in_var, NULL, 0, "scroll_cur", ECPGst_normal, "fetch absolute $0 from scroll_cur", 
	ECPGt_int,&(i),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 44 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 44 "cursor-ra-fetch.pgc"


		if (sqlca.sqlerrd[2] == 1)
			printf("\trow %d: id: %d\tt: %s\n", i, id[0], t[0].arr);
		else
			printf("\trow %d does not exist\n", i);
	}

	printf("\ntest scroll_cur for move absolute n (every 4th tuple backward, positive positions)\n");

	for (i = 33; i >= 0; i -= 4)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute_in_var, NULL, 0, "scroll_cur", ECPGst_normal, "fetch absolute $0 from scroll_cur", 
	ECPGt_int,&(i),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 56 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 56 "cursor-ra-fetch.pgc"


		if (sqlca.sqlerrd[2] == 1)
			printf("\trow %d: id: %d\tt: %s\n", i, id[0], t[0].arr);
		else
			printf("\trow %d does not exist\n", i);
	}

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 64 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 64 "cursor-ra-fetch.pgc"


	/*
	 * Test FETCH ABSOLUTE N with an interval of 4 using negative positions.
	 * Readahead is 8 so caching is in effect.
	 */

	printf("\ntest scroll_cur for move absolute n (every 4th tuple backward, negative positions)\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 8, 0, 0, "scroll_cur", ECPGst_normal, "declare scroll_cur scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 73 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 73 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	for (i = -1; i > -33; i -= 4)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute_in_var, NULL, 0, "scroll_cur", ECPGst_normal, "fetch absolute $0 from scroll_cur", 
	ECPGt_int,&(i),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 79 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 79 "cursor-ra-fetch.pgc"


		if (sqlca.sqlerrd[2] == 1)
			printf("\trow %d: id: %d\tt: %s\n", i, id[0], t[0].arr);
		else
			printf("\trow %d does not exist\n", i);
	}

	printf("\ntest scroll_cur for move absolute n (every 4th tuple forward, negative positions)\n");

	for (i = -33; i <= 0; i += 4)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute_in_var, NULL, 0, "scroll_cur", ECPGst_normal, "fetch absolute $0 from scroll_cur", 
	ECPGt_int,&(i),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 91 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 91 "cursor-ra-fetch.pgc"


		if (sqlca.sqlerrd[2] == 1)
			printf("\trow %d: id: %d\tt: %s\n", i, id[0], t[0].arr);
		else
			printf("\trow %d does not exist\n", i);
	}

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 99 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 99 "cursor-ra-fetch.pgc"


	/*
	 * Test FETCH RELATIVE +/- 4 using positive positions
	 * readahead is 8, so caching is in effect
	 */

	printf("\ntest scroll_cur for fetch relative 4 (positive positions)\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 8, 0, 0, "scroll_cur", ECPGst_normal, "declare scroll_cur scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 108 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 108 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	quit_loop = 0;
	while (!quit_loop)
	{
		for (i = 0; i < 8; i++)
			id[i] = 0, t[i].arr[0] = '\0';
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_relative, "4", 0, "scroll_cur", ECPGst_normal, "fetch relative 4 in scroll_cur", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 117 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 117 "cursor-ra-fetch.pgc"

		if (sqlca.sqlcode < 0)
			printf("fetch relative 4 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
		else
			printf("fetch relative 4 in scroll_cur succeeded, sqlerrd[2] %ld\n", sqlca.sqlerrd[2]);
		for (i = 0; i < sqlca.sqlerrd[2]; i++)
			printf("\tid: %d\tt: %s\n", id[i], t[i].arr);
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	printf("\ntest scroll_cur for fetch relative -4 (positive positions)\n");

	quit_loop = 0;
	while (!quit_loop)
	{
		for (i = 0; i < 8; i++)
			id[i] = 0, t[i].arr[0] = '\0';
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_relative, "- 4", 0, "scroll_cur", ECPGst_normal, "fetch relative - 4 in scroll_cur", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 134 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 134 "cursor-ra-fetch.pgc"

		if (sqlca.sqlcode < 0)
			printf("fetch relative -4 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
		else
			printf("fetch relative -4 in scroll_cur succeeded, sqlerrd[2] %ld\n", sqlca.sqlerrd[2]);
		for (i = 0; i < sqlca.sqlerrd[2]; i++)
			printf("\tid: %d\tt: %s\n", id[i], t[i].arr);
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 144 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 144 "cursor-ra-fetch.pgc"


	/*
	 * Test FETCH RELATIVE +/- 4 using negative positions
	 * readahead is 8, so caching is in effect
	 */

	printf("\ntest scroll_cur for fetch relative -4 (negative positions)\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 8, 0, 0, "scroll_cur", ECPGst_normal, "declare scroll_cur scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 153 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 153 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute, "- 1", 1, "scroll_cur", ECPGst_normal, "move absolute - 1 in scroll_cur", ECPGt_EOIT, ECPGt_EORT);
#line 157 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 157 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("move absolute -1 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "1", 1, "scroll_cur", ECPGst_normal, "move forward 1 in scroll_cur", ECPGt_EOIT, ECPGt_EORT);
#line 160 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 160 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("move forward 1 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);

	quit_loop = 0;
	while (!quit_loop)
	{
		for (i = 0; i < 8; i++)
			id[i] = 0, t[i].arr[0] = '\0';
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_relative, "- 4", 0, "scroll_cur", ECPGst_normal, "fetch relative - 4 in scroll_cur", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 169 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 169 "cursor-ra-fetch.pgc"

		if (sqlca.sqlcode < 0)
			printf("fetch relative -4 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
		else
			printf("fetch relative -4 in scroll_cur succeeded, sqlerrd[2] %ld\n", sqlca.sqlerrd[2]);
		for (i = 0; i < sqlca.sqlerrd[2]; i++)
			printf("\tid: %d\tt: %s\n", id[i], t[i].arr);
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	printf("\ntest scroll_cur for fetch relative 4 (negative positions)\n");

	quit_loop = 0;
	while (!quit_loop)
	{
		for (i = 0; i < 8; i++)
			id[i] = 0, t[i].arr[0] = '\0';
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_relative, "4", 0, "scroll_cur", ECPGst_normal, "fetch relative 4 in scroll_cur", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 186 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 186 "cursor-ra-fetch.pgc"

		if (sqlca.sqlcode < 0)
			printf("fetch relative 4 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
		else
			printf("fetch relative 4 in scroll_cur succeeded, sqlerrd[2] %ld\n", sqlca.sqlerrd[2]);
		for (i = 0; i < sqlca.sqlerrd[2]; i++)
			printf("\tid: %d\tt: %s\n", id[i], t[i].arr);
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 196 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 196 "cursor-ra-fetch.pgc"


	/*
	 * Test FETCH FORWARD +/- 4 using positive positions
	 * readahead is 8, so caching is in effect
	 */

	printf("\ntest scroll_cur for fetch forward 4 (positive positions)\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 8, 0, 0, "scroll_cur", ECPGst_normal, "declare scroll_cur scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 205 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 205 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	quit_loop = 0;
	while (!quit_loop)
	{
		for (i = 0; i < 8; i++)
			id[i] = 0, t[i].arr[0] = '\0';
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "4", 0, "scroll_cur", ECPGst_normal, "fetch forward 4 in scroll_cur", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 214 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 214 "cursor-ra-fetch.pgc"

		if (sqlca.sqlcode < 0)
			printf("fetch forward 4 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
		else
			printf("fetch forward 4 in scroll_cur succeeded, sqlerrd[2] %ld\n", sqlca.sqlerrd[2]);
		for (i = 0; i < sqlca.sqlerrd[2]; i++)
			printf("\tid: %d\tt: %s\n", id[i], t[i].arr);
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	printf("\ntest scroll_cur for fetch forward -4 (positive positions)\n");

	quit_loop = 0;
	while (!quit_loop)
	{
		for (i = 0; i < 8; i++)
			id[i] = 0, t[i].arr[0] = '\0';
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "- 4", 0, "scroll_cur", ECPGst_normal, "fetch forward - 4 in scroll_cur", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 231 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 231 "cursor-ra-fetch.pgc"

		if (sqlca.sqlcode < 0)
			printf("fetch forward -4 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
		else
			printf("fetch forward -4 in scroll_cur succeeded, sqlerrd[2] %ld\n", sqlca.sqlerrd[2]);
		for (i = 0; i < sqlca.sqlerrd[2]; i++)
			printf("\tid: %d\tt: %s\n", id[i], t[i].arr);
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 241 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 241 "cursor-ra-fetch.pgc"


	/*
	 * Test FETCH FORWARD +/- 4 using negative positions
	 * readahead is 8, so caching is in effect
	 */

	printf("\ntest scroll_cur for fetch forward -4 (negative positions)\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 8, 0, 0, "scroll_cur", ECPGst_normal, "declare scroll_cur scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 250 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 250 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute, "- 1", 1, "scroll_cur", ECPGst_normal, "move absolute - 1 in scroll_cur", ECPGt_EOIT, ECPGt_EORT);
#line 254 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 254 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("move absolute -1 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "1", 1, "scroll_cur", ECPGst_normal, "move forward 1 in scroll_cur", ECPGt_EOIT, ECPGt_EORT);
#line 257 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 257 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("move forward 1 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);

	quit_loop = 0;
	while (!quit_loop)
	{
		for (i = 0; i < 8; i++)
			id[i] = 0, t[i].arr[0] = '\0';
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "- 4", 0, "scroll_cur", ECPGst_normal, "fetch forward - 4 in scroll_cur", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 266 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 266 "cursor-ra-fetch.pgc"

		if (sqlca.sqlcode < 0)
			printf("fetch forward -4 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
		else
			printf("fetch forward -4 in scroll_cur succeeded, sqlerrd[2] %ld\n", sqlca.sqlerrd[2]);
		for (i = 0; i < sqlca.sqlerrd[2]; i++)
			printf("\tid: %d\tt: %s\n", id[i], t[i].arr);
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	printf("\ntest scroll_cur for fetch forward 4 (negative positions)\n");

	quit_loop = 0;
	while (!quit_loop)
	{
		for (i = 0; i < 8; i++)
			id[i] = 0, t[i].arr[0] = '\0';
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "4", 0, "scroll_cur", ECPGst_normal, "fetch forward 4 in scroll_cur", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 283 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 283 "cursor-ra-fetch.pgc"

		if (sqlca.sqlcode < 0)
			printf("fetch forward 4 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
		else
			printf("fetch forward 4 in scroll_cur succeeded, sqlerrd[2] %ld\n", sqlca.sqlerrd[2]);
		for (i = 0; i < sqlca.sqlerrd[2]; i++)
			printf("\tid: %d\tt: %s\n", id[i], t[i].arr);
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 293 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 293 "cursor-ra-fetch.pgc"


	/*
	 * Test FETCH ABSOLUTE N with an interval of 5 using positive positions.
	 * Readahead is 4 so cache misses occur.
	 * ecpglib will switch to plain ecpg_execute after 3 cache misses
	 */

	printf("\ntest scroll_cur4 for move absolute n (every 5th tuple forward, positive positions)\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 4, 0, 0, "scroll_cur4", ECPGst_normal, "declare scroll_cur4 scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 303 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 303 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	for (i = 1; i < 35; i += 5)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute_in_var, NULL, 0, "scroll_cur4", ECPGst_normal, "fetch absolute $0 from scroll_cur4", 
	ECPGt_int,&(i),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 309 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 309 "cursor-ra-fetch.pgc"


		if (sqlca.sqlerrd[2] == 1)
			printf("\trow %d: id: %d\tt: %s\n", i, id[0], t[0].arr);
		else
			printf("\trow %d does not exist\n", i);
	}

	/*
	 * Let's see caching recovers by fetching 2x the readahead size.
	 * The cursor must be at the end now, with the cursor's pos,
	 * backend_pos, atstart and atend correctly set.
	 */

	printf("\ntest fetch backward 8 from scroll_cur4 after the cursor switched to ecpg_execute()\n");

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_backward, "8", 0, "scroll_cur4", ECPGst_normal, "fetch backward 8 from scroll_cur4", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 325 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 325 "cursor-ra-fetch.pgc"

	for (i = 0; i < sqlca.sqlerrd[2]; i++)
		printf("\tid: %d t: %s\n", id[i], t[i].arr);

	printf("\ntest scroll_cur4 for move absolute n (every 5th tuple backward, positive positions)\n");

	for (i = 36; i >= 0; i -= 5)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute_in_var, NULL, 0, "scroll_cur4", ECPGst_normal, "fetch absolute $0 from scroll_cur4", 
	ECPGt_int,&(i),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 333 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 333 "cursor-ra-fetch.pgc"


		if (sqlca.sqlerrd[2] == 1)
			printf("\trow %d: id: %d\tt: %s\n", i, id[0], t[0].arr);
		else
			printf("\trow %d does not exist\n", i);
	}

	/*
	 * Let's see caching recovers by fetching 2x the readahead size.
	 * The cursor must be at the start+1 (pos == 1) now,
	 * with the cursor's pos, backend_pos, atstart and atend
	 * correctly set.
	 */

	printf("\ntest fetch forward 8 from scroll_cur4 after the cursor switched to ecpg_execute()\n");

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "8", 0, "scroll_cur4", ECPGst_normal, "fetch forward 8 from scroll_cur4", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 350 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 350 "cursor-ra-fetch.pgc"

	for (i = 0; i < sqlca.sqlerrd[2]; i++)
		printf("\tid: %d t: %s\n", id[i], t[i].arr);

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 354 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 354 "cursor-ra-fetch.pgc"


	/*
	 * Test FETCH ABSOLUTE N with an interval of 5 using negative positions.
	 * Readahead is 4 so cache misses occur.
	 * ecpglib will switch to plain ecpg_execute after 3 cache misses
	 */

	printf("\ntest scroll_cur4 for move absolute n (every 5th tuple backward, negative positions)\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 4, 0, 0, "scroll_cur4", ECPGst_normal, "declare scroll_cur4 scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 364 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 364 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	for (i = -1; i > -35; i -= 5)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute_in_var, NULL, 0, "scroll_cur4", ECPGst_normal, "fetch absolute $0 from scroll_cur4", 
	ECPGt_int,&(i),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 370 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 370 "cursor-ra-fetch.pgc"


		if (sqlca.sqlerrd[2] == 1)
			printf("\trow %d: id: %d\tt: %s\n", i, id[0], t[0].arr);
		else
			printf("\trow %d does not exist\n", i);
	}

	/*
	 * Let's see caching recovers by fetching 2x the readahead size.
	 * The cursor must be at the start (pos == -27) now,
	 * with the cursor's pos, backend_pos, atstart and atend
	 * correctly set.
	 */

	printf("\ntest fetch forward 8 from scroll_cur4 after the cursor switched to ecpg_execute()\n");

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "8", 0, "scroll_cur4", ECPGst_normal, "fetch forward 8 from scroll_cur4", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 387 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 387 "cursor-ra-fetch.pgc"

	for (i = 0; i < sqlca.sqlerrd[2]; i++)
		printf("\tid: %d t: %s\n", id[i], t[i].arr);

	printf("\ntest scroll_cur4 for move absolute n (every 5th tuple forward, negative positions)\n");

	for (i = -36; i <= 0; i += 5)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute_in_var, NULL, 0, "scroll_cur4", ECPGst_normal, "fetch absolute $0 from scroll_cur4", 
	ECPGt_int,&(i),(long)1,(long)1,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 395 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 395 "cursor-ra-fetch.pgc"


		if (sqlca.sqlerrd[2] == 1)
			printf("\trow %d: id: %d\tt: %s\n", i, id[0], t[0].arr);
		else
			printf("\trow %d does not exist\n", i);
	}

	/*
	 * Let's see caching recovers by fetching 2x the readahead size.
	 * The cursor must be at the end-1 (pos == -1) now,
	 * with the cursor's pos, backend_pos, atstart and atend
	 * correctly set.
	 */

	printf("\ntest fetch backward 8 from scroll_cur4 after the cursor switched to ecpg_execute()\n");

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_backward, "8", 0, "scroll_cur4", ECPGst_normal, "fetch backward 8 from scroll_cur4", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 412 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 412 "cursor-ra-fetch.pgc"

	for (i = 0; i < sqlca.sqlerrd[2]; i++)
		printf("\tid: %d t: %s\n", id[i], t[i].arr);

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 416 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 416 "cursor-ra-fetch.pgc"


	/*
	 * Test FETCH RELATIVE +/- 5 using positive positions.
	 * Readahead is 4 so cache misses occur.
	 * ecpglib will switch to plain ecpg_execute after 3 cache misses
	 */

	printf("\ntest scroll_cur4 for fetch relative 5 (positive positions)\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 4, 0, 0, "scroll_cur4", ECPGst_normal, "declare scroll_cur4 scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 426 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 426 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	quit_loop = 0;
	while (!quit_loop)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_relative, "5", 0, "scroll_cur4", ECPGst_normal, "fetch relative 5 from scroll_cur4", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 433 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 433 "cursor-ra-fetch.pgc"


		if (sqlca.sqlerrd[2] == 1)
			printf("\tid: %d\tt: %s\n", id[0], t[0].arr);
		else
			printf("\tfetch returned empty\n");
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	/*
	 * Let's see caching recovers by fetching 2x the readahead size.
	 * The cursor must be at the end now,
	 * with the cursor's pos, backend_pos, atstart and atend
	 * correctly set.
	 */

	printf("\ntest fetch backward 8 from scroll_cur4 after the cursor switched to ecpg_execute()\n");

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_backward, "8", 0, "scroll_cur4", ECPGst_normal, "fetch backward 8 from scroll_cur4", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 451 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 451 "cursor-ra-fetch.pgc"

	for (i = 0; i < sqlca.sqlerrd[2]; i++)
		printf("\tid: %d t: %s\n", id[i], t[i].arr);

	/* Exaggerate the number of tuples, move to the end. */
	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "100", 1, "scroll_cur4", ECPGst_normal, "move forward 100 in scroll_cur4", ECPGt_EOIT, ECPGt_EORT);
#line 456 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 456 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("move forward 100 in scroll_cur4 failed with SQLSTATE %5s\n", sqlca.sqlstate);

	printf("\ntest scroll_cur4 for fetch relative -5 (positive positions)\n");

	quit_loop = 0;
	while (!quit_loop)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_relative, "- 5", 0, "scroll_cur4", ECPGst_normal, "fetch relative - 5 from scroll_cur4", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 465 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 465 "cursor-ra-fetch.pgc"


		if (sqlca.sqlerrd[2] == 1)
			printf("\tid: %d\tt: %s\n", id[0], t[0].arr);
		else
			printf("\tfetch returned empty\n");
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	/*
	 * Let's see caching recovers by fetching 2x the readahead size.
	 * The cursor must be at the start now,
	 * with the cursor's pos, backend_pos, atstart and atend
	 * correctly set.
	 */

	printf("\ntest fetch forward 8 from scroll_cur4 after the cursor switched to ecpg_execute()\n");

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "8", 0, "scroll_cur4", ECPGst_normal, "fetch forward 8 from scroll_cur4", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 483 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 483 "cursor-ra-fetch.pgc"

	for (i = 0; i < sqlca.sqlerrd[2]; i++)
		printf("\tid: %d t: %s\n", id[i], t[i].arr);

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 487 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 487 "cursor-ra-fetch.pgc"


	/*
	 * Test FETCH RELATIVE +/- 5 using negative positions.
	 * Readahead is 4 so cache misses occur.
	 * ecpglib will switch to plain ecpg_execute after 3 cache misses
	 */

	printf("\ntest scroll_cur4 for move relative -5 (negative positions)\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 4, 0, 0, "scroll_cur4", ECPGst_normal, "declare scroll_cur4 scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 497 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 497 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute, "- 1", 1, "scroll_cur4", ECPGst_normal, "move absolute - 1 in scroll_cur4", ECPGt_EOIT, ECPGt_EORT);
#line 501 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 501 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("move absolute -1 in scroll_cur4 failed with SQLSTATE %5s\n", sqlca.sqlstate);
	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "1", 1, "scroll_cur4", ECPGst_normal, "move forward 1 in scroll_cur4", ECPGt_EOIT, ECPGt_EORT);
#line 504 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 504 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("move forward 1 in scroll_cur4 failed with SQLSTATE %5s\n", sqlca.sqlstate);

	quit_loop = 0;
	while (!quit_loop)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_relative, "- 5", 0, "scroll_cur4", ECPGst_normal, "fetch relative - 5 from scroll_cur4", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 511 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 511 "cursor-ra-fetch.pgc"


		if (sqlca.sqlerrd[2] == 1)
			printf("\tid: %d\tt: %s\n", id[0], t[0].arr);
		else
			printf("\tfetch returned empty\n");
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	/*
	 * Let's see caching recovers by fetching 2x the readahead size.
	 * The cursor must be at the start now,
	 * with the cursor's pos, backend_pos, atstart and atend
	 * correctly set.
	 */

	printf("\ntest fetch forward 8 from scroll_cur4 after the cursor switched to ecpg_execute()\n");

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "8", 0, "scroll_cur4", ECPGst_normal, "fetch forward 8 from scroll_cur4", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 529 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 529 "cursor-ra-fetch.pgc"

	for (i = 0; i < sqlca.sqlerrd[2]; i++)
		printf("\tid: %d t: %s\n", id[i], t[i].arr);

	/* Exaggerate the number of tuples, move to the start. */
	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_backward, "100", 1, "scroll_cur4", ECPGst_normal, "move backward 100 in scroll_cur4", ECPGt_EOIT, ECPGt_EORT);
#line 534 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 534 "cursor-ra-fetch.pgc"

	if (sqlca.sqlcode < 0)
		printf("move backward 100 in scroll_cur4 failed with SQLSTATE %5s\n", sqlca.sqlstate);

	printf("\ntest scroll_cur for move relative 5 (negative positions)\n");

	quit_loop = 0;
	while (!quit_loop)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_relative, "5", 0, "scroll_cur4", ECPGst_normal, "fetch relative 5 from scroll_cur4", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 543 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 543 "cursor-ra-fetch.pgc"


		if (sqlca.sqlerrd[2] == 1)
			printf("\tid: %d\tt: %s\n", id[0], t[0].arr);
		else
			printf("\tfetch returned empty\n");
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	/*
	 * Let's see caching recovers by fetching 2x the readahead size.
	 * The cursor must be at the end now,
	 * with the cursor's pos, backend_pos, atstart and atend
	 * correctly set.
	 */

	printf("\ntest fetch backward 8 from scroll_cur4 after the cursor switched to ecpg_execute()\n");

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_backward, "8", 0, "scroll_cur4", ECPGst_normal, "fetch backward 8 from scroll_cur4", ECPGt_EOIT, 
	ECPGt_int,(id),(long)1,(long)8,sizeof(int), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, 
	ECPGt_varchar,(t),(long)50,(long)8,sizeof(struct varchar_1), 
	ECPGt_NO_INDICATOR, NULL , 0L, 0L, 0L, ECPGt_EORT);
#line 561 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 561 "cursor-ra-fetch.pgc"

	for (i = 0; i < sqlca.sqlerrd[2]; i++)
		printf("\tid: %d t: %s\n", id[i], t[i].arr);

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 565 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 565 "cursor-ra-fetch.pgc"


	/* Drop the test table */

	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "drop table t1", ECPGt_EOIT, ECPGt_EORT);
#line 569 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 569 "cursor-ra-fetch.pgc"

	{ ECPGtrans(__LINE__, NULL, "commit", 0, 0, 0, NULL);
#line 570 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 570 "cursor-ra-fetch.pgc"


	{ ECPGdisconnect(__LINE__, "ALL");
#line 572 "cursor-ra-fetch.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 572 "cursor-ra-fetch.pgc"


	return 0;
}
