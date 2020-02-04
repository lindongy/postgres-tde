#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <crypt.h>

char	fn_templ[16] = "passwd.h.XXXXXX\0";
char	salt[16];
char	*key1, key[4096];
char	*crypted;

static void set_des_salt(void)
{
	strncpy(salt, &fn_templ[9], 2);
	salt[3] = '\0';
}

static void set_glibc2_salt(char c)
{
	strcpy(salt, "$C$XX");
	salt[1] = c;
	strncpy(&salt[3], &fn_templ[9], 2);
}

static char get_crypt_scheme(void)
{
	char	c, c1;
	int	chars;

	while (1)
	{
		printf("Please, choose an encryption scheme.\n");
		printf("0 - DES\n1 - MD5\n5 - SHA-256\n6 - SHA-512\nYour selection: ");
		c = fgetc(stdin);
		chars = 1;
		c1 = fgetc(stdin);
		while (c1 != '\r' && c1 != '\n')
		{
			chars++;
			c1 = fgetc(stdin);
		}
		if (chars > 1)
			printf ("You must enter a single character from the above choices\n");
		else
			switch (c)
			{
				case '0':
				case '1':
				case '5':
				case '6':
					goto out;
				default:
					printf("You must enter a character from the above choices\n");
					continue;
			}
	}
out:
	return c;
}

int main(void)
{
	int	f, i;
	FILE	*fd;
	char	c;

	f = mkstemp(fn_templ);
	if (f < 0)
	{
		printf("error: %s\n", strerror(errno));
		return 1;
	}
	close(f);
	unlink(fn_templ);

	printf("This programme will create plpgsql_pwd.h\n");
#ifdef __GLIBC__
#  if (__GLIBC__ == 2)
	switch ((c = get_crypt_scheme()))
	{
		case '0':
			set_des_salt();
			break;
		default:
			set_glibc2_salt(c);
			break;
	}
#  else
	set_des_salt();
#  endif
#else
	set_des_salt();
#endif

	printf("crypt(3) call will use this salt value: '%s'\n", salt);

	while (1)
	{
		printf("Please, enter your password (at least 8 chars long): ");
		key1 = fgets(key, 4095, stdin);
		for (i = 0; key[i] != '\r' && key[i] != '\n'; i++)
			;
		key[i] = '\0';
		if (i < 8)
		{
			printf("Your password is too short\n");
			continue;
		}
		break;
	}

	crypted = crypt(key, salt);

	fd = fopen("passwd.h", "w+");

	fprintf(fd, "#ifndef PASSWD_H\n");
	fprintf(fd, "#define PASSWD_H\n");
	fprintf(fd, "static char *mypassword = \"%s\";\n", crypted);
	fprintf(fd, "#endif /* PASSWD_H */\n");

	fclose(fd);

	return 0;
}
