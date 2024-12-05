#include <syslog.h>
#include <stddef.h>
#include <stdio.h>

int main (int argc, char **argv) {
	FILE *fptr;
	int ret = 0;

	openlog(NULL, LOG_NDELAY, LOG_USER);
	if (argc != 3)	{
		syslog(LOG_ERR, "unexpected number of arguments");
		ret = 1;
		goto exit;
	}

	fptr = fopen(argv[1], "w");

	if (fptr == NULL) {
		syslog(LOG_ERR, "file not opened");
		ret = 1;
		goto exit;
	}

	syslog(LOG_DEBUG, "Writing %s to %s", argv[1], argv[2]);

	fprintf(fptr, "%s", argv[2]);

	fclose(fptr);
exit:
	closelog();
	return ret;
}
