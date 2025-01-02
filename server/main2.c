#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/queue.h>

#ifndef USE_AESD_CHAR
#define USE_AESD_CHAR 1
#endif

#if USE_AESD_CHAR
const char filename[] = "/dev/aesdchar";
#else
const char filename[] = "/var/tmp/aesdsocketdata";
#endif

#define SuccessOrExit(param)                                                                       \
	do {                                                                                       \
		if ((param) != 0) {                                                                \
			goto exit;                                                                 \
		}                                                                                  \
	} while (0)

#define VerifyOrExit(condition)                                                                    \
	do {                                                                                       \
		if (!(condition)) {                                                                \
			goto exit;                                                                 \
		}                                                                                  \
	} while (0)

void insert_file(char *buf, size_t size);

FILE *file;

int terminate = 0;

pthread_mutex_t mutex;

void sig_handler(int param)
{
	terminate = 1;
}

void config_signals()
{
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
}

int handle_options(int argc, char **argv)
{
	int opt;
	pid_t pid;

	while ((opt = getopt(argc, argv, "d")) != -1) {
		switch (opt) {
		case 'd':
			pid = fork();

			if (pid < 0) {
				syslog(LOG_ERR, "Fork failed exiting");
				return -1;
			} else if (pid > 0) {
				syslog(LOG_ERR, "Fork failed exiting");
				return -2;
			}
			break;
		default:
			return -1;
		}
	}

	return 0;
}

void *periodic_function(void *arg)
{
	time_t t;
	struct tm *tmp;
	char buf[64];

	t = time(NULL);
	tmp = localtime(&t);

	while (!terminate) {
		size_t size = strftime(buf, sizeof(buf), "timestamp:%Y:%m:%d:%H:%M:%S\n", tmp);
		insert_file(buf, size);
		syslog(LOG_DEBUG, "Function called! Time: %s\n", buf);
		sleep(10);
	}
	return NULL;
}

void set_nonblocking(int sockfd)
{
	int flags = fcntl(sockfd, F_GETFL, 0);
	if (flags == -1) {
		syslog(LOG_ERR, "fcntl F_GETFL");
	}
	if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
		syslog(LOG_ERR, "fcntl F_SETFL");
	}
}

int create_server_socket()
{
	int error = 0;
	struct sockaddr_in servaddr;

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (server_fd == -1) {
		syslog(LOG_ERR, "socket not created.");
		syslog(LOG_DEBUG, "socket not created.");
		error = -1;
		goto exit;
	}

	set_nonblocking(server_fd);

	bzero(&servaddr, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(9000);

	if ((bind(server_fd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
		syslog(LOG_ERR, "Socket bind failed.");
		syslog(LOG_DEBUG, "Socket bind failed.");
		error = -1;
		goto close_soc;
	}

	if (listen(server_fd, 5) < 0) {
		syslog(LOG_ERR, "ERROR on listen");
		error = -1;
		goto close_soc;
	}

	goto exit;

close_soc:
	close(server_fd);

exit:
	if (error != 0) {
		return error;
	} else {
		return server_fd;
	}
}

void insert_file(char *buf, size_t size)
{
	pthread_mutex_lock(&mutex);
	// fprintf(file, "%s", buf);
	fseek(file, 0, SEEK_END);
	fwrite(buf, sizeof(buf[0]), size, file);
	pthread_mutex_unlock(&mutex);
}

int send_all(int fd)
{
	char buf[512];
	size_t read = 0;

	pthread_mutex_lock(&mutex);
	fseek(file, 0, SEEK_SET);
	while ((read = fread(buf, sizeof(buf[0]), sizeof(buf), file)) > 0) {
		if (send(fd, buf, read, 0) < 0) {
			return -1;
		}
	}
	pthread_mutex_unlock(&mutex);
}

void free_file()
{
	if (file != NULL) {
		fclose(file);
	}
}

void *handle_client(void *args)
{
	int *fd = (int *)args;
	char buf[3000000];
	size_t pos = 0;

	bzero(buf, sizeof(buf));

	syslog(LOG_DEBUG, "Client FD: %d \n", *fd);

	while (!terminate) {
		int bytes_read = recv(*fd, buf, sizeof(buf) - pos, 0);
		if (bytes_read > 0) {
			syslog(LOG_DEBUG, "Received %s\n", buf);

			pos += bytes_read;
			if (buf[pos - 1] == '\n') {
				insert_file(buf, pos);
				send_all(*fd);
				bzero(buf, sizeof(buf));
				pos = 0;
			}
		} else {
			syslog(LOG_DEBUG, "client disconnected\n");
			break;
		}
	}

exit:
	close(*fd);
	free(fd);
	return NULL;
}

int main(int argc, char **argv)
{
	int error = 0;
	int server_fd = -1;
	int client_fd;
	pthread_t thread_id[80];
	int maxclient = 0;
	int fds[20];
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);

	openlog(NULL, LOG_NDELAY, LOG_USER | LOG_CONS);

	syslog(LOG_DEBUG, "starting daemon aesdsocket");
	config_signals();

	pthread_mutex_init(&mutex, NULL);
	VerifyOrExit(server_fd = create_server_socket());

	SuccessOrExit(error = handle_options(argc, argv));

#if USE_AESD_CHAR == 0
	SuccessOrExit(error = pthread_create(thread_id, NULL, periodic_function, NULL));
	maxclient++;
#endif
	file = fopen(filename, "w+");
	if (file == NULL) {
		syslog(LOG_ERR, "File not opened");
		goto exit;
	}

	while (!terminate) {
		client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
		if (client_fd < 0) {
			// syslog(LOG_ERR, "Accept failed");
			// syslog(LOG_DEBUG,"Accept failed");
			continue;
		}
		int *fd = malloc(sizeof(client_fd));
		*fd = client_fd;
		syslog(LOG_DEBUG, "New connection from %s:%d\n", inet_ntoa(client_addr.sin_addr),
		       ntohs(client_addr.sin_port));

		syslog(LOG_DEBUG, "Accepted connection from  %s:%d",
		       inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

		syslog(LOG_DEBUG, "Spawning thread");
		SuccessOrExit(error = pthread_create(&thread_id[maxclient], NULL, handle_client,
						     (void *)fd));
		maxclient++;
	}

	syslog(LOG_DEBUG, "Program terminated normally.\n");

	for (size_t i = 0; i < maxclient; i++) {
		SuccessOrExit(error = pthread_cancel(thread_id[i]));
		SuccessOrExit(error = pthread_join(thread_id[i], NULL));
	}
	syslog(LOG_DEBUG, "Program threads terminated.\n");

	pthread_mutex_destroy(&mutex);
exit:
	if (server_fd >= 0) {
		close(server_fd);
	}
	free_file();
	if (error == -2) {
		exit(0);
	}
	exit(error);
}
