#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
FILE *fptr;

int server_fd;	   // Global server socket to close on shutdown
fd_set active_fds; // Global file descriptor set for cleanup
char filepath[] = "/var/tmp/aesdsocketdata";
char filebuf[30000];
size_t loc = 0;
FILE *fptr;

void sig_handler(int param)
{
	syslog(LOG_WARNING, "Signal received %d.", param);
	// Close all active client sockets
	for (int fd = 0; fd < FD_SETSIZE; fd++) {
		if (FD_ISSET(fd, &active_fds)) {
			close(fd);
		}
	}

	// Close the server socket
	close(server_fd);

	if (fptr != NULL) {
		fclose(fptr);
	}
	unlink(filepath);
	// Exit the program
	exit(0);
}

void *periodic_function(void *arg)
{
	time_t t;
	struct tm *tmp;

	t = time(NULL);
	tmp = localtime(&t);

	while (1) {
		strftime(outstr, sizeof(outstr), argv[1], tmp
		printf("Function called!\n");
		sleep(); // Wait 5 seconds
	}
	return NULL;
}

void *handle_data(void *arg)
{
	char buffer[BUFFER_SIZE];
	int fd = *(int *)arg;
	int bytes_read;
	char *found;

	memset(buffer, 0, BUFFER_SIZE);
	bytes_read = recv(fd, buffer, BUFFER_SIZE - 1, 0);

	while (1) {
		if (bytes_read <= 0) {
			if (bytes_read == 0) {
				syslog(LOG_DEBUG, "Client disconnected\n");
			} else {
				syslog(LOG_ERR, "Recv failed");
			}
			close(fd);
			break;
		} else {
			found = strstr(buffer, "\n");
			if (found) {
				send(fd, filebuf, loc, 0);
			} else {
				// append to list
			}
		}
	}

	return NULL;
}

// Function to set a socket to non-blocking mode
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

void start_timer()
{
	pthread_t thread_id;

	// Create the thread
	pthread_create(&thread_id, NULL, periodic_function, NULL);

	// Wait for the thread to finish (in this case, it runs indefinitely)
	pthread_join(thread_id, NULL);
}

int main(int argc, char **argv)
{
	int ret = 0;
	int client_fd, max_fd;
	struct sockaddr_in servaddr, client_addr;
	int client_len = sizeof(client_addr);
	struct hostent *hostp;
	char *hostaddrp;
	fd_set read_fds;
	pid_t pid;
	char buffer[BUFFER_SIZE];

	openlog(NULL, LOG_NDELAY, LOG_USER | LOG_CONS);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1) {
		syslog(LOG_ERR, "socket not created.");
		ret = -1;
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
		ret = -1;
		goto close_soc;
	}

	if (argc == 2 && argv[1][1] == 'd') {
		pid_t pid = fork();

		if (pid < 0) {
			syslog(LOG_ERR, "Fork failed exiting");
			ret = -1;
			goto close_soc;
		} else if (pid > 0) {
			// parent
			goto close_soc;
		}
	}

	fptr = fopen(filepath, "w");

	if (fptr == NULL) {
		syslog(LOG_ERR, "file not opened");
		ret = 1;
		goto close_soc;
	}

	if (listen(server_fd, 5) < 0) {
		syslog(LOG_ERR, "ERROR on listen");
	}

	// Initialize the fd sets
	FD_ZERO(&active_fds);
	FD_SET(server_fd, &active_fds);
	max_fd = server_fd;

	while (1) {

		read_fds = active_fds;

		// Use select to wait for events
		if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
			syslog(LOG_ERR, "Select failed");
			ret = 1;
			goto close_file;
		}

		for (int fd = 0; fd <= max_fd; fd++) {
			if (FD_ISSET(fd, &read_fds)) {
				if (fd == server_fd) {
					// New connection
					client_fd =
						accept(server_fd, (struct sockaddr *)&client_addr,
						       &client_len);
					if (client_fd < 0) {
						syslog(LOG_ERR, "Accept failed");
						continue;
					}

					printf("New connection from %s:%d\n",
					       inet_ntoa(client_addr.sin_addr),
					       ntohs(client_addr.sin_port));
					syslog(LOG_DEBUG, "Accepted connection from  %s:%d",
					       inet_ntoa(client_addr.sin_addr),
					       ntohs(client_addr.sin_port));
					// Set the new client socket to non-blocking mode
					set_nonblocking(client_fd);

					// Add the new client socket to the active set
					FD_SET(client_fd, &active_fds);
					if (client_fd > max_fd) {
						max_fd = client_fd;
					}
				} else {
					// Handle data from a client
					memset(buffer, 0, BUFFER_SIZE);
					int bytes_read = recv(fd, buffer, BUFFER_SIZE - 1, 0);
					if (bytes_read <= 0) {
						if (bytes_read == 0) {
							syslog(LOG_DEBUG, "Client disconnected\n");
						} else {
							syslog(LOG_ERR, "Recv failed");
						}
						close(fd);
						FD_CLR(fd, &active_fds);
					} else {
						memcpy(filebuf + loc, buffer, bytes_read);
						loc += bytes_read;
						// printf("received data %s\n", buffer);
						if (loc != 0 && filebuf[loc - 1] == '\n') {
							send(fd, filebuf, loc, 0);
						}
						fprintf(fptr, "%s", buffer);
						fflush(fptr);
					}
				}
			}
		}
	}

close_file:
	fclose(fptr);
	unlink(filepath);
close_soc:
	for (int fd = 0; fd < FD_SETSIZE; fd++) {
		if (FD_ISSET(fd, &active_fds)) {
			close(fd);
		}
	}

	// Close the server socket
	close(server_fd);

exit:
	closelog();
	return ret;
}
