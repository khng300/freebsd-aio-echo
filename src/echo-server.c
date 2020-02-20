#include <stdbool.h>

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/tree.h>		/* For binary search tree */
#include <unistd.h>

/*
 * Parameters
 */
#define LISTEN_PORT 2222
#define LISTEN_BACKLOG 10

#define BUFFER_SIZE PAGE_SIZE


#define INVALID_HANDLE -1

struct sockctx {
	/* The FD corresponding */
	int fd;
	/* Indicate whether this FD is a listening socket */
	bool listener;
	/* The address associated with the socket */
	struct sockaddr_in6 saddr;
	/* AIO read control block for this socket */
	struct aiocb aioreadcb;
	/* AIO write control block for this socket */
	struct aiocb aiowritecb;
	/* AIO buffer */
	void *buf;
	/* Buffer size */
	size_t bufsz;
	/* The RB-Tree entry of this socket context */
	RB_ENTRY(sockctx) rbt_entry;
};

static int
sockctx_fd_cmp(struct sockctx *elm, struct sockctx *cur)
{
	if (elm->fd < cur->fd)
		return -1;
	if (elm->fd > cur->fd)
		return 1;
	return 0;
}

RB_HEAD(sockctx_rbt, sockctx) sockctx_container;
RB_GENERATE(sockctx_rbt, sockctx, rbt_entry, sockctx_fd_cmp);

static struct sockctx *
get_sockctx(int fd, bool listener, size_t bufsz)
{
	struct sockctx *sctx;
	
	sctx = (struct sockctx *)malloc(sizeof(struct sockctx));
	if (sctx == NULL)
		return NULL;
	sctx->fd = fd;
	sctx->listener = listener;
	sctx->bufsz = bufsz;
	sctx->buf = NULL;
	if (bufsz) {
		sctx->buf = mmap(NULL, bufsz,
		    PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
		if (sctx->buf == MAP_FAILED) {
			free(sctx);
			return NULL;
		}
	}
	RB_INSERT(sockctx_rbt, &sockctx_container, sctx);
	return sctx;
}

static void
kill_sockctx(struct sockctx *sctx, bool reset)
{
	RB_REMOVE(sockctx_rbt, &sockctx_container, sctx);
	if (!sctx->listener && !reset)
		shutdown(sctx->fd, SHUT_RDWR);
	close(sctx->fd);
	if (sctx->buf)
		munmap(sctx->buf, BUFFER_SIZE);
	free(sctx);
}

static struct sockctx *
find_sockctx(int fd)
{
	struct sockctx elm;
	elm.fd = fd;

	return RB_FIND(sockctx_rbt, &sockctx_container, &elm);
}

static void
sockctx_container_cleanup()
{
	struct sockctx *sctx, *tsctx;

	RB_FOREACH_SAFE(sctx, sockctx_rbt, &sockctx_container, tsctx) {
		kill_sockctx(sctx, false);
	}
}

static int
enable_dualstack(int sockfd)
{
	int v6only = 0;

	return setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
	    sizeof(v6only));
}

int
main(int argc, char **argv)
{
	int exitcode = EXIT_FAILURE, ret;
	int kqfd = INVALID_HANDLE;
	int listenfd = INVALID_HANDLE;
	struct kevent event;
	struct kevent tevent;
	struct sockctx *sctx;

	kqfd = kqueue();
	if (kqfd == INVALID_HANDLE) {
		perror("kqueue");
		goto out;
	}

	signal(SIGPIPE, SIG_IGN);

	listenfd = socket(PF_INET6, SOCK_STREAM, 0);
	if (listenfd == INVALID_HANDLE) {
		perror("socket");
		goto out;
	}

	sctx = get_sockctx(listenfd, true, 0);
	if (sctx == NULL) {
		perror("get_sockctx");
		close(listenfd);
		goto out;
	}

	ret = enable_dualstack(listenfd);
	if (ret == -1) {
		perror("enable_dualstack");
		goto out;
	}

	sctx->saddr.sin6_family = AF_INET6;
	sctx->saddr.sin6_addr = in6addr_any;
	sctx->saddr.sin6_port = htons(LISTEN_PORT);
	ret = bind(listenfd, (struct sockaddr *)&sctx->saddr,
	    sizeof(struct sockaddr_in6));
	if (ret == -1) {
		perror("bind");
		goto out;
	}

	ret = listen(listenfd, LISTEN_BACKLOG);
	if (ret == -1) {
		perror("listen");
		goto out;
	}

	EV_SET(&event, listenfd, EVFILT_READ, EV_ADD, 0, 0, sctx);
	ret = kevent(kqfd, &event, 1, NULL, 0, NULL);
	if (ret == -1) {
		perror("kevent");
		goto out;
	}
	if (event.flags & EV_ERROR) {
		fprintf(stderr, "Event error: %s\n", strerror(event.data));
		goto out;
	}

	while (1) {
		int infd;
		int fdflags;
		struct aiocb *aiocbp;
		ssize_t aioret;

		ret = kevent(kqfd, NULL, 0, &tevent, 1, NULL);
		if (ret == -1) {
			perror("kevent");
			goto out;
		} else if (!ret)
			continue;

		sctx = (struct sockctx *)tevent.udata;
		if (sctx->listener) {
			socklen_t saddrlen;
			struct sockctx *newsctx;
			struct sockaddr_in6 insaddr;
			char ip6str[INET6_ADDRSTRLEN];

			saddrlen = sizeof(struct sockaddr_in6);
			infd = ret = accept(sctx->fd,
			    (struct sockaddr *)&insaddr,
			    &saddrlen);
			if (ret == -1) {
				perror("accept");
				continue;
			}

			inet_ntop(AF_INET6, &insaddr.sin6_addr, ip6str,
			    INET6_ADDRSTRLEN);
			fprintf(stderr,
			    "Accepted a connection. FD: %d, Address: %s.%hu\n",
			    infd, ip6str, ntohs(insaddr.sin6_port));

			fdflags = ret = fcntl(infd, F_GETFL);
			if (ret == -1) {
				perror("fcntl(..., F_GETFL)");
				close(infd);
				continue;
			}
			ret = fcntl(infd, F_SETFL, fdflags);
			if (ret == -1) {
				perror(
				    "fcntl(..., F_SETFL, fdflags | O_NONBLOCK)");
				close(infd);
				continue;
			}

			newsctx = get_sockctx(infd, false, BUFFER_SIZE);
			if (newsctx == NULL) {
				perror("get_sockctx");
				close(infd);
				continue;
			}
			newsctx->saddr = insaddr;

			memset(&newsctx->aioreadcb, 0, sizeof(struct aiocb));
			newsctx->aioreadcb.aio_fildes = infd;
			newsctx->aioreadcb.aio_offset = 0;
			newsctx->aioreadcb.aio_buf = newsctx->buf;
			newsctx->aioreadcb.aio_nbytes = newsctx->bufsz;
			newsctx->aioreadcb.aio_lio_opcode = LIO_READ;
			newsctx->aioreadcb.aio_sigevent.sigev_notify =
			    SIGEV_KEVENT;
			newsctx->aioreadcb.aio_sigevent.sigev_notify_kqueue =
			    kqfd;
			newsctx->aioreadcb.aio_sigevent.sigev_value.sigval_ptr =
			    newsctx;
			ret = aio_read(&newsctx->aioreadcb);
			if (ret == -1) {
				perror("aio_read");
				kill_sockctx(newsctx, true);
			}
			continue;
		}
		aiocbp = (struct aiocb *)tevent.ident;
		aioret = aio_return(aiocbp);
		if (aioret == -1) {
			fprintf(stderr, "aiocb error: %s\n",
			    strerror(tevent.data));
			kill_sockctx(sctx, true);
			continue;
		} else if (aioret == 0) {
			char ip6str[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET6, &sctx->saddr.sin6_addr, ip6str,
			    INET6_ADDRSTRLEN);
			fprintf(stderr,
			    "Closed a connection. FD: %d, Address: %s.%hu\n",
			    sctx->fd, ip6str, ntohs(sctx->saddr.sin6_port));
			kill_sockctx(sctx, false);
			continue;
		}
		if (aiocbp == &sctx->aioreadcb) {
			memset(&sctx->aiowritecb, 0, sizeof(struct aiocb));
			sctx->aiowritecb.aio_fildes = sctx->fd;
			sctx->aiowritecb.aio_offset = 0;
			sctx->aiowritecb.aio_buf = sctx->buf;
			sctx->aiowritecb.aio_nbytes = aioret;
			sctx->aiowritecb.aio_sigevent.sigev_notify =
			    SIGEV_KEVENT;
			sctx->aiowritecb.aio_sigevent.sigev_notify_kqueue =
			    kqfd;
			sctx->aiowritecb.aio_sigevent.sigev_value.sigval_ptr =
			    sctx;
			ret = aio_write(&sctx->aiowritecb);
			if (ret == -1) {
				perror("aio_write");
				kill_sockctx(sctx, true);
			}
		} else {
			if (aioret < sctx->aiowritecb.aio_nbytes) {
				/* This path is for socket with O_NONBLOCK. */
				size_t rembytes = sctx->aiowritecb.aio_nbytes;

				memset(&sctx->aiowritecb, 0, sizeof(struct aiocb));
				sctx->aiowritecb.aio_fildes = sctx->fd;
				sctx->aiowritecb.aio_offset = 0;
				sctx->aiowritecb.aio_buf = (char *)sctx->buf + aioret;
				sctx->aiowritecb.aio_nbytes = rembytes - aioret;
				sctx->aiowritecb.aio_sigevent.sigev_notify =
					SIGEV_KEVENT;
				sctx->aiowritecb.aio_sigevent.sigev_notify_kqueue =
					kqfd;
				sctx->aiowritecb.aio_sigevent.sigev_value.sigval_ptr =
					sctx;
				ret = aio_write(&sctx->aiowritecb);
				if (ret == -1) {
					perror("aio_write");
					kill_sockctx(sctx, true);
				}
			} else {
				memset(&sctx->aioreadcb, 0, sizeof(struct aiocb));
				sctx->aioreadcb.aio_fildes = sctx->fd;
				sctx->aioreadcb.aio_offset = 0;
				sctx->aioreadcb.aio_buf = sctx->buf;
				sctx->aioreadcb.aio_nbytes = sctx->bufsz;
				sctx->aioreadcb.aio_sigevent.sigev_notify =
					SIGEV_KEVENT;
				sctx->aioreadcb.aio_sigevent.sigev_notify_kqueue =
					kqfd;
				sctx->aioreadcb.aio_sigevent.sigev_value.sigval_ptr =
					sctx;
				ret = aio_read(&sctx->aioreadcb);
				if (ret == -1) {
					perror("aio_read");
					kill_sockctx(sctx, true);
				}
			}
		}
	}
	
out:
	sockctx_container_cleanup();
	if (kqfd != INVALID_HANDLE)
		close(kqfd);
	return (exitcode);
}
