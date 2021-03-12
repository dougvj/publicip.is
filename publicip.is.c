#include <asm-generic/socket.h>
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <signal.h>
#include <sys/epoll.h>

#define MAX_BUF_LEN 1024


struct client_data {
  int epoll;
  int client_sock;
  int num_end_headers_bytes_found;
  struct sockaddr_in6 client_addr;
  char buffer[MAX_BUF_LEN];
  int buf_len;
  char* buf_ptr;
  int thread_num;
};


void init_client_data(struct client_data* d, int epoll) {
  d->epoll = epoll;
  d->buf_len = MAX_BUF_LEN;
  d->buf_ptr = d->buffer;
  d->num_end_headers_bytes_found = 0;
}

bool client_cont_read(struct client_data* d) {
  struct epoll_event ev;
  ev.data.fd = d->client_sock;
  ev.data.ptr = d;
  ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
  if (epoll_ctl(d->epoll, EPOLL_CTL_MOD, d->client_sock, &ev) == -1) {
    perror("epoll_ctl: EPOLL_CTL_MOD: client_sock");
    return false;
  }
  return true;
}

bool client_cont_write(struct client_data* d) {
  struct epoll_event ev;
  ev.data.fd = d->client_sock;
  ev.data.ptr = d;
  ev.events = EPOLLOUT | EPOLLET | EPOLLONESHOT;
  if (epoll_ctl(d->epoll, EPOLL_CTL_MOD, d->client_sock, &ev) == -1) {
    perror("epoll_ctl: EPOLL_CTL_MOD: client_sock");
    return false;
  }
  return true;
}

#define MAX_EVENTS 1

struct app_context {
  int port;
  int num_threads;
  int sock;
  int epoll;
  pthread_t* threads;
} context;

#define eprintf(...) fprintf(stderr, __VA_ARGS__);


void _500(int client) {
  char error_response[] = "HTTP/1.0 500 Internal Server Error\r\n\r\n";
  if (send(client, error_response, sizeof(error_response), 0) == -1) {
    perror("send");
  };
}

bool get_start_line_and_headers(struct client_data* d) {
  // Look for end of headers
  static const char END_HEADERS_BYTES[] = "\r\n\r\n";
  int num = recv(d->client_sock, d->buf_ptr, d->buf_len, 0);
  if (num == -1) {
    if (errno == EAGAIN) {
      return client_cont_read(d);
    }
    perror("recv");
    return false;
  }
  if (num == 0) {
    eprintf("recv: Unexpected socket close\n");
    return false;
  }
  for (int i = 0; i < num; i++) {
    if (d->buf_ptr[i] == END_HEADERS_BYTES[d->num_end_headers_bytes_found]) {
      d->num_end_headers_bytes_found++;
      if (d->num_end_headers_bytes_found == sizeof(END_HEADERS_BYTES) - 1) {
        return client_cont_write(d);
      }
    } else {
      d->num_end_headers_bytes_found = 0;
    }
  }
  d->buf_ptr += num;
  d->buf_len -= num;
  if (d->buf_len == 0) {
    eprintf("recv: Buffer Full\n");
    return false;
  }
  return client_cont_read(d);
}



bool return_ip(struct client_data* d) {
  // TODO parse the start line in case there are wierd requests
  char ip[INET6_ADDRSTRLEN];
  struct in6_addr* addr6 = &(d->client_addr.sin6_addr);
  struct in_addr* addr = (struct in_addr*)addr6;
  sa_family_t family = AF_INET6;
  // Detect ipv4 mapped ipv6 addr by converting raw IP address bytes into two
  // 64-bit ints and looking for the ::FFFF prefix
  uint64_t *addr_blocks = (uint64_t*)addr6->s6_addr;
  if (addr_blocks[0] == 0 &&
  // TODO deal with endianess, works on arm and x86 though so  ¯\_(ツ)_/¯
     (addr_blocks[1] & 0x00000000FFFFFFFF) == 0x00000000FFFF0000) {
    family = AF_INET;
    // addr4 is the last 4 bytes of addr6, which is 16 bytes
    struct in4_addr* addr4 = (struct in4_addr*)&(addr6->s6_addr[12]);
    addr = (struct in_addr*)addr4;
  }
  if (inet_ntop(family, addr, ip, INET6_ADDRSTRLEN) == NULL) {
    perror("inet_ntop");
    _500(d->client_sock);
    return false;
  };
  unsigned int ip_len = strlen(ip);
  int response_len = snprintf(
      d->buffer,
      MAX_BUF_LEN,
      "HTTP/1.0 200 OK\r\n"
      "Content-Length: %u\r\n"
      "Content-Type: text/plain\r\n"
      "Connection: close\r\n\r\n"
      "%s\n",
      ip_len + 1,
      ip
  );
  if (send(d->client_sock, d->buffer, response_len, 0) == -1) {
    if (errno == EAGAIN) {
      return client_cont_write(d);
    }
    perror("send");
    return false;
  }
  eprintf("%3i: %s\n", d->thread_num, ip);
  return false;
}

void process_client(struct epoll_event ev) {
  struct client_data *d = ev.data.ptr;
  bool cont = false;
  if (ev.events & EPOLLIN) {
    cont = get_start_line_and_headers(d);
  }
  if (ev.events & EPOLLOUT) {
    cont = return_ip(d);
  }
  if (!cont) {
    epoll_ctl(d->epoll, EPOLL_CTL_MOD, d->client_sock, NULL);
    shutdown(d->client_sock, SHUT_RDWR);
    close(d->client_sock);
    free(d);
  }
}

void* worker_thread(void* data) {
  struct app_context* context = data;
  static atomic_int thread_count = 0;
  int thread_num = atomic_fetch_add(&thread_count, 1);
  eprintf("Thread %i starting\n", thread_num);
  struct epoll_event events[MAX_EVENTS];
  for (;;) {
    int nfds = epoll_wait(context->epoll, events, MAX_EVENTS, -1);
    if (nfds == -1) {
      perror("epoll_wait");
      if (errno == EINTR) {
        break;
      }
    }
    for (int n = 0; n < nfds; n++) {
      if (events[n].data.fd == context->sock) {
        for(;;) {
          struct client_data* d = malloc(sizeof(struct client_data));
          socklen_t addrlen = sizeof(d->client_addr);
          d->client_sock =
              accept4(context->sock, (struct sockaddr *)&(d->client_addr),
                      &addrlen, SOCK_NONBLOCK);
          if (d->client_sock == -1) {
            free(d);
            if (errno != EAGAIN) {
              perror("accept");
            }
            break;
          }
          init_client_data(d, context->epoll);
          struct epoll_event ev;
          ev.data.fd = d->client_sock;
          ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
          ev.data.ptr = d;
          if (epoll_ctl(context->epoll, EPOLL_CTL_ADD, d->client_sock, &ev) ==
              -1) {
            perror("epoll_ctl: EPOLL_CTL_ADD: conn_sock");
            close(d->client_sock);
            free(d);
            continue;
          }
        }
      } else {
        struct client_data* d = events[n].data.ptr;
        d->thread_num = thread_num;
        process_client(events[n]);
      }
    }
  }
  eprintf("Thread %i stopping\n", thread_num);
  return 0;
}


void handle_term(int signo) {
  if (signo == SIGTERM || signo == SIGINT) {
    int num_threads = context.num_threads;
    eprintf("\nStopping server...\n");
    for (int i = 0; i < num_threads; i++) {
      pthread_kill(context.threads[i], SIGUSR1);
    }
    for (int i = 0; i < num_threads; i++) {
      pthread_join(context.threads[i], NULL);
    }
    shutdown(context.sock, SHUT_RDWR);
    close(context.sock);
    close(context.epoll);
  }
}

int main(int argc, char** argv) {
    int port, num_threads;
    if (argc != 2 && argc != 3) {
      eprintf("Usage:\n\t%s <port> (threads)\n"
              "\t<port> The port to listen on\n"
              "\t(threads) Optional number of threads to listen on\n"
              "\t          If not specified, num cores is used\n",
              argv[0]);
      exit(EXIT_FAILURE);
    } else {
      port = atoi(argv[1]);
      if (port == 0) {
        eprintf("Port is invalid\n");
        exit(EXIT_FAILURE);
      }
      if (argc == 3) {
        num_threads = atoi(argv[2]);
        if (num_threads == 0) {
          eprintf("Num threads is invalid\n");
          exit(EXIT_FAILURE);
        }
      } else {
        num_threads = get_nprocs();
      }
    }
    int sock = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) <
        0) {
      perror("setsockopt: SO_REUSEADDR");
    }
    struct sockaddr_in6 server;
    server.sin6_family = AF_INET6;
    server.sin6_port = htons(port);
    server.sin6_addr = in6addr_any;
    if (bind(sock, (struct sockaddr*)&server, sizeof(server)) == -1) {
      perror("bind");
      exit(EXIT_FAILURE);
    }
    if (listen(sock, 1) < 0) {
      perror("listen");
      exit(EXIT_FAILURE);
    }
    context.epoll = epoll_create1(0);
    if (context.epoll == -1) {
      perror("epoll_create1");
      exit(EXIT_FAILURE);
    }
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    if (epoll_ctl(context.epoll, EPOLL_CTL_ADD, sock, &ev) == -1) {
      perror("epoll_ctl: listen_sock");
      exit(EXIT_FAILURE);
    }

    // Block signals in threads except SIGUSR1 (signal masks are inherited)
    sigset_t mask;
    sigfillset(&mask);
    sigdelset(&mask, SIGUSR1);
    pthread_sigmask(SIG_SETMASK, &mask, NULL);
    signal(SIGUSR1, handle_term);
    // Create threads
    pthread_t threads[num_threads];
    for (int i = 0; i < num_threads; i++) {
      pthread_create(&(threads[i]), NULL, worker_thread, &context);
    }
    // Unblock signals except SIGUSR1, so SIGUSR1 goes to threads and the rest
    // goes to main thread
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    pthread_sigmask(SIG_SETMASK, &mask, NULL);
    signal(SIGTERM, handle_term);
    signal(SIGINT, handle_term);
    eprintf("%i threads waiting for clients on port %u\n", num_threads,
            port);
    // Fill in context for signal handler
    context.num_threads = num_threads;
    context.port = port;
    context.sock = sock;
    context.threads = threads;
    pause();
    exit(EXIT_SUCCESS);
}
