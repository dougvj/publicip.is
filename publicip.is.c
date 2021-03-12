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

struct client_data {
  int client_sock;
  struct sockaddr_in6 client_addr;
};

#define eprintf(...) fprintf(stderr, __VA_ARGS__);

#define MAX_BUF_LEN 1024

void _500(int client) {
  char error_response[] = "HTTP/1.0 500 Internal Server Error\r\n\r\n";
  if (send(client, error_response, sizeof(error_response), 0) == -1) {
    perror("send");
  };
}

bool get_start_line_and_headers(int client, char* buffer, int max_buf_len) {
  // Look for end of headers
  static const char END_HEADERS_BYTES[] = "\r\n\r\n";
  int num_end_headers_bytes_found = 0;
  for (;;) {
    int num = recv(client, buffer, max_buf_len, 0);
    if (num == -1) {
      perror("recv");
      return false;
    }
    if (num == 0) {
      eprintf("recv: Unexpected socket close\n");
      return false;
    }
    for (int i = 0; i < num; i++) {
      if (buffer[i] == END_HEADERS_BYTES[num_end_headers_bytes_found]) {
        num_end_headers_bytes_found++;
        if (num_end_headers_bytes_found == sizeof(END_HEADERS_BYTES) - 1) {
          return true;
        }
      } else {
        num_end_headers_bytes_found = 0;
      }
    }
    buffer += num;
    max_buf_len -= num;
    if (max_buf_len == 0) {
      eprintf("recv: Buffer Full\n");
      return false;
    }
  }
}



void return_ip(struct client_data* d, int thread_num) {
  int client = d->client_sock;
  // Set socket timeout to 5
  struct timeval tv = {
    .tv_sec = 5
  };
  setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
  char buffer[MAX_BUF_LEN];
  if (get_start_line_and_headers(client, buffer, MAX_BUF_LEN) == false) {
    goto fail;
  }
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
    goto fail;
  };
  unsigned int ip_len = strlen(ip);
  int response_len = snprintf(
      buffer,
      MAX_BUF_LEN,
      "HTTP/1.0 200 OK\r\n"
      "Content-Length: %u\r\n"
      "Content-Type: text/plain\r\n"
      "Connection: close\r\n\r\n"
      "%s\n",
      ip_len + 1,
      ip
  );
  if (send(d->client_sock, buffer, response_len, 0) == -1) {
      perror("send");
  }
  eprintf("%3i: %s\n", thread_num, ip);
fail:
  shutdown(d->client_sock, SHUT_RDWR);
  close(d->client_sock);
}

void* worker_thread(void* data) {
  int sock = ((intptr_t)(data));
  static atomic_int thread_count = 0;
  int thread_num = atomic_fetch_add(&thread_count, 1);
  eprintf("Thread %i starting\n", thread_num);
  struct client_data d;
  socklen_t client_sock_len = sizeof(d.client_addr);
  for (;;) {
    int client =
        accept(sock, (struct sockaddr *)&(d.client_addr), &client_sock_len);
    if (client == -1) {
      // Socket was closed
      if (errno == EBADF || errno == EINVAL) {
        break;
      }
      perror("accept");
      continue;
    }
    d.client_sock = client;
    return_ip(&d, thread_num);
  }
  eprintf("Thread %i stopping\n", thread_num);
  return 0;
}

struct app_context {
  int port;
  int num_threads;
  int sock;
  pthread_t* threads;
} context;

void handle_term(int signo) {
  int num_threads = context.num_threads;
  eprintf("\nStopping server...\n");
  shutdown(context.sock, SHUT_RDWR);
  close(context.sock);
  for (int i = 0; i < num_threads; i++) {
    pthread_join(context.threads[i], NULL);
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
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }
    struct sockaddr_in6 server;
    server.sin6_family = AF_INET6;
    server.sin6_port = htons(port);
    server.sin6_addr = in6addr_any;
    if (bind(sock, (struct sockaddr*)&server, sizeof(server)) == -1) {
      perror("bind");
      exit(EXIT_FAILURE);
    }
    if (listen(sock, 128) < 0) {
      perror("listen");
      exit(EXIT_FAILURE);
    }
    // Block signals in threads (signal masks are inherited)
    sigset_t mask;
    sigfillset(&mask);
    pthread_sigmask(SIG_SETMASK, &mask, NULL);
    // Create threads
    pthread_t threads[num_threads];
    for (int i = 0; i < num_threads; i++) {
      pthread_create(&(threads[i]), NULL, worker_thread,
                     (void *)((intptr_t)sock));
    }
    // Unblock signals
    sigemptyset(&mask);
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
