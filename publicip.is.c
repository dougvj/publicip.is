#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>

struct client_data {
  int client_sock;
  struct sockaddr_in6 client_addr;
};

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
      fprintf(stderr, "recv: Unexpected socket close\n");
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
      fprintf(stderr, "recv: Buffer Full\n");
      return false;
    }
  }
}



void return_ip(struct client_data* d) {
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
  fprintf(stderr, "%s\n", ip);
fail:
  shutdown(d->client_sock, SHUT_RDWR);
  close(d->client_sock);
  free(d);
}

int main(int argc, char** argv) {
    int port;
    if (argc != 2) {
      fprintf(stderr, "Usage:\n\t%s <port>\n", argv[0]);
      exit(EXIT_FAILURE);
    } else {
      port = atoi(argv[1]);
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
    listen(sock, 5);
    fprintf(stderr, "Waiting for clients on port %u\n", port);
    //TODO switch to epoll in a thread pool to see if that's faster
    for(;;) {
        struct client_data* d = malloc(sizeof(struct client_data));
        socklen_t client_sock_len = sizeof(d->client_addr);
        int client = accept(
            sock,
            (struct sockaddr*)&(d->client_addr),
            &client_sock_len
        );
        d->client_sock = client;
        pthread_t one_off;
        pthread_create(&one_off, NULL, (void*(*)(void*))return_ip, d);
        pthread_detach(one_off);
    }
}
