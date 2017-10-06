
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>

#include <memory.h>
#include <stdint.h>
#include <assert.h>
#include <pthread.h>
#include <time.h>
#include <sys/times.h>
#include <sys/sendfile.h>
#include <sys/stat.h>

#include <resolv.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/modes.h>
#include <openssl/aes.h>

#include <sched.h>


#define PRINT_E
#define PRINT_I
#define PRINT_V

#ifdef PRINT_E
#define PRINTE printf
#else
#define PRINTE(format, args...) ((void)0)
#endif

#ifdef PRINT_I
#define PRINTI printf
#else
#define PRINTI(format, args...) ((void)0)
#endif

#ifdef PRINT_V
#define PRINTV printf
#else
#define PRINTV(format, args...) ((void)0)
#endif

#define MAXEVENTS 1000

#define SENDFILE_LIMIT 1000000000
#define MAX_CONN     10000

#define HTTP_MODE         0
#define KTLS_MODE         1
#define OPENSSL_MODE      2

#define KTLS_SET_IV_RECV                1
#define KTLS_SET_KEY_RECV               2
#define KTLS_SET_SALT_RECV              3
#define KTLS_SET_IV_SEND                4
#define KTLS_SET_KEY_SEND               5
#define KTLS_SET_SALT_SEND              6
#define KTLS_SET_MTU                    7
#define KTLS_UNATTACH                   8
#define KTLS_VERSION_1_2                1
#define AF_KTLS         12
#define KTLS_CIPHER_AES_GCM_128         51

/* AF_ALG defines not in linux headers */
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN 4
#endif
#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE 5
#endif
#ifndef ALG_SET_PUBKEY
#define ALG_SET_PUBKEY 6
#endif

struct sockaddr_ktls {
        unsigned short   sa_cipher;
        unsigned short   sa_socket;
        unsigned short   sa_version;
};

/* Opaque OpenSSL structures to fetch keys */
#define u64 uint64_t
#define u32 uint32_t
#define u8 uint8_t

typedef struct {
  u64 hi, lo;
} u128;

typedef struct {
  /* Following 6 names follow names in GCM specification */
  union {
    u64 u[2];
    u32 d[4];
    u8 c[16];
    size_t t[16 / sizeof(size_t)];
  } Yi, EKi, EK0, len, Xi, H;
  /*
   * Relative position of Xi, H and pre-computed Htable is used in some
   * assembler modules, i.e. don't change the order!
   */
#if TABLE_BITS==8
  u128 Htable[256];
#else
  u128 Htable[16];
  void (*gmult) (u64 Xi[2], const u128 Htable[16]);
  void (*ghash) (u64 Xi[2], const u128 Htable[16], const u8 *inp,
                 size_t len);
#endif
  unsigned int mres, ares;
  block128_f block;
  void *key;
} gcm128_context_alias;

typedef struct {
  union {
    double align;
    AES_KEY ks;
  } ks;                       /* AES key schedule to use */
  int key_set;                /* Set if key initialised */
  int iv_set;                 /* Set if an iv is set */
  gcm128_context_alias gcm;
  unsigned char *iv;          /* Temporary IV store */
  int ivlen;                  /* IV length */
  int taglen;
  int iv_gen;                 /* It is OK to generate IVs */
  int tls_aad_len;            /* TLS AAD length */
  ctr128_f ctr;
} EVP_AES_GCM_CTX;


typedef struct {
    int sfd;
    int ktls_sfd;
    SSL *ssl;
    int nRequests;
    ssize_t file_offset;
    int active;
} Connection;

int http_mode;
int efd;
SSL_CTX *ctx; //per server
Connection *connArray;
int http_response(Connection *conn, char *file);

static const char* http_resp_header="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1000000\r\n\r\n";
int setnonblocking( int fd )
{
    int old_option = fcntl( fd, F_GETFL );
    int new_option = old_option | O_NONBLOCK;
    fcntl( fd, F_SETFL, new_option );
    return old_option;
}

void addfd( int epollfd, Connection *conn, int fd )
{
    struct epoll_event event;
    event.data.ptr = conn;
    event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    //event.events = EPOLLIN | EPOLLET;
    epoll_ctl( epollfd, EPOLL_CTL_ADD, fd, &event );
}

void removefd( int epollfd, int fd )
{
    epoll_ctl( epollfd, EPOLL_CTL_DEL, fd, 0 );
}

void modfd( int epollfd, Connection * conn, int fd, int ev )
{
    struct epoll_event event;
    event.data.ptr = conn;
    event.events = ev | EPOLLET  | EPOLLRDHUP | EPOLLERR;
    epoll_ctl( epollfd, EPOLL_CTL_MOD, fd, &event );
}

int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr; 
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    int enable = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        abort();
    }
    if ( bind(sd, (const struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    return sd;
}

SSL_CTX* InitServerCTX(void)
{
  SSL_CTX *ctx;
  ctx = SSL_CTX_new(SSLv23_server_method());/* create new context from method */
  if ( ctx == NULL )
  {
      ERR_print_errors_fp(stderr);
      abort();
  }
  return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
  /* set the local certificate from CertFile */
  if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
  /* set the private key from KeyFile (may be the same as CertFile) */
  if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
  /* verify private key */
  if ( !SSL_CTX_check_private_key(ctx) )
    {
      fprintf(stderr, "Private key does not match the public certificate\n");
      abort();
    }
}

int setup_ktls_socket(int sfd, SSL* ssl)
{
    /* Kernel TLS tests */
    int ktls_socket = socket(AF_KTLS, SOCK_STREAM, 0);
    if (ktls_socket == -1) {
        perror("socket error:");
        exit(-1);
    }
    struct sockaddr_ktls sa = {
                .sa_cipher = KTLS_CIPHER_AES_GCM_128,
                .sa_socket = sfd,
                .sa_version = KTLS_VERSION_1_2,
    };
    
    if (bind(ktls_socket, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("AF_KTSL: bind failed");
        close(ktls_socket);
        exit(-1);
    }
    
    EVP_CIPHER_CTX * writeCtx = ssl->enc_write_ctx;
    EVP_CIPHER_CTX * readCtx = ssl->enc_read_ctx;
    EVP_AES_GCM_CTX* gcmWrite = (EVP_AES_GCM_CTX*)(writeCtx->cipher_data);
    EVP_AES_GCM_CTX* gcmRead = (EVP_AES_GCM_CTX*)(readCtx->cipher_data);
    
    unsigned char* writeKey = (unsigned char*)(gcmWrite->gcm.key);
    unsigned char* readKey = (unsigned char*)(gcmRead->gcm.key);
    
    unsigned char* writeIV = gcmWrite->iv;
    unsigned char* readIV = gcmRead->iv;
    
    char keyiv[20] = {0};
    memcpy(keyiv, writeKey, 16);
    if (setsockopt(ktls_socket, AF_KTLS, KTLS_SET_KEY_SEND, keyiv, 16)) {
        perror("AF_ALG: set write key failed\n");
        exit(-1);
    }
    
    memcpy(keyiv, writeIV, 4);
    if (setsockopt(ktls_socket, AF_KTLS, KTLS_SET_SALT_SEND, keyiv, 4)) {
        perror("AF_ALG: set write iv failed\n");
        exit(-1);
    }

  uint64_t writeSeq;
  unsigned char* writeSeqNum = ssl->s3->write_sequence;
  memcpy(&writeSeq, writeSeqNum, sizeof(writeSeq));
  if (setsockopt(ktls_socket, AF_KTLS, KTLS_SET_IV_SEND, (unsigned char*)&writeSeq, 8)) {
    perror("AF_ALG: set write salt failed\n");
    exit(-1);
  }


  memcpy(keyiv, readKey, 16);
  if (setsockopt(ktls_socket, AF_KTLS, KTLS_SET_KEY_RECV, keyiv, 16)) {
    perror("AF_ALG: set read key failed\n");
    exit(-1);
  }
  memcpy(keyiv, readIV, 4);
  if (setsockopt(ktls_socket, AF_KTLS, KTLS_SET_SALT_RECV, keyiv, 4)) {
    perror("AF_ALG: set read iv failed\n");
    exit(-1);
  }

  uint64_t readSeq;
  unsigned char* readSeqNum = ssl->s3->read_sequence;
  memcpy(&readSeq, readSeqNum, sizeof(readSeq));
  if (setsockopt(ktls_socket, AF_KTLS, KTLS_SET_IV_RECV, (unsigned char*)&readSeq, 8)) {
    perror("AF_ALG: set read salt failed\n");
    exit(-1);
  }
  return ktls_socket;
}

int TLShandshake(Connection *conn)
{
  conn->ssl = SSL_new(ctx);         /* get new SSL state with context */
  SSL_set_fd(conn->ssl, conn->sfd);/* set connection socket to SSL state */

  if ( SSL_accept(conn->ssl) == -1 ) {
      printf("SSL_accept error\n");
      return -1;
  }

  if(http_mode == KTLS_MODE) {
      conn->ktls_sfd = setup_ktls_socket(conn->sfd, conn->ssl);
      PRINTI("ktls socket setup done: ktls socket %d <-> TCP socket %d\n\n", conn->ktls_sfd, conn->sfd);
  }
  return 0;
}

void closeConn(Connection *conn)
{
    if(http_mode == KTLS_MODE) {
        removefd(efd, conn->ktls_sfd);
        SSL_free(conn->ssl);
        close(conn->ktls_sfd);
    }
    else if(http_mode == OPENSSL_MODE) {
        removefd(efd, conn->sfd);
        SSL_free(conn->ssl);
    }
    else {
        removefd(efd, conn->sfd);
    }
    close (conn->sfd);
    conn->active = 0;
    conn->file_offset = 0;
}

Connection * getFreeConn(void)
{
    for(int i = 1; i < MAX_CONN + 1; i++) {
        if( connArray[i].active == 0) {
            connArray[i].active = 1;
            return &connArray[i];
        }
    }
    return NULL;
}

void set_cpu_affinity(void) {
    cpu_set_t  mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    //CPU_SET(2, &mask);
    if(sched_setaffinity(0, sizeof(mask), &mask) < 0)
        perror("sched_setaffinity");
}


int filefd;
struct stat statBuf;
int filesize;

int main (int argc, char *argv[])
{
  int s;
  struct epoll_event *events;
  int port;
  char *filename;
  char *cipher;

  if (argc != 5)
  {
      fprintf (stderr, "Usage: %s [port] [HTTP|KTLS|SSL  0|1|2] cipher file\n", argv[0]);
      exit (EXIT_FAILURE);
  }

  port = atoi(argv[1]);
  http_mode = atoi(argv[2]);
  cipher = argv[3];
  filename = argv[4];
  
  //set_cpu_affinity();

  if(http_mode != HTTP_MODE) {
      SSL_library_init();
      OpenSSL_add_all_algorithms();
      ERR_load_BIO_strings();
      ERR_load_crypto_strings();
      SSL_load_error_strings();/* load all error messages */
      
      ctx = InitServerCTX();/* initialize SSL */
      LoadCertificates(ctx, "ca.crt", "ca.pem");/* load certs */
      
      SSL_CTX_set_cipher_list(ctx, cipher);
      
      //Nginx can only use this, why?
      //SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256");
      //KTLS code use this
      //SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");
  }

  connArray = (Connection *)malloc((MAX_CONN + 1) * sizeof(Connection)); 
  bzero(connArray, (MAX_CONN + 1) * sizeof(Connection));
 
  connArray[0].sfd = OpenListener(port);
  if (connArray[0].sfd == -1)
    abort ();
  
  setnonblocking(connArray[0].sfd );

  s = listen(connArray[0].sfd, SOMAXCONN);
  if (s == -1) {
      perror ("listen");
      abort ();
  }

  efd = epoll_create (1000);
  if (efd == -1)
  {
      perror ("epoll_create");
      abort ();
  }
  
  addfd( efd, &connArray[0], connArray[0].sfd);

  /* Buffer where events are returned */
  events = calloc(MAXEVENTS, sizeof(struct epoll_event));
  
  filefd = open(filename, O_RDONLY);
  fstat(filefd, &statBuf);
  filesize = statBuf.st_size;
  
  /* The event loop */
  while (1)
  {
      int n, i;

      n = epoll_wait(efd, events, MAXEVENTS, -1);
      for (i = 0; i < n; i++)
      {
          Connection *conn = events[i].data.ptr;
          if (events[i].events & EPOLLERR)
          {
              perror("EPOLLERR");
              closeConn(conn);
              continue;
          }
          if (events[i].events & EPOLLHUP)
          {
              perror("EPOLLHUP");
              closeConn(conn);
              continue;
          }
          if (events[i].events & EPOLLRDHUP)
          {
              perror("EPOLLRDHUP");
              closeConn(conn);
              continue;
          }
          else if (connArray[0].sfd == conn->sfd) // Read on listen sfd
          {
              PRINTV("\n#epoll event: TCP accept\n");
              while (1)
              {
                  struct sockaddr in_addr;
                  socklen_t in_len;
                  int infd;
                  char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

                  in_len = sizeof(in_addr);
                  infd = accept(conn[0].sfd, &in_addr, &in_len);
                  if (infd == -1)
                  {
                      if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
                      {
                          /* We have processed all incoming connections. */
                          break;
                      }
                      else
                      {
                          perror ("accept");
                          break;
                      }
                  }

                  Connection * conn = getFreeConn();
                  conn->sfd = infd;

                  s = getnameinfo (&in_addr, in_len, hbuf, sizeof hbuf, sbuf, sizeof sbuf, NI_NUMERICHOST | NI_NUMERICSERV);
                  if (s == 0)
                  {
                      PRINTI("Accepted connection on descriptor %d (host=%s, port=%s)\n", infd, hbuf, sbuf);
                  }

                  if(http_mode == KTLS_MODE) {
                      TLShandshake(conn);
                      setnonblocking( conn->ktls_sfd );
                      addfd(efd, conn, conn->ktls_sfd );
                  }
                  else if (http_mode == OPENSSL_MODE) {
                      TLShandshake(conn);
                      setnonblocking( conn->sfd );
                      addfd(efd, conn, conn->sfd );
                  }
                  else {
                      setnonblocking( conn->sfd );
                      addfd(efd, conn, conn->sfd );
                  }
              }
              continue;
          }
          else if (events[i].events & EPOLLOUT) // write
          {
              PRINTV("\n#epoll event: write\n");
              int ret;
              if(http_mode == OPENSSL_MODE) {
                  ret = ssl_http_response(conn, filename); /* 0-Again, 1-Done, -1-Error */
              }
              else {
                  ret = http_response(conn, filename); /* 0-Again, 1-Done, -1-Error */
              }


              if(ret == -1) {
                  //error
                  perror("send - sendfile:");
                  closeConn(conn);
              }
              else if(ret == 0) {
                  //continue on next epoll
                  if(http_mode == KTLS_MODE) {
                      //modfd( efd, conn, conn->ktls_sfd, EPOLLOUT );
                  }
                  else {
                      //modfd( efd, conn, conn->sfd, EPOLLOUT );
                  }
              }
              else { 
                  // done
                  if(http_mode == KTLS_MODE) {
                      modfd( efd, conn, conn->ktls_sfd, EPOLLIN );
                  }
                  else {
                      modfd( efd, conn, conn->sfd, EPOLLIN );
                  }
              }
          }
          else if (events[i].events & EPOLLIN) // read
          {
              PRINTV("\n#epoll event: read\n");
              int done = 0;
              ssize_t total = 0;
              while (1)
              {
                  ssize_t count;
                  char buf[2048];

                  if(http_mode == OPENSSL_MODE) {
                      count = SSL_read(conn->ssl, buf, sizeof(buf));
                  }
                  else if (http_mode == KTLS_MODE) {
                      count = recv (conn->ktls_sfd, buf, sizeof(buf), 0);
                  }
                  else {
                      count = recv (conn->sfd, buf, sizeof(buf), 0);
                  }
                  
                  PRINTV("      read %ld\n", count);
                  
                  if (count == -1)
                  {
                      if (errno != EAGAIN)
                      {
                          perror ("Why error not EAGAIN");
                          done = 1;
                      }
                      else {
                          PRINTV("      read return EAGAIN, total %d\n", total);
                          if(!total) {
                              perror ("Why read nothing:");
                              break;
                          }
                      }
                      
                      if(total)
                          done = 1;

                      break;
                  }
                  else if (count == 0)
                  {
                      /* End of file. The remote has closed the connection. */
                      PRINTE("read return 0, for https, just return to epoll write????\n");
                      //closeConn(conn);
                      break;
                  }
                  else
                  {
                      total += count;
                  }

                  //printf("%s\n", buf);
              }

              if (done)
              {
                  if(http_mode == KTLS_MODE) {
                      modfd( efd, conn, conn->ktls_sfd, EPOLLOUT );
                  }
                  else {
                      modfd( efd, conn, conn->sfd, EPOLLOUT );
                  }
              }
          }
          else
          {
              PRINTE("ERROR unknow event\n");
          }
      }
  }

  free(events);
  close(connArray[0].sfd);
  close(efd);
  free(connArray);
  close(filefd);
  if(http_mode != HTTP_MODE)
      SSL_CTX_free(ctx);

  return EXIT_SUCCESS;
}

#define SSL_LIMIT 16384
char buf[SSL_LIMIT];
int ssl_http_response(Connection * conn, char *file)
{
    int sfd;
    off_t offset = 0;
    ssize_t sent;
    size_t toSent;
    ssize_t remain;
    int ret;
    ssize_t bytes;
    int ssl_done;
    int hasSent, toSend;

    PRINTV("ssl send start, file offset is %d\n", conn->file_offset);

    
    if (conn->file_offset == 0) {
        ret = SSL_write(conn->ssl, http_resp_header, strlen(http_resp_header));
        if (ret < strlen(http_resp_header)) {
            PRINTE("error, to do later\n");
        }
        else {
            PRINTV("Send header done\n");
        }

    }
    
    lseek(filefd, conn->file_offset, SEEK_SET);
    do {
         ssl_done = 0;
         bytes = read(filefd, buf, sizeof(buf));
         if (bytes > 0) {
             hasSent = 0;
             toSend = bytes;
             remain = toSend;

             while(1) {
                 ret = SSL_write(conn->ssl, buf + hasSent, toSend);
                 if(ret > 0) {
                     hasSent += ret;
                     toSend -= ret;
                     PRINTV("SSL write return %d, total sent %d\n", ret, hasSent);
                     if (toSend == 0) {
                         PRINTV("SSL write done\n");
                         ssl_done = 1;
                         break;
                     }
                 }
                 else {
                     PRINTI("SSL write return %d\n", ret);
                     break;
                 }
             }
         }
         else if (bytes == 0) {
             PRINTI("End of File\n");
             ssl_done = 1;
             conn->file_offset = 0;
             break;
         }
         else {
             perror("Read file:");
             return -1;
         }
         
         conn->file_offset += hasSent; 
     } while(bytes > 0 && ssl_done);

    if(ssl_done)
        return 1;
    else
        return 0;

}

int http_response(Connection * conn, char *file)
{
  int sfd;
  off_t offset = 0;
  ssize_t sent;
  size_t toSent;
  ssize_t remain;
  int ret;

  if(http_mode == KTLS_MODE)
      sfd = conn->ktls_sfd;
  else
      sfd = conn->sfd;
  
  if (conn->file_offset == 0) {
      sent = send(sfd, http_resp_header, strlen(http_resp_header), 0);
      if(sent < strlen(http_resp_header)) {
          perror("send http header error");
          return -1;
      }
      PRINTV("send http header OK\n");
  }
  
  offset = conn->file_offset;
  remain = filesize - offset;
  while(remain > 0) {
      toSent =  remain > SENDFILE_LIMIT ? SENDFILE_LIMIT: remain;
      PRINTV("      Sendfile start from offset %d, to send %d\n", offset, toSent);
      sent = sendfile(sfd, filefd, &offset, toSent);
      if(sent == 0) {
          perror("      Sendfile 0:");
          conn->file_offset = filesize - remain;
          PRINTV("      Sendfile remain %ld\n", remain);
          ret = 0;
          break;
      }
      else if(sent < 0) {
          perror("      Sendfile -1:");
          conn->file_offset = filesize - remain;
          PRINTV("      Sendfile remain %ld\n", remain);
          ret = 0;
          break;
      }
      else {
          remain -= sent;
          PRINTV("      Sendfile has sent bytes %ld, remain %ld, total file size %d\n", sent, remain, filesize);
          if(remain == 0) {
              PRINTI("Sendfile done, total file size %d\n", filesize);
              ret = 1; //Done with Senfile
              conn->file_offset = 0;
          }
      }
  }
  return ret;
}



