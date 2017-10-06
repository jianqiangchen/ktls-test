#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

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

char request[100];
SSL_CTX *ctx;
int bHTTPS;
char *cipher;
const char *ip;
int port;
int nThread, nConnections, nRequests;
char *filename;
int filesize;

typedef struct {
    int sockfd;
    SSL *ssl;
    int nRequests;
    int response_size;
} Connection;

void* main_http_client(void *arg); 
int setnonblocking(int fd);
void addfd(int epoll_fd, Connection *conn);
bool write_nbytes(Connection * conn, const char* buffer, int len);
int https_read( Connection *conn, char* buffer, int len );
int http_read( Connection *conn, char* buffer, int len );
int TLS_handshake(SSL_CTX *ctx, Connection *con);
void start_conn( int epoll_fd, Connection *connArray, int num, const char* ip, int port );
void close_conn( int epoll_fd, Connection * con );
SSL_CTX* init_https(const char * cypher_list);


int main( int argc, char* argv[] )
{
    pthread_t *client_thread;

    if( argc != 10 ) {
        printf("Usage: ./%s [HTTPS 0/1] cipher ip port filename filesize nThread nConnections nRequests\n", basename(argv[0]));
        return 0;
    }
    
    bHTTPS = atoi(argv[1]);
    cipher = argv[2];
    ip = argv[3];
    port = atoi(argv[4]);
    filename = argv[5];
    filesize = atoi(argv[6]);
    nThread = atoi(argv[7]);
    nConnections = atoi(argv[8]);
    nRequests = atoi(argv[9]);

    sprintf(request, "GET /%s HTTP/1.1\r\n\Host: %s\r\nConnection: keep-alive\r\n\r\n", filename, ip);

    if(bHTTPS) {
        //ctx = init_https("ECDH-ECDSA-AES128-GCM-SHA256"); //used for original code
        //ctx = init_https("ECDHE-RSA-AES128-GCM-SHA256"); //ued for nginx
        ctx = init_https(cipher);
        if(ctx == NULL) {
            printf("error to create openSSL CTX\n");
            return -1;
        }
    }
    

    client_thread = (pthread_t *)malloc(nThread * sizeof(pthread_t));
    for(int i=0; i<nThread; i++) {
        int rc = pthread_create(&client_thread[i], NULL, main_http_client, (void *)&port);
        if (rc) {
            printf("Error creating server %i\n", rc);
            exit(-1);
        }
    }
    
    for(int i=0; i<nThread; i++) {
        pthread_join(client_thread[i], NULL);
    }

    free(client_thread);
    if(bHTTPS) {
        SSL_CTX_free(ctx);
    }
    return 0;
}


char buffer[16384];
void* main_http_client(void *arg) 
{
    int activeConn;
    int epoll_fd;
    epoll_event events[10000];
    
    Connection *connArray = (Connection *)malloc(nConnections * sizeof(Connection));
    bzero(connArray, nConnections * sizeof(Connection));
    for(int i = 0; i < nConnections; i++) {
        connArray[i].nRequests = nRequests;
    }

    epoll_fd = epoll_create(100);
    start_conn(epoll_fd, connArray, nConnections, ip, port);
    
    activeConn = nConnections;
    clock_t start = clock();
    long read_byte = 0;
    while ( activeConn )
    {
        //PRINTV("epoll wait\n");
        int fds = epoll_wait( epoll_fd, events, 10000, 2000 );
        //int fds = epoll_wait( epoll_fd, events, 10000, 0 );
        //PRINTV("epoll wait return %d\n", fds);

        for ( int i = 0; i < fds; i++ )
        {   
            Connection *conn = (Connection *)events[i].data.ptr;
            if ( events[i].events & EPOLLIN )  // read
            {
                PRINTV("READ Event \n");
                int size;
                if(bHTTPS) {
                    size = https_read( conn, buffer, sizeof(buffer));
                    //PRINTV("https_read return %d\n", size);
                }
                else {
                    size = http_read( conn, buffer, sizeof(buffer));
                    //PRINTV("http_read return %d\n", size);
                }
                if(size > 0) {
                    conn->response_size += size;
                    if(conn->response_size >= filesize) {
                    //if(conn->response_size == filesize + 256) {
                        read_byte += conn->response_size;
                        PRINTI( "finish one request, read total %d bytes for a request from socket %d\n", conn->response_size, conn->sockfd );
                        
                        conn->response_size = 0;
                        conn->nRequests--;
                        if (conn->nRequests <= 0) {
                            PRINTI("finish one connection\n");
                            close_conn( epoll_fd, conn );
                            activeConn--;
                            continue;
                        }
                        struct epoll_event event;
                        event.events = EPOLLOUT | EPOLLET | EPOLLERR;
                        event.data.ptr = conn;
                        epoll_ctl( epoll_fd, EPOLL_CTL_MOD, conn->sockfd, &event );
                        continue;
                    }
                    else {
                        //struct epoll_event event;
                        //event.events = EPOLLIN | EPOLLET | EPOLLERR;
                        //event.data.ptr = conn;
                        //epoll_ctl( epoll_fd, EPOLL_CTL_MOD, conn->sockfd, &event );
                        PRINTV("not finish for a request, wait on next epoll read again\n");
                        continue;
                    }
                }
                else if(size == 0) {
                    PRINTV("read nothing? why? run epoll again\n");
                    continue;
                }
                else {
                    PRINTE("read error? why\n");
                    continue;
                }
            }
            else if( events[i].events & EPOLLOUT ) //write
            {
                PRINTV("**************\nWRITE EVENT: to send request %d\n", conn->nRequests);
                if (conn->nRequests <= 0) {
                    printf("close connection\n");
                    close_conn( epoll_fd, conn );
                    activeConn--;
                }
                else {
                    if ( !write_nbytes( conn, request, strlen( request ) ) )
                    {
                        PRINTE("write error\n");
                        close_conn( epoll_fd, conn );
                    }
                    else {
                        struct epoll_event event;
                        event.events = EPOLLIN | EPOLLET | EPOLLERR;
                        event.data.ptr = conn;
                        epoll_ctl( epoll_fd, EPOLL_CTL_MOD, conn->sockfd, &event );
                    }
                }
            }
            else if( events[i].events & EPOLLERR )
            {
                perror("EPOLL ERR: ");
                //close_conn( epoll_fd, conn );
            }
            else
            {
                perror("EPOLL ERR: ");
            }
        }
    }
            
    clock_t end = clock();
    double bandwidth = (((double)read_byte) * 8)/(end -start);
    printf("time total(us): %ld, total data: %ld, bandwith(Mbps) : %f\n", end - start, read_byte, bandwidth);

    close(epoll_fd);
    free(connArray);

    return NULL;
}


int setnonblocking(int fd)
{
    int old_option = fcntl(fd, F_GETFL);
    int new_option = old_option | O_NONBLOCK;
    fcntl(fd, F_SETFL, new_option);
    return old_option;
}

void addfd(int epoll_fd, Connection *conn)
{
    epoll_event event;
    event.data.ptr = conn;
    event.events = EPOLLOUT | EPOLLET | EPOLLERR;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->sockfd, &event);
    setnonblocking(conn->sockfd);
}

bool write_nbytes(Connection * conn, const char* buffer, int len)
{
    int bytes_write = 0;
    while( 1 ) 
    {   
        if(bHTTPS) {
            bytes_write = SSL_write( conn->ssl, buffer, len);
        }
        else {
            bytes_write = send( conn->sockfd, buffer, len, 0 );
        }
        PRINTV( "write out %d bytes to socket %d\n", bytes_write, conn->sockfd );

        if ( bytes_write == -1 )
        {   
            return false;
        }   
        else if ( bytes_write == 0 ) 
        {   
            return false;
        }   

        len -= bytes_write;
        buffer = buffer + bytes_write;
        if ( len <= 0 ) 
        {   
            return true;
        }   
    }   
}

int https_read( Connection *conn, char* buffer, int len )
{
    int ret, err;
    int size = 0;
    
    do {
        memset(buffer, '\0', len);
        ret = SSL_read(conn->ssl, buffer, len);
        if (ret <= 0) {
            err = SSL_get_error(conn->ssl, ret);
            if(err == SSL_ERROR_WANT_READ) {
                if(size == 0) {
                    PRINTV( "               read return %d, total zero in a epoll from socket %d, wait epoll again\n", ret, conn->sockfd );
                }
                else {
                    PRINTI( "               read return %d, total %d in a epoll from socket %d, wait epoll again\n", ret, size, conn->sockfd );
                }
                return size;
            }
            else {
                PRINTV( "               read return %d, read ERROR - err code %d, retuen size recived so far %d\n", err, size);
                return size;  //Jason retrurn -1?
            }
        }
        else {
            size += ret;
            PRINTV( "       read in a SSL_read for %d bytes from socket %d\n", ret, conn->sockfd );
        }
    } while(1);
}
	

int http_read( Connection *conn, char* buffer, int len )
{
    int ret = 0;
    int size = 0;
    
    do {
        memset(buffer, '\0', len);
        ret = recv(conn->sockfd, buffer, len, 0);
        if ( ret <= 0 )
        {
            PRINTV( "       recv return %d\n", ret);
            if (errno == EAGAIN) {
                PRINTV( "                   read total %d bytes in a epoll from socket %d\n", size, conn->sockfd );
            }
            else {
                PRINTE("                    unkonw error\n");
            }
            return size;
        }
        else {
            size += ret;
            PRINTV( "       recv %d bytes in a recv call from socket %d\n", ret, conn->sockfd );
        }
    } while (1);
}

int TLS_handshake(SSL_CTX *ctx, Connection *con)
{
    con->ssl = SSL_new(ctx);
    SSL_set_fd(con->ssl, con->sockfd);
    if(SSL_connect(con->ssl) != 1)
    {
        printf("Error: SSL handshake fail\n");
        SSL_free(con->ssl);
        close(con->sockfd);
        return -1;
    }
    return 0;
}


void start_conn( int epoll_fd, Connection *connArray, int num, const char* ip, int port )
{
    struct sockaddr_in address;
    bzero( &address, sizeof( address ) );
    address.sin_family = AF_INET;
    inet_pton( AF_INET, ip, &address.sin_addr );
    address.sin_port = htons( port );

    for ( int i = 0; i < num; ++i )
    {
        //sleep( 1 );
        connArray[i].sockfd = socket(PF_INET, SOCK_STREAM, 0);
        if( connArray[i].sockfd < 0 )
        {
            printf( "create sock failure for connection %d\n", i);
            continue;
        }

        if (connect(connArray[i].sockfd, (struct sockaddr *)&address, sizeof(address)) == 0)
        {
            if(bHTTPS) {
                if( TLS_handshake(ctx, &connArray[i]) == -1 ) {
                    continue;
                }
            }
            addfd( epoll_fd, &connArray[i] );
        }
        else {
            printf("connetion %d connect fail\n", i);
            if(bHTTPS) {
                SSL_free(connArray[i].ssl);
            }
            close(connArray[i].sockfd);
        }

    }
}

void close_conn( int epoll_fd, Connection * con )
{
    SSL_free(con->ssl);
    epoll_ctl( epoll_fd, EPOLL_CTL_DEL, con->sockfd, 0 );
    close( con->sockfd );
}

SSL_CTX* init_https(const char * cypher_list)
{
    SSL_CTX *ctx;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();/* load all error messages */ 
    
    ctx = SSL_CTX_new(SSLv23_client_method());
    if(ctx == NULL) {
        printf("Unable to create a new SSL context structure.\n");
        return NULL;
    }
    
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_cipher_list(ctx, cypher_list);
    return ctx;
}



