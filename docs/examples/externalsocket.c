/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/*
 * This is an example demonstrating how an application can pass in a custom
 * socket to libcurl to use. This example also handles the connect itself.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
//#include <connect.h>
//#include <sockaddr.h>
//#include <curl_addrinfo.h>


#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#else
#include <sys/types.h>        /*  socket types              */
#include <sys/socket.h>       /*  socket definitions        */
#include <netinet/in.h>
#include <arpa/inet.h>        /*  inet (3) funtions         */
#include <unistd.h>           /*  misc. UNIX functions      */
#endif

#include <errno.h>

#include <libserval/serval.h>
#include <netinet/serval.h>

/* The IP address and port number to connect to */
#define IPADDR "127.0.0.1"
#define PORTNUM 80

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif


struct Curl_sockaddr_storage {
 union {
    struct sockaddr sa;
    struct sockaddr_in sa_in;
#ifdef ENABLE_IPV6
    struct sockaddr_in6 sa_in6;
#endif
    struct sockaddr_sv sa_sv;
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
    struct sockaddr_storage sa_stor;
#else
    char cbuf[256];   /* this should be big enough to fit a lot */
#endif
  } buffer;
};


struct Curl_sockaddr_ex {
  int family;
  int socktype;
  int protocol;
  unsigned int addrlen;
  union {
    struct sockaddr addr;
    struct sockaddr_sv addr_sv;
    struct Curl_sockaddr_storage buff;
  } _sa_ex_u;
};
#define sa_addr _sa_ex_u.addr
#define sa_addr_sv _sa_ex_u.addr_sv


static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
  int written = fwrite(ptr, size, nmemb, (FILE *)stream);
  printf("In write_data.\n");
  return written;
}

static curl_socket_t opensocket(void *clientp,
                                curlsocktype purpose,
                                struct curl_sockaddr *address)
{
  curl_socket_t sockfd;
  struct Curl_sockaddr_ex *saddr;
  struct service_id server_srvid;

  printf("In opensocket.\n");

  saddr = (struct Curl_sockaddr_ex *)address;

  saddr->family = AF_SERVAL;
  saddr->socktype = SOCK_STREAM;
  
  //server_srvid.s_sid32[0] = htonl(12345);
  //printf("IP in opensock: %d\n", saddr->sa_addr_sv.sv_srvid.s_sid32[0]);
  memset(&saddr->sa_addr_sv, 0, sizeof(saddr->sa_addr_sv));
  //  saddr->sa_addr_sv.sv_srvid.s_sid32[0] = htonl(16385);
  strcpy(saddr->sa_addr_sv.sv_srvid.s_sid, "www.princeton.edu");
  saddr->sa_addr_sv.sv_family = AF_SERVAL;
  //printf("sid: %d\n", saddr->sa_addr_sv.sv_srvid.s_sid32[0]);
  printf("sid: %d\n", saddr->sa_addr_sv.sv_srvid.s_sid);
  printf("sv_family: %d\n", saddr->sa_addr_sv.sv_family);
  //memcpy(&saddr->sa_addr_sv.sv_srvid, &server_srvid, sizeof(server_srvid));
  saddr->addrlen = sizeof(saddr->sa_addr_sv);
  printf("saddr->addrlen: %d\n", saddr->addrlen);

  (void)purpose;
  (void)address;
  sockfd = *(curl_socket_t *)clientp;
  /* the actual externally set socket is passed in via the OPENSOCKETDATA
     option */
  return sockfd;
}

static int sockopt_callback(void *clientp, curl_socket_t curlfd,
                            curlsocktype purpose)
{
  (void)clientp;
  (void)curlfd;
  (void)purpose;
  /* This return code was added in libcurl 7.21.5 */
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

int main(void)
{
  CURL *curl;
  CURLcode res;
  struct sockaddr_in servaddr;  /*  socket address structure  */
  curl_socket_t sockfd;
  curl_socket_t sock;

#ifdef WIN32
  WSADATA wsaData;
  int initwsa;

  if((initwsa = WSAStartup(MAKEWORD(2,0), &wsaData)) != 0) {
    printf("WSAStartup failed: %d\n", initwsa);
    return 1;
  }
#endif

  curl = curl_easy_init();
  if(curl) {
    /*
     * Note that libcurl will internally think that you connect to the host
     * and port that you specify in the URL option.
     */
    curl_easy_setopt(curl, CURLOPT_URL, "www.princeton.edu");

    if ( (sock = socket(AF_SERVAL, SOCK_STREAM, 0)) == CURL_SOCKET_BAD) {
      printf("Error creating SERVAL socket.\n");
      return 3;
    }

    /* Create the socket "manually" */
    if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) == CURL_SOCKET_BAD ) {
      printf("Error creating listening socket.\n");
      return 3;
    }

    //    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    //    servaddr.sin_port   = htons(PORTNUM);

    //    if (INADDR_NONE == (servaddr.sin_addr.s_addr = inet_addr(IPADDR)))
    // return 2;
    /*
    if(connect(sockfd,(struct sockaddr *) &servaddr, sizeof(servaddr)) ==
       -1) {
      close(sockfd);
      printf("client error: connect: %s\n", strerror(errno));
      return 1;
    }
    */

    /* no progress meter please */
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

    /* call this function to get a socket */
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, opensocket);
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &sock);

    /* call this function to set options for the socket */
    //    curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_callback);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);

    if(res) {
      printf("libcurl error: %d\n", res);
      return 4;
    }
  }
  return 0;
}
