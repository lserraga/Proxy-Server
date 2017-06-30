#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/in.h>
#include <time.h>
#define MAXLINE 4096
#define SA struct sockaddr
#define maxThreads 100
#define LISTENQ 1024


//Definition of boolean value
typedef int bool;
enum {
   false,
   true
};

//Erro function
void error(char * msg) {
   perror(msg);
   exit(0);
}

//function that counts lines in a txt file
int countLines(FILE * fp) {

   int lines = 0;
   char ch;

   while (!feof(fp)) {
      ch = fgetc(fp);
      if (ch == '\n') {
         lines++;
      }
   }
   rewind(fp);
   return lines;
}

//Duction that returns the size of the headers in an HTTP message
int sizeHeaders(char * message) {
   char forwardHeader[100];
   int where = 0;

   char * aux = malloc(strlen(message) + 1);
   strcpy(aux, message);
   char * ptr = strtok(aux, "\n"); //parse at new line

   while (ptr) { //while token was found
      //Blank line
      if (strlen(ptr) == 1) {
         break;
      }
      where = where + strlen(ptr) + 1;
      bzero(ptr, strlen(ptr));
      ptr = strtok(NULL, "\n");
   }
   return where;
}

//Function that adds a Forwarded header to a http request
void addForwardHeader(char * clientaddress, char * serevraddres, char * message) {
   char forwardHeader[100];
   int where = 0;

   sprintf(forwardHeader, "Forwarded: for=%s; proto=http; by=%s\r\n\r\n", clientaddress, serevraddres);
   char * aux = malloc(strlen(message) + 1);
   strcpy(aux, message);
   char * ptr = strtok(aux, "\n"); //parse at new line

   while (ptr) { //while token was found
      //Blank line
      if (strlen(ptr) == 1) {
         break;
      }
      where = where + strlen(ptr) + 1;
      bzero(ptr, strlen(ptr));
      ptr = strtok(NULL, "\n");
   }

   message[where] = '\0';
   strcat(message, forwardHeader);
}

//Function that sends a 400 bad request response to the socket provided
void sendInvalidRequest(char * t3, int connfd) {
   char * message;
   strcpy(message, t3);
   strcat(message, " 400 Bad request\nConnection: Closed\nContent-Type: text/html; charset=UTF-8\r\n\r\n <h1>INVALID REQUEST</h1>");
   //printf("Sending the client %i bytes: \n%s\n",send(connfd, message, strlen(message), 0),message);
   send(connfd, message, strlen(message), 0);
}

//Function that returns in result the value of the headerTitle in a http request
//Returns true if the header is in the request and false if it isn't
bool checkHeaderValue(char * message, char * headerTitle, char * result) {
   char * aux = malloc(strlen(message) + 1);
   strcpy(aux, message);
   char * ptr = strtok(aux, "\n"); //parse at new line

   char aux2[50];

   while (ptr) { //while token was found
      //Blank line so we finished checking headers
      if (strlen(ptr) == 1) {
         break;
      }
      if (strncmp(ptr, headerTitle, strlen(headerTitle)) == 0) {
         sscanf(ptr, "%s %s", aux2, result);
         char * ptr2 = strtok(result, ";");
         result[strlen(ptr2)] = '\0';
         return true;
      }
      bzero(ptr, strlen(ptr));
      ptr = strtok(NULL, "\n");
   }

   return false;
}

//Function that logs a request
void logRequest(char * type, char * requestedObject, char * proto, char * responseCode, char * clientIP, char * responseSize) {
   FILE * fp = fopen("access.log", "a+");
   if (fp == NULL)
      error("Error with the log txt file\n");
   time_t t = time(NULL);

   char log[300];

   //Getting the time 
   struct tm tm = * localtime( & t);
   sprintf(log, "Date: %d-%d-%dT%d:%d:%d ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
   strcat(log, clientIP);
   strcat(log, " \"");
   strcat(log, type);
   strcat(log, " ");
   strcat(log, requestedObject);
   strcat(log, " ");
   strcat(log, proto);
   strcat(log, "\" ");
   strcat(log, responseCode);
   strcat(log, " ");
   strcat(log, responseSize);
   strcat(log, " Bytes\n\0");
   //printf("TO log: %s\n",log);
   fprintf(fp, "%s", log);
   fclose(fp);
}

//Not  used!
void removeLine(char * message) {
   int i, max, newlinePosition;
   char * aux = malloc(strlen(message));
   strcpy(aux, message);

   for (i = 0; i < strlen(message);)
      i++;
   newlinePosition = i;
   max = strlen(message) - newlinePosition;
   for (i = 0; i < max; i++) {
      message[i] = aux[newlinePosition];
      newlinePosition++;
   }
   message[newlinePosition + 1] = '\0';
}

// Function that modifies a webName so it's in the correct format for getaddrsinfo() 
//It is also used when checking if a web is banned
void setCleanName(char * webNameRaw) {
   int i, lengthx;
   char * ptr = strtok(webNameRaw, "/"); //parse at new line
   char * ptr2;

   while (ptr) { //while token was found
      if (strncmp(ptr, "www", 3) == 0) {
         break;
      }
      ptr = strtok(NULL, "/");
   }

   char * aux = malloc(strlen(ptr));
   strcpy(aux, ptr);
   ptr2 = strtok(aux, ":");
   bzero(webNameRaw, strlen(webNameRaw));
   for (i = 0; i < strlen(ptr2); i++)
      webNameRaw[i] = ptr[i];
   webNameRaw[i] = '\0';
}

//Function that returns whether a webname is within the a list of blocked websites
bool isBanned(char * * bannedSites, char * hostNameRaw, int numberWebsBanned) {
   int i;
   //struct hostent *host1=gethostbyname(webSite);

   //cleaning host name
   setCleanName(hostNameRaw);

   if (!hostNameRaw)
      return false;
   for (i = 0; i < numberWebsBanned; i++) {
      if (strcmp(bannedSites[i], hostNameRaw) == 0) {
         printf("%s is banned\n", hostNameRaw);
         return true;
      }
   }
   return false;
}

//Function that gets a list of blocked websites from a filename
//It returns the numbers of sites in the list 
int getBannedNames(char * * banned, char * fileName) {
   //Loading the banned websites
   FILE * bannedWebs = fopen(fileName, "r");
   int i;

   if (bannedWebs == NULL) {
      printf("Error opening %s\n", fileName);
      exit(1);
   }
   int nfiles = countLines(bannedWebs);
   for (i = 0; i < nfiles; ++i) {
      banned[i] = malloc(300); /* allocate a memory slot of 128 chars */
      fscanf(bannedWebs, "%1299s", banned[i]);
      printf("Banned web number %i: %s\n", i, banned[i]);
   }
   printf("\n\n");
   return nfiles;
}

//Function that creates a simple HTTP request modifying the one received from the browser
//STRANGE ERROR: I created this function because in my linux virtual machine I got strange encoding
//errors when just sending the request from the browser (in the lab  pcs it worked fine so im not using
//this function)
void createHTTPrequest(char * message, char * request) {
   char t1[300], t2[300], t3[10];
   char * temp = NULL;
   int flag = 0, i, port = 0;
   sscanf(message, "%s %s %s", t1, t2, t3);
   strcpy(t1, t2);

   flag = 0;

   for (i = 7; i < strlen(t2); i++) {
      if (t2[i] == ':') {
         flag = 1;
         break;
      }
   }

   temp = strtok(t2, "//");
   if (flag == 0) {
      port = 80;
      temp = strtok(NULL, "/");
   } else {
      temp = strtok(NULL, ":");
   }

   sprintf(t2, "%s", temp);
   //printf("host = %s", t2);
   if (flag == 1) {
      temp = strtok(NULL, "/");
      port = atoi(temp);
   }

   strcat(t1, "^]");
   temp = strtok(t1, "//");
   temp = strtok(NULL, "/");
   if (temp != NULL)
      temp = strtok(NULL, "^]");
   //printf("\npath = %s\nPort = %d\n", temp, port);

   bzero((char * ) request, sizeof(request));
   if (temp != NULL)
      sprintf(request, "GET /%s %s\r\nHost: %s\r\nConnection: close\r\n\r\n", temp, t3, t2);
   else
      sprintf(request, "GET / %s\r\nHost: %s\r\nConnection: close\r\n\r\n", t3, t2);
}

int
main(int argc, char * * argv) {
   int listenfd, connfd;
   pid_t pid;
   char * banned[100];
   struct sockaddr_in servaddr, cli_addr, proxy_addr;
   int numberWebsBanned;
   int clilen = sizeof(cli_addr);
   int proxylen = sizeof(proxy_addr);
   int sizePacket;

   if (argc != 3) {
      printf("usage: <Port> <Forbiden-Sites-File>\n");
      exit(1);
   }

   //Creation of the TCP socket
   listenfd = socket(AF_INET, SOCK_STREAM, 0);
   if (listenfd < 0)
      error("Error initializing socket (socket())\n");
   bzero( & servaddr, sizeof(servaddr));
   servaddr.sin_family = AF_INET;
   servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
   servaddr.sin_port = htons(atoi(argv[1]));
   //Servers port is binded to the socket

   if (bind(listenfd, (SA * ) & servaddr, sizeof(servaddr)) < 0)
      error("Error binding socket (bind())\n");
   //Socket converted into a listening socket that will accept incoming connections
   //ListenQ defines the maximum number of connection s in line

   if (listen(listenfd, LISTENQ) < 0)
      error("Error on listening");

   printf("**** Proxy server up and running**** \n\nCreated by Luis Serra Garcia\n");
   printf("Network Programmin-University of California, Santa Cruz\n\n\n");
   //Getting the names of the blocked webPages
   numberWebsBanned = getBannedNames(banned, argv[2]);

   for (;;) {
      accepting:

      //Accepting the connection request from the browser
         connfd = accept(listenfd, (SA * ) & cli_addr, & clilen);
      if (connfd < 0) {
         printf("Error accepting connection\n");
         continue;
      }

      //Getting the proxy addres for the logging 
      char serevraddres[INET_ADDRSTRLEN];
      getsockname(connfd, (SA * ) & proxy_addr, & proxylen);
      inet_ntop(AF_INET, & (proxy_addr), serevraddres, INET_ADDRSTRLEN);

      //Creation of the subprocesses that handle the requestsfrom the browser
      pid = fork();
      if (pid == 0) {
         char bufferx[MAXLINE + 1];
         char buffer[MAXLINE + 1];
         char t1[300], t2copy[300], t2[300], t3[10];
         char client_command[MAXLINE + 1];

         bzero(client_command, strlen(client_command));

         //Reading teh request from the browser
         if (recv(connfd, client_command, MAXLINE, 0) <= 0)
            goto closing;
         printf("Received from browser \n%s\n", client_command);
         sscanf(client_command, "%s %s %s", t1, t2, t3);
         strcpy(t2copy, t2);

         //Setting the address of the remote server to which the proxy has to connect
         struct addrinfo hints;
         struct addrinfo * result, * rp;
         int sfd;
         bzero(buffer, MAXLINE + 1);

         //If the request is different from GET or HEAD, the proxy sends a 405 response and logs the request
         if (strcmp(t1, "GET") != 0 && strcmp(t1, "HEAD") != 0) {
            strcpy(buffer, t3);
            strcat(buffer, " 405 Method not allowed\nConnection: Closed\nContent-Type: text/html; charset=UTF-8\r\n\r\n<h1>This proxy only work with HEAD and GET requests</h1>");
            //printf("Sending the client %i bytes: \n%s\n",send(connfd, buffer, strlen(buffer), 0),buffer);
            printf("Method error\n");
            send(connfd, buffer, strlen(buffer), 0);
            logRequest(t1, t2copy, t3, "405", "", "0");
            goto closing;
         }

         //If the request is for a website that is banned, the proxy sends a 403 response and logs the request
         if (isBanned(banned, t2, numberWebsBanned)) {
            strcpy(buffer, t3);
            strcat(buffer, " 403 Forbiden URL\nConnection: Closed\nContent-Type: text/html; charset=UTF-8\r\n\r\n<h1> This site is banned, go do your work and don't procastinate!</h1>");
            //printf("Sending the client %i bytes: \n%s\n",send(connfd, buffer, strlen(buffer), 0),buffer);
            send(connfd, buffer, strlen(buffer), 0);
            logRequest(t1, t2copy, t3, "403", "", "0");
            goto closing;
         }

         //Getting the host name from the http message headers
         char hostName[200];
         checkHeaderValue(client_command, "Host", hostName);

         printf("Type: %s \nProtocol: %s \nWeb: %s\nHostName: %s\n\n", t1, t3, t2, hostName);

         //Starting the process of connecting to the remote server
         memset( & hints, 0, sizeof(struct addrinfo));
         hints.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
         hints.ai_socktype = SOCK_STREAM;

         //If the getaddrinfo() functions fails it logs the request and it send an invalid request message to the browser
         if (getaddrinfo(hostName, "http", & hints, & result) != 0) {
            printf("getaddrinfo() failed\n");
            sendInvalidRequest(t3, connfd);
            logRequest(t1, t2copy, t3, "400", "", "0");
            goto closing;
         }

         /* getaddrinfo() returns a list of address structures.
         Try each address until we successfully bind(2).
         If socket(2) (or bind(2)) fails, we (close the socket
         and) try the next address. */

         for (rp = result; rp != NULL; rp = rp->ai_next) {
            sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sfd == -1)
               continue;

            if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == -1) {
               printf("Connect error\n");
               close(sfd);
               continue;
            }
            break; // if we get here, we must have connected successfully
         }

         //Geting the ip address of the client in a string format 
         char clientaddress[INET_ADDRSTRLEN];
         inet_ntop(AF_INET, & (rp->ai_addr), clientaddress, INET_ADDRSTRLEN);

         //If rp is null it means that it couldnt connect to the remote server
         //It logs the request and it send an invalid request message to the browser
         if (rp == NULL) {
            printf("Could not bind to the desired server\n");
            sendInvalidRequest(t3, connfd);
            logRequest(t1, t2copy, t3, "400", "", "0");
            goto closing;
         }

         freeaddrinfo(result); // No longer needed

         //printf("Client IP: %s \nProxy IP:%s\n",clientaddress,serevraddres);
         addForwardHeader(clientaddress, serevraddres, client_command);

         //printf("Sending to %s:\n%s\n",t2,client_command);

         bzero((char * ) bufferx, sizeof(bufferx));
         createHTTPrequest(client_command, bufferx);
         addForwardHeader(clientaddress, serevraddres, bufferx);
         printf("Sending to %s:\n%s\n", t2, bufferx);
         send(sfd, bufferx, strlen(bufferx), 0);

         int n, naux = 0;

         //Receiving the first part of the server response that will include the headers
         n = recv(sfd, buffer, MAXLINE, 0);
         //printf("Received: %s\n",buffer);
         char t22[300], t33[10];
         sscanf(buffer, "%s %s", t33, t22);
         char headerValue[200];
         bzero(headerValue, 200);
         //We check if the server response includes the content length header
         checkHeaderValue(buffer, "Content-Length", headerValue);

         //If the length of the headerValue is 0 means that the response didn't include a content-length header
         //Sending everything that the remote server sends
         if (strlen(headerValue) == 0) {
            send(connfd, buffer, strlen(buffer), 0);
            bzero(buffer, strlen(buffer));
            while (naux = recv(sfd, buffer, MAXLINE, 0) > 0) {
               printf("Received: %s\n", buffer);
               send(connfd, buffer, MAXLINE, 0);
               bzero(buffer, MAXLINE + 1);
               n = n + naux;
            }
            char auxSize[300];
            sprintf(auxSize, "%i", n);
            //logging the request with the size of it
            printf("Sent a total of %i to the browser\n", n);
            logRequest(t1, t2, t3, t22, clientaddress, auxSize);
         }

         //In this case the proxy will have the size of the http response so it can make sure that it sends everything
         else {
            //The size of the packet is the content-length header plus the size of the headers
            sizePacket = atoi(headerValue) + sizeHeaders(buffer);
            // printf("Checking Content-Length header: %s\nTotal size of the packet: %i\n",headerValue,sizePacket);

            //Logging the rquest with the size of it
            logRequest(t1, t2, t3, t22, clientaddress, headerValue);

            //printf("%s\n",buffer);

            send(connfd, buffer, n, 0);
            bzero(buffer, strlen(buffer));
            while (n < sizePacket) {
               naux = recv(sfd, buffer, MAXLINE, 0);
               printf("%s\n", buffer);
               send(connfd, buffer, MAXLINE, 0);
               bzero(buffer, MAXLINE + 1);
               n = n + naux;
            }

            printf("Sent a total of %i to the browser\n", n);
         }
         closing:
            bzero(client_command, MAXLINE + 1);
         close(connfd);
         close(sfd); //It is done by the remote server so is not needec
         //Terminating the child
         exit(0);
      } else {
         //Parent
         close(connfd);
      }
   }
   close(listenfd);
}