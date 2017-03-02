/*
 * cucm2csv - Cisco Unified Communications Manager - Dial Plan Export Utility
 * version 1.0, Copyright (c) 2009 by Antoni Sawicki <tenox@tenox.tc>
 *  
 * This utility dumps all Directory Numbers with descriptions into a CSV file
 * Can be used for CDR log analysis or integration with LDAP/Active Directory
 * 
 * Requires mxml library from www.minixml.org and OpenSSL from www.openssl.org
 *    
 */

#include <stdio.h>

#ifdef WIN32
#define snprintf _snprintf

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <mxml.h>


#define DATA_BUFF_SIZE 2048
#define SOAP_BUFF_SIZE 1024
#define AUTH_BUFF_SIZE 128

typedef unsigned char byte;

void encode(char *, char *);
void usage(void);
 
int main(int argc, char **argv) {
    struct sockaddr_in saddr;
    struct hostent *cucmsrv;
    SSL_METHOD *meth;
    SSL_CTX *sslctx;
    SSL *ssl;
    X509* server_cert;
    //char *temp;
    char buffer[DATA_BUFF_SIZE];
    char authstring[AUTH_BUFF_SIZE];
    char soap_buff[SOAP_BUFF_SIZE];
    int err, recv, sock;
  	unsigned int len, read, tot_read;
    char *str;
  	char *bigstr;
  	mxml_node_t *tree;
  	mxml_node_t *node;
#ifdef WIN32
  	WSADATA wsadata;
  	WORD wsaver;
  	DWORD wsaerr;
#endif
    FILE *out;


    if(argc!=5) {
      usage();
      return -1;
    }  

#ifdef WIN32
  	wsaver=MAKEWORD(2,2);
    if(WSAStartup(wsaver, &wsadata)!=0) {
      fprintf(stderr, "WSAStartup error\n");
      return -1;
    }
#endif

    sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

    if(argv[1] && strlen(argv[1])>2) {
      if(isalpha(argv[1][0])) {
        fprintf(stderr, "Host must be in numeric IP address form eg: 10.20.30.40\n\n");
        usage();
        return -1;
      } 
      else {
        saddr.sin_addr.s_addr=inet_addr(argv[1]);
        //printf("num:%s\naddr:%s\n", argv[1], inet_ntoa(saddr.sin_addr));
      }
    } 
    else {
      usage();
      return -1;
    }

    if(argv[2] && strlen(argv[2])>1) {
      if(isdigit(argv[2][0])) {  
        saddr.sin_port=htons(atoi(argv[2]));
      }
      else {
        fprintf(stderr, "port should be a number!\n\n");
        usage();
        return -1;
      }
    } 
    else {
      usage();
      return -1;
    }

    if(sock<0) {
      fprintf(stderr, "create socket failed\n");
      return -1;
    }
 
    saddr.sin_family=AF_INET;
    if(connect(sock,(struct sockaddr *)&saddr,sizeof(saddr))<0) {
      fprintf(stderr, "connect failed\n");
      return -1;
    }

    SSL_library_init();
    SSL_load_error_strings();

    meth=TLSv1_client_method();
    sslctx=SSL_CTX_new(meth);
    if(!sslctx) {
      fprintf(stderr, "SSL_CTX_new failed\n");
      close(sock);
      return -1;
    }

    SSL_CTX_set_verify(sslctx,SSL_VERIFY_NONE,NULL);
    ssl=SSL_new(sslctx);
    if(!ssl) {
      fprintf(stderr, "SSL_new failed\n");
      close(sock);
      return -1;
    }

    if(!SSL_set_fd(ssl,sock)) {
      fprintf(stderr, "SSL_set_fd failed\n");
      close(sock);
      return -1;
    }
  
    SSL_set_mode(ssl,SSL_MODE_AUTO_RETRY);
    if(SSL_get_error(ssl,SSL_connect(ssl))!=SSL_ERROR_NONE) {
        fprintf(stderr, "SSL connection failed\n");
        return -1;
    }
    
    if(!SSL_get_peer_certificate (ssl)) {
		fprintf(stderr, "get server certificate failed!\n");
		goto cleanup;
    }

    if(argv[3] && strlen(argv[3])>4 && strchr(argv[3], ':')) {
      encode(argv[3], authstring);
    } else {
      fprintf(stderr, "username and password are in wrong format, should be: \"user:pass\"\n\n");
      usage();
      return -1;
    }
    
    snprintf(soap_buff, SOAP_BUFF_SIZE,
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
              "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " 
              "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"> "
          "<SOAP-ENV:Body> "    
            "<axlapi:executeSQLQuery sequence=\"1\" " 
                  "xmlns:axlapi=\"http://www.cisco.com/AXL/API/1.0\" " 
                  "xmlns:axl=\"http://www.cisco.com/AXL/API/1.0\" "
                  "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " 
                  "xsi:schemaLocation=\"http://www.cisco.com/AXL/API/1.0 axlsoap.xsd\"> "
                  "<sql>select numplan.dnorpattern, numplan.description, typepatternusage.name as type "
                        "from numplan, typepatternusage where numplan.tkpatternusage=typepatternusage.enum</sql>"
            "</axlapi:executeSQLQuery> "
          "</SOAP-ENV:Body> "
        "</SOAP-ENV:Envelope>"
    );


    snprintf(buffer, DATA_BUFF_SIZE,
        "POST /axl/ HTTP/1.1\r\n" 
        "Host: %s:%s\r\n"
        "Accept: text/*\r\n"
        "Authorization: Basic %s\r\n"
        "Content-type: text/xml\r\n"
        "SOAPAction: \"CUCM:DB ver=6.0\"\r\n"
        "Content-length: %d\r\n"
        "Connection: close\r\n"
        "\r\n%s\r\n\r\n",
        argv[1], argv[2], authstring, strlen(soap_buff), soap_buff
    );

         
    SSL_write(ssl,buffer,strlen(buffer));
    memset(buffer, 0, DATA_BUFF_SIZE);

    read=SSL_read(ssl,buffer,DATA_BUFF_SIZE);
  	if(!read) {
  		fprintf(stderr, "unable to read ssl data\n");
  		goto cleanup;
  	}
    buffer[read]='\0';
    
  	if(strlen(buffer)>15 && strncmp(buffer, "HTTP/1.1 200 OK", 15)!=0) {
  		fprintf(stderr, "protocol error (http code not 200 OK)\n%s\n", buffer);
  		goto cleanup;
  	}

  	str=strstr(buffer, "Content-Length: ");
  	if(!str) {
  		fprintf(stderr, "no content length specified\n%s\n", buffer);
  		goto cleanup;
  	}

  	bigstr=strchr(str, ' ');
  	if(!bigstr) {
  		fprintf(stderr, "no content length specified\n%s\n", buffer);
  		goto cleanup;
  	}

  	if(sscanf(bigstr, " %d\r\n", &len)!=1) {
  		fprintf(stderr, "wrong content length specified (1)\n%s\n", buffer);
  		goto cleanup;
  	}

  	str=strstr(buffer, "\r\n\r\n");
  	if(!str) {
  		fprintf(stderr, "protocol error (header end)\n%s\n", buffer);
  		goto cleanup;
  	}
  
  	if(len<strlen(str) || len>1024*1024*100) {
  		fprintf(stderr, "wrong content length specified (2)\n%s\n", buffer);
  		goto cleanup;
  	}
  
  	bigstr=malloc(len+(DATA_BUFF_SIZE*4));
  	if(!bigstr) {
  		fprintf(stderr, "unable to allocte memory for specified content length\n");
  		goto cleanup;
  	}
    memset(bigstr,0,len+(DATA_BUFF_SIZE*4));

	//printf("%d\n", len);
	snprintf(bigstr, len, "<?xml version=\"1.0\"?>\n%s", str);

	tot_read=strlen(bigstr);
	
	while(read=SSL_read(ssl,bigstr+tot_read,DATA_BUFF_SIZE)) {
		tot_read=tot_read+read;
		//printf("%d \t| %d\n", read, tot_read);
		if(tot_read>=len+DATA_BUFF_SIZE) {
			fprintf(stderr, "more data than buffer size\n");
			goto cleanup;
		}
	}

	//fprintf(stderr, "%s\n", bigstr);

	tree=mxmlLoadString(NULL, bigstr, MXML_OPAQUE_CALLBACK);
	if(tree==NULL) {
		fprintf(stderr, "unable to parse xml\n");
		goto cleanup;
	}

  out=fopen(argv[4], "w");
  if(!out) {
    fprintf(stderr, "unable to open %s\n", argv[4]);
    goto cleanup;
  }

  fprintf(out, "Number,Description,Type\n");

	for(node=mxmlFindElement(tree, tree, "dnorpattern", NULL, NULL, MXML_DESCEND);
		node!=NULL;
		node=mxmlFindElement(node, tree, "dnorpattern", NULL, NULL, MXML_DESCEND)) {

		if(node->type==MXML_ELEMENT && node->child && node->child->type==MXML_OPAQUE && node->child->value.opaque)
			fprintf(out, "%s,", node->child->value.opaque);

		while(node->next) {
      node=node->next;
      if(node->type==MXML_ELEMENT && node->child && node->child->type==MXML_OPAQUE && node->child->value.opaque ) 
			   fprintf(out, "%s", node->child->value.opaque);      

      fputc(',', out);
		}

		fputc('\n', out);

	}
	
	fclose(out);

cleanup:
    SSL_shutdown(ssl);
    close(sock);

    return 0;
}

void encode(char *inbuf, char *outbuf) {
    unsigned int i,j,k;
    int hiteof=0;
    byte dtable[256]; 

    for(i= 0;i<9;i++) {
       dtable[i]= 'A'+i;
       dtable[i+9]= 'J'+i;
       dtable[26+i]= 'a'+i;
       dtable[26+i+9]= 'j'+i;
    }
    
    for(i= 0;i<8;i++) {
       dtable[i+18]= 'S'+i;
       dtable[26+i+18]= 's'+i;
    }
    
    for(i= 0;i<10;i++) {
       dtable[52+i]= '0'+i;
    }
    
    dtable[62]= '+';
    dtable[63]= '/';
    j=0;
    k=0;
    
    while(!hiteof) {
       byte igroup[3],ogroup[4];
       int c,n;
       igroup[0]= igroup[1]= igroup[2]= 0;
       for(n=0; n<3; n++) {
          if(j < strlen(inbuf)) {
             c=inbuf[j++];
          } else {
             hiteof=1;
             break;
          }
          igroup[n]= (byte)c;
       }
       if(n>0) {
          ogroup[0]= dtable[igroup[0]>>2];
          ogroup[1]= dtable[((igroup[0]&3)<<4)|(igroup[1]>>4)];
          ogroup[2]= dtable[((igroup[1]&0xF)<<2)|(igroup[2]>>6)];
          ogroup[3]= dtable[igroup[2]&0x3F];
          if(n<3) {
             ogroup[3]= '=';
             if(n<2) {
                ogroup[2]= '=';
             }
          }
          for(i= 0;i<4;i++) 
            if(k<AUTH_BUFF_SIZE)
              outbuf[k++] = ogroup[i];
       }
    }
    outbuf[k++]=0;
}

void usage(void) {
  printf("cucm2csv - Cisco Unified Communications Manager - Dial Plan Export Utility\n");
  printf("version 1.0, Copyright (c) 2009 by Antoni Sawicki <tenox@tenox.tc>\n\n");
  printf("This utility dumps all Directory Numbers with descriptions into a CSV file\n");
  printf("Can be used for CDR log analysis or integration with LDAP/Active Directory\n\n");
  printf("Usage:\n");
  printf("        cucm2csv <cucm-server> <port> <username:password> <file.csv>\n\n");
  printf("Example:\n");
  printf("        cucm2csv 10.1.2.3 8443 axluser:axlpass numplan.csv\n\n");
  printf("AXL Username is created under User Management -> Application User\n");
  printf("The user has to have \"Standard AXL API Access\" right enabled\n");
}
