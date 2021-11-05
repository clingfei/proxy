/*
   The firewall framework is used to show the foundmental principle the proxy firwwall works, the undergraduates can do some experiments based on the framework, we hope you like these experiments.

   The framework is proposed by Information Security School at Shanghai Jiaotong Univ. If you have any question during the experiments, please send mail to the author, zixiaochao@sjtu.edu.cn, asking for the techinical supports.
 
   Thank you all.
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "base64.h"

#define REMOTE_SERVER_PORT 80			
#define BUF_SIZE 4096*4 				
#define QUEUE_SIZE 100

struct parameter {
    int accept_sockfd;
    struct sockaddr_in cl_addr;
};

struct iprules {
    char allowed_ip[20];
    char username[20];
    char passwd[256];
    int sign;               //check whether authorization is needed.
    int num;
    struct iprules * next;
};

struct hostRules {
    char host[256];
    int num;
    struct hostRules *next;
};

struct ctRules {
    char text[512];
    int num ;
    struct ctRules *next;
};

pthread_mutex_t conp_mutex;
pthread_mutex_t iprules_mutex;
pthread_mutex_t hostrules_mutex;
pthread_mutex_t ctrules_mutex;

char lastservername[256] = "";
int lastserverip = 0;

struct iprules *iphead, *iprear;
struct hostRules *hostHead, *hostRear;
struct ctRules *ctHead, *ctRear;

int checkserver(char *hostname){
	/*please add some statments here to accomplish Experiemnt 4! 
	The experiment's mission is to check the ip addr of the server, 
	and block the connection to the server you don't wish to access.*/

	/*A simple example is shown here, you can follow it to accomplish Experiment 4. 
	If you let the client access the server , please return 1, otherwise return -1 */
	
    char *blocked_server = "127.0.0.1:8888";
    struct hostRules *p = hostHead->next;
    while (p != NULL) {
        if (strstr(hostname, p->host) != NULL) {
            printf("the server has been blocked.\n");
            return -1;
        }
        p = p->next;
    }
    printf("checkserver passed.\n");
	/*
		#define BLOCKED_SERVER "bbs.sjtu.edu.cn"

		if (strstr(hostname, BLOCKED_SERVER) != NULL) {
			printf("Destination blocked! \n");
			return -1;
		}
	*/
	return 1;

}

int checkclient(in_addr_t cli_ipaddr) {

	/*please add some statments here to accomplish Experiemnt 3! 
	The experiment's mission is to check the ip addr of the cliens, 
	and block the connection from these clients you don't provide the proxy service.*/

	/*A simple example is shown here, you can follow it to accomplish Experiment 3. 
	If you want to provide the proxy server to the clients, please return 1, otherwise return -1 */

	//ALLOWED should be read from a text file, then use a loop to check whether the ip is allowed.
	printf("client ip address check start.\n");
	//struct iprules *head = (struct iprules *)malloc(sizeof(struct iprules));
	//head->next = (struct iprules *)malloc(sizeof(struct iprules));
	//strcpy(head->next->allowed_ip, "127.0.0.1");
    struct iprules *p = (struct iprules *)malloc(sizeof (struct iprules));
    pthread_mutex_lock(&iprules_mutex);
    p = iphead->next;
    while (p != NULL) {
        int allowedip;
        inet_pton(AF_INET, p->allowed_ip, &allowedip);
        if (allowedip == cli_ipaddr) {
            printf("ip address check passed\n");
            pthread_mutex_unlock(&iprules_mutex);
            return 1;
        }
        else p = p->next;
    }
    pthread_mutex_unlock(&iprules_mutex);
    //printf("%u, %s\n", strlen(iphead->next->allowed_ip), iphead->next->allowed_ip);
    //printf("%u, %s\n", strlen(iprear->allowed_ip), iphead->next->allowed_ip);
    //char ALLOWED_CLIENTIP[20] = "127.0.0.1";
    //printf("%u\n", strlen(ALLOWED_CLIENTIP));
    /*
    char ALLOWED_CLIENTIP[20] = "127.0.0.1";
    int allowedip;
    inet_pton(AF_INET, ALLOWED_CLIENTIP, &allowedip);
    if (allowedip != cli_ipaddr) {
        printf("Client IP authentication failed !\n ");
        return -1;
    }
    return 1;*/
    //printf("Client IP authentication failed !\n ");
    return -1;

}


void print_clientinfo(struct sockaddr_in cli_addr)
{
	/*please add some statments here to accomplish the Experiemnt 2! 
	The experiment's mission is to print the ip addr and port of client making proxy request.*/

	/*
	 * struct sockaddr_in {
	 *      short      sin_family;    // 2 bytes e.g. AF_INET, AF_INET6
     *      unsigned short  sin_port;  // 2 bytes e.g. htons(3490)
     *      struct in_addr  sin_addr;   // 4 bytes see struct in_addr, below
     *      char       sin_zero[8];   // 8 bytes zero this if you want to
     *  };
	 */
	char ip_addr[20];
	printf("Received a new request!\n");   //if the output statement disturbs the experiments, please delete it.

    char * ptr = inet_ntop(cli_addr.sin_family, &cli_addr.sin_addr, ip_addr, sizeof(ip_addr));
    if (ptr == NULL) {
        printf("failed to convert\n");
        exit(-1);
    }
    printf("client port: %d, client addr: %s\n", ntohs(cli_addr.sin_port), ip_addr);
	return;
}

void print_severinfo(struct sockaddr_in server_addr)
{
	//please add some statments here to accomplish the Experiemnt 2! The mission is to print the ip addr and port of the remote web server.
    char ip_addr[20];

    char * ptr = inet_ntop(server_addr.sin_family, &server_addr.sin_addr, ip_addr, sizeof(ip_addr));
    if (ptr == NULL) {
        printf("failed to convert\n");
        exit(-1);
    }
    printf("server port: %d, server addr: %s\n", ntohs(server_addr.sin_port), ip_addr);

	return;
}

int checkuser(struct sockaddr_in cl_addr, char * authorization, int flag) {             //flag 用于判断客户连接时是否有Authorization
    //check whether the user and passwd is suit for ip
    //char ALLOWED_CLIENTIP[20] = "127.0.0.1";
    //char *allowed_user = "bo", *allowed_passwd = "1234";
    pthread_mutex_lock(&iprules_mutex);
    struct iprules *p = iphead->next;
    while(p != NULL) {
        int allowedip;
        inet_pton(AF_INET, p->allowed_ip, &allowedip);

        if (cl_addr.sin_addr.s_addr == allowedip) {
            if (p->sign == 0 ) {
                pthread_mutex_unlock(&iprules_mutex);
                return 0;
            }
            if (flag == -1) {
                pthread_mutex_unlock(&iprules_mutex);
                return -1;
            }

            char *const end = b64decode(authorization);
            printf("authotization: %s\n", authorization);
            int outputlen = end - authorization;
            char res[outputlen + 1];
            strncpy(res, authorization, outputlen);
            printf("%s\n", res);

            char username[outputlen];
            char passwd[outputlen];
            int i = 0, j = 0;
            for (i = 0, j = 0; i < outputlen && res[i] != ':'; ++i, ++j) {
                username[j] = res[i];
            }
            username[j] = '\0';
            for (j = 0, i = i + 1; i < outputlen && res[i] != '\0'; ++i, ++j) {
                passwd[j] = res[i];
            }
            passwd[j] = '\0';
            printf("username: %s, \t passwd: %s\n", username, passwd);


            if (!strcmp(username, p->username) && !strcmp(passwd, p->passwd)) {
                pthread_mutex_unlock(&iprules_mutex);
                return 0;
            }
            else  {
                pthread_mutex_unlock(&iprules_mutex);
                return -1;
            }
        }
        p = p->next;
    }
    pthread_mutex_unlock(&iprules_mutex);
    return -1;
}

int checkcontent(char *buf, int buflen) {
    struct ctRules *p = ctHead->next;
    while (p != NULL) {
        if (strstr(buf, p->text) != NULL) {
            printf("the content has been blocked.\n");
            return -1;
        }
        p = p->next;
    }
    return 0;
}

void dealonereq(void *arg)
{
	int bytes;
	char buf[BUF_SIZE]; 											// buffer for incoming file
	char recvbuf[BUF_SIZE],hostname[256];
	char authorization[8192];
	int remotesocket;
	struct parameter *para;
	para = (struct parameter *)arg;
	int accept_sockfd = (int)para->accept_sockfd;               //accept_sockfd is the socket of client
	pthread_detach(pthread_self());
	//
	bzero(buf,BUF_SIZE);
	bzero(recvbuf,BUF_SIZE);

	bytes = read(accept_sockfd, buf, BUF_SIZE); 	// read a buffer from socket
	if (bytes <= 0) {	        //bytes <= 0, client send finished, close socket
		close(accept_sockfd);
		return; 
	}

	getHostName(buf,hostname,bytes);
	if (sizeof(hostname) == 0) {
		printf("Invalid host name");
		close(accept_sockfd);
		return;
	}

	if (checkserver(hostname) != 1){
	    printf("The host %s has been blocked.\n", hostname);
		close(accept_sockfd);
		return; 
	}

	remotesocket = connectserver(hostname);
	if (remotesocket == -1){
		close(accept_sockfd);
		return; 
	}

	int flag = getUserInfo(buf, authorization, bytes);

	if (checkuser(para->cl_addr, authorization, flag) == -1) {
	    printf("user check failed\n");
	    close(accept_sockfd);
	    return;
	}

    printf("buffer from client: %s\n", buf);
	send(remotesocket, buf, bytes,MSG_NOSIGNAL);
	while(1) {
		int readSizeOnce = 0;
		readSizeOnce = read(remotesocket, recvbuf, BUF_SIZE);				//get response from server.

		if (readSizeOnce <= 0) {
			break;
		}
        if (checkcontent(recvbuf, BUF_SIZE) != -1 ) {
            send(accept_sockfd, recvbuf, readSizeOnce,MSG_NOSIGNAL);
        }
	}
	close(remotesocket);
	close(accept_sockfd);
}

void loadrules() {
    iphead = (struct iprules *)malloc(sizeof(struct iprules));
    iprear = iphead;
    FILE *fp = fopen("rules/ip", "rw");
    if (fp == NULL) {
        printf("Open files failed.\n");
        exit(-1);
    }
    int num = 0;
    char ip[256];
    while (fscanf(fp, "%s", ip) != EOF) {
        /*
        iprear->next = (struct iprules*)malloc(sizeof (struct iprules));;
        iprear = iprear->next;
        strcpy(iprear->allowed_ip, ip);
        //printf("%s\n", iprear->allowed_ip);
        */
        num++;
        char *p1, *p2;
        p1 = strstr(ip, ",");
        p2 = strstr(ip, ":");
        iprear->next = (struct iprules*)malloc(sizeof (struct iprules));
        iprear = iprear->next;
        if (p1 != NULL) {
            strncpy(iprear->allowed_ip, ip, p1 - ip);
            strncpy(iprear->username, ip + (p1 - ip) + 1, p2 - p1 - 1);
            strncpy(iprear->passwd, ip + (p2 - ip) + 1, strlen(ip) - (p2 - ip));
            iprear->sign = 1;
        }
        else {
            strcpy(iprear->allowed_ip, ip);
            iprear->sign = 0;
        }
        printf("%s %s %s\n", iprear->allowed_ip, iprear->username, iprear->passwd);
    }
    iprear->next = NULL;
    iphead->num = num;
    fclose(fp);

    num = 0;
    hostHead = (struct hostRules *)malloc(sizeof(struct hostRules));
    hostRear = hostHead;
    fp = fopen("rules/hostname", "rw");
    if (fp == NULL) {
        printf("Open hostname file failed.\n");
        exit(-1);
    }
    char hostname[256];
    while (fscanf(fp, "%s", hostname) != EOF) {
        num++;
        hostRear->next = (struct hostRules*)malloc(sizeof(struct hostRules));
        hostRear = hostRear->next;
        strcpy(hostRear->host, hostname);
    }
    hostRear->next = NULL;
    hostHead->num = num;
    fclose(fp);

    num = 0;
    ctHead = (struct ctRules *)malloc(sizeof(struct ctRules));
    ctRear = ctHead;
    fp = fopen("rules/content", "rw");
    if (fp == NULL) {
        printf("Open content files failed.\n");
        exit(-1);
    }
    char content[512];
    while (fgets(content, 512, fp) != NULL) {
        num++;
        printf("%s\n", content);
        ctRear->next = (struct ctRules *) malloc(sizeof(struct ctRules));
        ctRear = ctRear->next;
        strncpy(ctRear->text, content, strlen(content) - 1);
    }
    ctRear->next = NULL;
    ctHead->num = num;
    fclose(fp);
}

void list(char *target) {
    if (strstr(target, "IP") || strstr(target, "ip") || strstr(target, "Ip") || strstr(target, "iP")) {
        struct iprules *p = iphead->next;
        int seq = 0;
        printf("SEQ \t\t\t IP \t\t\t USERNAME \t\t\t PASSWORD\n");
        while (p != NULL) {
            if (p->sign == 1)
                printf("%d \t\t\t %s \t\t %s \t\t\t\t %s\n", ++seq, p->allowed_ip, p->username, p->passwd);
            else
                printf("%d \t\t\t %s \t\t\n", ++seq, p->allowed_ip);
            p = p->next;

        }
    }
    else if (strstr(target, "HOST") || strstr(target, "Host") || strstr(target, "host")) {
        struct hostRules *p = hostHead->next;
        int seq = 0;
        printf("SEQ \t\t\t\t\t HOSTNAME\n");
        while (p != NULL) {
            printf("%d \t\t\t\t\t %s\n", ++seq, p->host);
            p = p->next;
        }
    }
    else if (strstr(target, "Content") || strstr(target, "CONTENT")) {
        struct ctRules *p = ctHead->next;
        int seq = 0;
        printf("SEQ \t\t\t\t Content\n");
        while (p != NULL) {
            printf("%d \t\t\t\t %s\n", ++seq, p->text);
            p = p->next;

        }
    }
    printf("Manage instructions: [L]ist, [M]odify, [A]dd, [D]elete "\
           "Target Rules: IP, Host, Content\n");
}

void modify(char *target) {
    if (strstr(target, "IP") || strstr(target, "ip") || strstr(target, "Ip") || strstr(target, "iP")) {
        int seq;
        char ip[20];
        char username[20];
        char passwd[256];

        scanf("%d %s %s %s", &seq, ip, username, passwd);
        if (seq > iphead->num) {
            printf("There are only %d rules.\n", iphead->num);
            printf("Manage instructions: [L]ist, [M]odify, [A]dd, [D]elete "\
           "Target Rules: IP, Host, Content\n");
            return;
        }
        else {
            struct iprules *p = iphead->next;
            while (--seq > 0) {
                p = p->next;
            }
            pthread_mutex_lock(&iprules_mutex);
            strcpy(p->allowed_ip, ip);
            if (strcmp(username, "None") == 0)
                p->sign = 0;
            else {
                p->sign = 1;
                strcpy(p->username, username);
                strcpy(p->passwd, passwd);
            }
            pthread_mutex_unlock(&iprules_mutex);
        }
    }
    else if (strstr(target, "HOST") || strstr(target, "Host") || strstr(target, "host")) {
        int seq;
        char hostname[256];

        scanf("%d %s", &seq, hostname);
        if (seq > hostHead->num) {
            printf("There are only %d rules.\n", hostHead->num);
            printf("Manage instructions: [L]ist, [M]odify, [A]dd, [D]elete "\
           "Target Rules: IP, Host, Content\n");
           return;
        }
        else {
            struct hostRules *p = hostHead->next;
            while (--seq > 0) {
                p = p->next;
            }
            pthread_mutex_lock(&hostrules_mutex);
            strcpy(p->host, hostname);
            pthread_mutex_unlock(&hostrules_mutex);
        }
    }
    else if (strstr(target, "Content") || strstr(target, "CONTENT")) {
        int seq;
        char text[512];

        scanf("%d %s", &seq, text);
        if (seq > ctHead->num) {
            printf("There are only %d rules.\n", ctHead->num);
            printf("Manage instructions: [L]ist, [M]odify, [A]dd, [D]elete "\
           "Target Rules: IP, Host, Content.\n");
            return;
        }
        else {
            struct ctRules *p = ctHead->next;
            while (--seq > 0) {
                p = p->next;
            }
            pthread_mutex_lock(&ctrules_mutex);
            strcpy(p->text, text);
            pthread_mutex_unlock(&hostrules_mutex);
        }
    }
    printf("Modify successfully.\n");
    return;
}

void add(char *target) {
    return;
}

void delete(char *target) {
    return;
}

void manage(void *arg) {
    printf("pthread created successfully.\n");
    printf("Manage instructions: [L]ist, [M]odify, [A]dd, [D]elete "\
           "Target Rules: IP, Host, Content\n");
    char instructions[10], target[10];
    while (scanf("%s %s", instructions, target)) {

        switch(instructions[0]) {
            case 'L': list(target);break;
            case 'M': modify(target);break;
            case 'A': add(target);break;
            case 'D': delete(target);break;
            default: break;
        }
    }
}

/*
 * Main entry: read listening port from the command prompt
 */
int main(int argc, char **argv)
{
	short port = 0;
	char opt;
	struct sockaddr_in cl_addr,proxyserver_addr;
	socklen_t sin_size = sizeof(struct sockaddr_in);
	int sockfd, accept_sockfd, on = 1;
	pthread_t Clitid;
	pthread_t Userid;
    loadrules();

    pthread_create(&Userid, NULL, (void*)manage, NULL);

	while( (opt = getopt(argc, argv, "p:")) != EOF) {
		switch(opt) {
		case 'p':
			port = (short) atoi(optarg);
			break;
		default:
			printf("Usage: %s -p port\n", argv[0]);
			return -1;
		}
	}

	if (port == 0) {
		printf("Invalid port number, try again. \n");
			printf("Usage: %s -p port\n", argv[0]);
			return -1;
	}

	printf("Welcome to attend the experiments of designing a proxy firewall! \n");

	memset(&proxyserver_addr, 0, sizeof(proxyserver_addr));							// zero proxyserver_addr
	proxyserver_addr.sin_family = AF_INET;
	proxyserver_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	proxyserver_addr.sin_port = htons(port);

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);			// create socket
	if (sockfd < 0) {
		printf("Socket failed...Abort...\n");
		return;
	} 
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));
	if (bind(sockfd, (struct sockaddr *) &proxyserver_addr, sizeof(proxyserver_addr)) < 0) {
		printf("Bind failed...Abort...\n");
		return;
	} 
	if (listen(sockfd, QUEUE_SIZE) < 0) {
		printf("Listen failed...Abort...\n");
		return;
	}
	while (1) {
		accept_sockfd = accept(sockfd, (struct sockaddr *)&cl_addr, &sin_size); 	// block for connection request
		if (accept_sockfd < 0) {
			printf("accept failed");
			continue;
		}

		print_clientinfo(cl_addr);
		
		//printf("Received a request from %s:%u \n",(char*)inet_ntoa(cl_addr.sin_addr.s_addr),ntohs(cl_addr.sin_port));


		if (checkclient(cl_addr.sin_addr.s_addr) == 1)
		{
		    struct parameter para;
		    para.accept_sockfd = accept_sockfd;
		    para.cl_addr = cl_addr;
		    pthread_create(&Clitid,NULL,(void*)dealonereq,&para);
		}
		else
			close(accept_sockfd);
	}
	return 0;
}

int getUserInfo(char* buf,char *passwd,  int length)
{
    char *p=strstr(buf,"Authorization:");
    int i,j = 0;
    if(!p) {
        return -1;
    }
    bzero(passwd, sizeof(passwd));
    for (i = (p-buf) + 21, j = 0; buf[i] != '\n'; ++i, ++j ) {
        passwd[j] = buf[i];
    }
    passwd[j] = '\0';
    return 1;
}

int getHostName(char* buf,char *hostname, int length)			//tested, must set this pointer[-6] to be '\n' again.
{
	
	char *p=strstr(buf,"Host: ");
	int i,j = 0;
	if(!p) {
		p=strstr(buf,"host: ");
	}
	bzero(hostname,256);
	for(i = (p-buf) + 6, j = 0; i<length; i++, j++)	{
		if(buf[i] =='\r') {
			hostname[j] ='\0';
			return 0;
		}
		else 
			hostname[j] = buf[i];
	}	
	return -1;
}

int connectserver(char* hostname)
{
	int cnt_stat;
	struct hostent *hostinfo;								// info about server
	struct sockaddr_in server_addr; 							// holds IP address
	int remotesocket;
	int remoteport = REMOTE_SERVER_PORT;  //80
	char newhostname[32];
	char *tmpptr;

	strcpy(newhostname, hostname); 
	tmpptr = strchr(newhostname,':');
	if (tmpptr != NULL)   //port is included in newremotename
	{
		remoteport = atoi(tmpptr + 1); //skip the char ':'
		*tmpptr = '\0';		
	}
		

	remotesocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (remotesocket < 0) {
		printf("can't create socket! \n");
		return -1;
	}
	memset(&server_addr, 0, sizeof(server_addr));

	//

	server_addr.sin_family= AF_INET;
//	server_addr.sin_port= htons(REMOTE_SERVER_PORT);
	server_addr.sin_port= htons(remoteport);
	pthread_mutex_lock(&conp_mutex);
	// lastservername被各线程共享，属于临界资源，故加锁
	if (strcmp(lastservername, newhostname) != 0)
	{ 	
		hostinfo = gethostbyname(newhostname);						
		if (!hostinfo) {
			
			printf("gethostbyname(%s) failed! \n",newhostname);
			pthread_mutex_unlock(&conp_mutex);
			return -1;
		}
		strcpy(lastservername,newhostname);
		lastserverip = *(int *)hostinfo->h_addr;
	}
	server_addr.sin_addr.s_addr = lastserverip;
	pthread_mutex_unlock(&conp_mutex);

	print_severinfo(server_addr);	

	if (connect(remotesocket, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		printf("remote connect failed! \n");
		close(remotesocket);
		return -1;
	}

	//You can delete the statement in case of voiding too much output.
	printf("A proxy connection is established properly! Congratulation! \n");

 	return remotesocket;
}



