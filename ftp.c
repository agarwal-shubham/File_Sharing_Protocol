#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <openssl/md5.h>

char history[1000][1000]={0};
int cmd_no=0;
int match(char *regexp, char *text){
        if (regexp[0] == '^')
            return matchhere(regexp+1, text);
        do {    /* must look even if string is empty */
            if (matchhere(regexp, text))
                return 1;
        } while (*text++ != '\0');
        return 0;
}

/* matchhere: search for regexp at beginning of text */
int matchhere(char *regexp, char *text){
        if (regexp[0] == '\0')
            return 1;
        if (regexp[1] == '*')
            return matchstar(regexp[0], regexp+2, text);
        if (regexp[0] == '$' && regexp[1] == '\0')
            return *text == '\0';
        if (*text!='\0' && (regexp[0]=='.' || regexp[0]==*text))
            return matchhere(regexp+1, text+1);
        return 0;
}

/* matchstar: search for c*regexp at beginning of text */
int matchstar(int c, char *regexp, char *text){
        do {    /* a * matches zero or more instances */
            if (matchhere(regexp, text))
                return 1;
        } while (*text != '\0' && (*text++ == c || c == '.'));
        return 0;
}
int server()
{
	DIR *d;
	struct dirent *dir;
	struct stat st;
	char dirc[1024],list[1024],f_name[1024];
	int listenSocket = 0,clilen=0;	// This is my server's socket which is created to 
						//	listen to incoming connections
	int connectionSocket = 0;
	struct tm tm;
	time_t start_t,end_t;
	struct sockaddr_in serv_addr,cli_addr;		// This is for addrport for listening
	socklen_t ser_len=sizeof(cli_addr);

	// Creating a socket
	listenSocket = socket(AF_INET,SOCK_STREAM,0);
	if(listenSocket<0){
		printf("ERROR WHILE CREATING A SOCKET\n");
		perror("socket");
		return 0;
	}
	else
		printf("[SERVER] SOCKET ESTABLISHED SUCCESSFULLY\n\n");

	// Its a general practice to make the entries 0 to clear them of malicious entry

	bzero((char *) &serv_addr,sizeof(serv_addr));
	
	int reuseaddr=1;
	if (setsockopt(listenSocket,SOL_SOCKET,SO_REUSEADDR,&reuseaddr,sizeof(reuseaddr))==-1) {
    		printf("fsdfa\n");
	}
	// Binding the socket

	int portno = 5605;
	serv_addr.sin_family = AF_INET;	//For a remote machine
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(portno);

	if(bind(listenSocket,(struct sockaddr * )&serv_addr,sizeof(serv_addr))<0){
		printf("ERROR WHILE BINDING THE SOCKET\n");
		perror("bind");
	}
	else
		printf("[SERVER] SOCKET BINDED SUCCESSFULLY\n");
	 //Listening to connections
	if(listen(listenSocket,10) == -1)	//maximum connections listening to 10
	{
		perror("listen");
		printf("[SERVER] FAILED TO ESTABLISH LISTENING \n\n");
	}
	printf("[SERVER] Waiting fo client to connect....\n" );
	while(1){
		printf("Server is open\n");
		// Accepting connections
		bzero((char *) &cli_addr,sizeof(cli_addr));
		clilen = sizeof(cli_addr);
		while((connectionSocket=accept(listenSocket , (struct sockaddr*)&cli_addr,&clilen))<0);
		printf("[CONNECTED]\n");
		while(1){
			char buffer[1024],locn[1024],data[1024],recv_name[1000];
			bzero(buffer,1024);
			int byte_rec;
			byte_rec=recv(connectionSocket,buffer,1023,0);
			if(byte_rec<0){			//////
				printf("ERROR while reading from Client  sd\n");
				perror("read");
				continue;
			}
			/*if(byte_rec==0){
				printf("[SERVER]Closing\n");
				close(connectionSocket);
				break;
			}*/
		
			if(strcmp(buffer,"Upload")==0){
				//printf("%s\n",buffer);
				bzero(buffer,1024);
				bzero(recv_name,1000);
				if(write(connectionSocket,"allow",5)<0){
					printf("ERROR while writing to the client\n");					
					perror("write_upload");
				}
				if(read(connectionSocket,buffer,1023)<0){			//////
					printf("ERROR while reading from Client\n");
					perror("read");
				}
				strcat(recv_name,"./server_share/");
				//printf("buffer=%s \nrecv_name=%s\n",buffer,recv_name);
				char temp[1024];
				char* delim=strtok(buffer," ");
				strcat(recv_name,buffer);
				while(delim!=NULL){
					bzero(temp,1024);
					strcat(temp,delim);
					delim=strtok(NULL," ");
				}
				//printf("%s\n",temp);
				FILE *fr=fopen(recv_name,"a");
				if(fr==NULL)
					printf("[SERVER] File %s cannot be opened on server\n",recv_name);
				else{
					bzero(data,1024);
					int data_block;
					while((data_block=read(connectionSocket,data,1023))>0){
						int write_block = fwrite(data, sizeof(char),data_block,fr);			
						if(write_block<data_block)
							printf("[SERVER] Error while writing file %s \n",recv_name);
						bzero(data,100);
						if(data_block==0 || data_block!=1024)
							break;
					}
					fclose(fr);
				}
			//MD5 Checksum
			char checksum[1000],tmp[1000];
			bzero(checksum,1000);
			unsigned char c[MD5_DIGEST_LENGTH];
    			int i;
    			FILE *inFile = fopen (recv_name, "rb");
    			MD5_CTX mdContext;
    			int bytes;
    			unsigned char dta[1024];
    			if (inFile == NULL) {
        			printf ("%s can't be opened.\n", recv_name);
    			}
    			MD5_Init (&mdContext);
    			while ((bytes = fread (dta, 1, 1024, inFile)) != 0)
    			MD5_Update (&mdContext, dta, bytes);
    			MD5_Final (c,&mdContext);
    			for(i = 0; i < MD5_DIGEST_LENGTH; i++){
				bzero(tmp,1000);
				sprintf(tmp,"%02x", c[i]);
				strcat(checksum,tmp);
			}
    			fclose (inFile);
				printf("Checking for transfer errors via md5-checksum.....\n");
				if(strcmp(checksum,temp)==0)
					printf("File was transferred without errors\n");
				bzero(buffer,1024);
				bzero(data,1024);	
			}
			else if(strcmp(buffer,"Download")==0){
					printf("%s\n",buffer);
				bzero(buffer,1024);
				bzero(recv_name,1000);
				if(write(connectionSocket,"allow",5)<0){
					printf("ERROR while writing to the client\n");					
					perror("write_upload");
				}
				bzero(recv_name,1000);

				if(recv(connectionSocket,buffer,1023,0)<0)
					printf("ERROR while reading from Client\n");

				strcat(recv_name,"./server_share/");
				strcat(recv_name,buffer);
				printf("%s\n",recv_name);

				FILE *fs=fopen(recv_name,"r");
				if(fs==NULL)
					printf("[SERVER] Error:File %s not found \n",recv_name);
				else
					printf("[SERVER] File %s is being shared......\n",recv_name);
				int data_blocks;
				while((data_blocks=fread(data, sizeof(char), 1024, fs))>0){
					if(send(connectionSocket,data,data_blocks,0)<0)
						printf("[SERVER] Error while sending file %s \n",recv_name);
					bzero(data,1024);
				}
				fclose(fs);
			}
			else if(strcmp(buffer,"--longlist")==0){
				printf("longlist\n");
				bzero(dirc,1024);
				bzero(list,1024);
				d=opendir("./server_share");
				if(d){
					while ((dir = readdir(d)) != NULL){
						if(dir->d_name[0]!='.'){
								//printf("am i here\n");
								bzero(list,1024);
								strcat(dirc,"./server_share/");
								strcat(dirc,dir->d_name);
								stat(dirc,&st);
								char tim[100];
								bzero(tim,100);
								strncpy(tim,ctime(&st.st_atime),strlen(ctime(&st.st_atime))-1);
								strcat(list,dir->d_name);
								strcat(list,"   ");
								//strcat(list,(char*)st.st_size);
								sprintf(list,"%s%d",list,(int)st.st_size);
								strcat(list,"  ");
								strcat(list,tim);
								strcat(list,"  ");
								if(S_ISREG(st.st_mode))
									strcat(list,"regular file\n");
								else if(S_ISDIR(st.st_mode))
									strcat(list,"directory\n");
								else if(S_ISCHR(st.st_mode))
									strcat(list,"character device\n");
								else if(S_ISBLK(st.st_mode))
									strcat(list,"block device\n");
								else if(S_ISLNK(st.st_mode))
									strcat(list,"symbolic link\n");
								else if(S_ISSOCK(st.st_mode))
									strcat(list,"socket\n");
								else if(S_ISFIFO(st.st_mode))
									strcat(list,"FIFO(named pipe)\n");
								bzero(dirc,100);
								if(write(connectionSocket,list,1024)<0){
									printf("ERROR while writing to the client\n");
									perror("write_upload");
								}
						}
					}
				}
				closedir(d);
				if(write(connectionSocket,"End Of File",11)<0){
					printf("ERROR while writing to the client\n");
					perror("write_upload");
				}
				
				
			}
			else if(strncmp(buffer,"--regex ",8)==0){
				bzero(dirc,1024);
				bzero(list,1024);
				//printf("%s\n",buffer);
				char temp[1024];
				d=opendir("./server_share");
				char* delim=strtok(buffer," ");
				while(delim!=NULL){
					bzero(temp,1024);
					strcat(temp,delim);
					delim=strtok(NULL," ");
				}
				printf("%s\n",temp);
				if(d){
					while ((dir = readdir(d)) != NULL){
						if(dir->d_name[0]!='.'){
							int a= match(temp,dir->d_name);
							//if(strstr(dir->d_name,temp)){
							if(a==1){
								bzero(list,1024);
								strcat(dirc,"./server_share/");
								strcat(dirc,dir->d_name);
								//printf("%s\n",dirc);
								stat(dirc,&st);
								char tim[100];
								bzero(tim,100);
								strncpy(tim,ctime(&st.st_atime),strlen(ctime(&st.st_atime))-1);
								strcat(list,dir->d_name);
								strcat(list,"   ");
								//strcat(list,(char*)st.st_size);
								sprintf(list,"%s%d",list,(int)st.st_size);
								strcat(list,"  ");
								strcat(list,tim);
								strcat(list,"  ");
								if(S_ISREG(st.st_mode))
									strcat(list,"regular file\n");
								else if(S_ISDIR(st.st_mode))
									strcat(list,"directory\n");
								else if(S_ISCHR(st.st_mode))
									strcat(list,"character device\n");
								else if(S_ISBLK(st.st_mode))
									strcat(list,"block device\n");
								else if(S_ISLNK(st.st_mode))
									strcat(list,"symbolic link\n");
								else if(S_ISSOCK(st.st_mode))
									strcat(list,"socket\n");
								else if(S_ISFIFO(st.st_mode))
									strcat(list,"FIFO(named pipe)\n");
								bzero(dirc,100);
								if(write(connectionSocket,list,1024)<0){
									printf("ERROR while writing to the client\n");
									perror("write_upload");
								}
							}
						}
				    	}
				}
				closedir(d);
				if(write(connectionSocket,"End Of File",11)<0){
					printf("ERROR while writing to the client\n");
					perror("write_upload");
				}
				
				
			}
			else if(strncmp(buffer,"--shortlist ",12)==0){
				bzero(dirc,1024);
				bzero(list,1024);
				//printf("%s\n",buffer);
				d=opendir("./server_share");
				char start[100],end[100];
				bzero(start,100);bzero(end,100);
				char* delim=strtok(buffer," ");
				int k=0;
				
				while(delim!=NULL){
					if(k==1)
						strcat(start,delim);
					if(k==2)
						strcat(end,delim);
					k++;
					delim=strtok(NULL," ");
				}
				//printf("%s%s\n",start,end);
				//if(strptime(start,"%d-%b-%Y-%H:%M:%S",&tm)==NULL){
				//	printf("Wrong Format Correct format is dd-mm-yy-hh:mm:ss\n");
				//}
				strptime(start,"%d-%b-%Y-%H:%M:%S",&tm);
				start_t=mktime(&tm);
				//if(strptime(end,"%d-%b-%Y-%H:%M:%S",&tm)==NULL){
				//	printf("Wrong Format Correct format is dd-mm-yy-hh:mm:ss\n");
				//}
				strptime(start,"%d-%b-%Y-%H:%M:%S",&tm);
				end_t=mktime(&tm);
				////
				d=opendir("./server_share");
				if(d){
					while ((dir = readdir(d)) != NULL){
						if(dir->d_name[0]!='.'){
							if(difftime(st.st_mtime,start_t) > 0 && difftime(end_t,st.st_mtime) > 0){
								bzero(list,1024);
								strcat(dirc,"./server_share/");
								strcat(dirc,dir->d_name);
								//printf("%s\n",dirc);
								stat(dirc,&st);
								char tim[100];
								bzero(tim,100);
								strncpy(tim,ctime(&st.st_atime),strlen(ctime(&st.st_atime))-1);
								strcat(list,dir->d_name);
								strcat(list,"   ");
								//strcat(list,(char*)st.st_size);
								sprintf(list,"%s%d",list,(int)st.st_size);
								strcat(list,"  ");
								strcat(list,tim);
								strcat(list,"  ");
								if(S_ISREG(st.st_mode))
									strcat(list,"regular file\n");
								else if(S_ISDIR(st.st_mode))
									strcat(list,"directory\n");
								else if(S_ISCHR(st.st_mode))
									strcat(list,"character device\n");
								else if(S_ISBLK(st.st_mode))
									strcat(list,"block device\n");
								else if(S_ISLNK(st.st_mode))
									strcat(list,"symbolic link\n");
								else if(S_ISSOCK(st.st_mode))
									strcat(list,"socket\n");
								else if(S_ISFIFO(st.st_mode))
									strcat(list,"FIFO(named pipe)\n");
								bzero(dirc,100);
								if(write(connectionSocket,list,1024)<0){
									printf("ERROR while writing to the client\n");
									perror("write_upload");
								}
							}
						}
					}
				}
				else{
					printf("Couldn't open the directory\n");
				}
				closedir(d);
				if(write(connectionSocket,"End Of File",11)<0){
					printf("ERROR while writing to the client\n");
					perror("write_upload");
				}
			}
			else if(strncmp(buffer,"--verify ",8)==0){
				bzero(dirc,1024);
				bzero(list,1024);
				bzero(f_name,1024);
				//int x=recv(connectionSocket,buffer,1024,0);
				//printf("%s\n",buffer);
				char temp[1024];
				char* delim=strtok(buffer," ");
				while(delim!=NULL){
					bzero(temp,1024);
					strcat(temp,delim);
					delim=strtok(NULL," ");
				}
				//printf("%s\n",temp);
				strcat(dirc,"./server_share/");
				strcat(dirc,temp);
				stat(dirc,&st);
				//printf("%s\n",dirc);
				char checksum[1000],tmp[1000];
				bzero(checksum,1000);
				unsigned char c[MD5_DIGEST_LENGTH];
    				int i;
    				FILE *inFile = fopen (dirc, "rb");
    				MD5_CTX mdContext;
    				int bytes;
    				unsigned char dta[1024];
    				if (inFile == NULL) {
        				printf ("%s can't be opened.\n", dirc);
    				}
    				MD5_Init (&mdContext);
    				while ((bytes = fread (dta, 1, 1024, inFile)) != 0)
    				MD5_Update (&mdContext, dta, bytes);
    				MD5_Final (c,&mdContext);
    				for(i = 0; i < MD5_DIGEST_LENGTH; i++){
					bzero(tmp,1000);
					sprintf(tmp,"%02x", c[i]);
					strcat(checksum,tmp);
				}
				strcat(checksum,"   ");
				strcat(checksum,ctime(&st.st_mtime));
				//printf("%s\n",checksum);
				if(write(connectionSocket,checksum,strlen(checksum))<0){
					printf("ERROR while writing to the client\n");
					perror("write_upload");
				}
				bzero(dirc,100);
			}
			else if(strcmp(buffer,"--checkall")==0){
				d=opendir("./server_share");
				if(d){
					while((dir = readdir(d)) != NULL){
						if(dir->d_name[0]!='.'){
							strcat(dirc,"./server_share/");
							strcat(dirc,dir->d_name);
							//printf("am i here\n");
							stat(dirc,&st);
							char checksum[1000],tmp[1000];
							bzero(checksum,1000);
							strcat(checksum,dir->d_name);
							strcat(checksum,"  ");
							unsigned char c[MD5_DIGEST_LENGTH];
    							int i;
    							FILE *inFile = fopen (dirc, "rb");
    							MD5_CTX mdContext;
    							int bytes;
    							unsigned char dta[1024];
    							if (inFile == NULL) {
        							printf ("%s can't be opened.\n", dirc);
    							}
    							MD5_Init (&mdContext);
    							while ((bytes = fread (dta, 1, 1024, inFile)) != 0)
    							MD5_Update (&mdContext, dta, bytes);
    							MD5_Final (c,&mdContext);
    							for(i = 0; i < MD5_DIGEST_LENGTH; i++){
								bzero(tmp,1000);
								sprintf(tmp,"%02x", c[i]);
								strcat(checksum,tmp);
							}
							strcat(checksum,"   ");
							strcat(checksum,ctime(&st.st_mtime));
							//printf("%s\n",checksum);
							if(write(connectionSocket,checksum,strlen(checksum))<0){
								printf("ERROR while writing to the client\n");
								perror("write_upload");
							}
							bzero(dirc,100);
						}
					}
				}
				closedir(d);
				printf("\n\n");
				if(write(connectionSocket,"End Of File",11)<0){
					printf("ERROR while writing to the client\n");
					perror("write_upload");
				}
				bzero(dirc,100);
			}
		}
	}
	printf("\nClosing connection\n");
	//close(connectionSocket);	
	close(listenSocket);
	return 0;
}
int client()
{
		
		int ClientSocket = 0,ser_len=0;
		struct sockaddr_in serv_addr;
		char comd[1000],t1[100],t2[100],prot[3],f_name[1000],hash[100];
		bzero(comd,1000);bzero(t1,100);bzero(t2,100);bzero(prot,3);bzero(f_name,1000);bzero(hash,100);
		DIR *d;
		char dirc[100];
		bzero(dirc,100);
		struct dirent *dir;
		struct stat st;		
		// Creating a socket
		ClientSocket = socket(AF_INET,SOCK_STREAM,0);
		if(ClientSocket<0)
		{
			printf("ERROR WHILE CREATING A SOCKET\n");
			perror("socket");
			return 0;
		}
		else
			printf("[CLIENT] Socket created \n");
		int portno = 5610;
		int flag=0;		
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(portno);
		serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		char buffer[1024],locn[1024],data[1024];	
		while(1){
			printf("Enter Command\n");
			scanf("%s",comd);			
			if(strcmp(comd,"FileDownload")==0){
				scanf("%s",prot);
				if(strcmp(prot,"--TCP")==0 || strcmp(prot,"--UDP")==0){
					bzero(locn,1024);
					bzero(buffer,1024);
					char recv_name[1000];
					bzero(recv_name,1000);
					scanf("%s",locn);
					printf("TCP download\n");
					if(flag==0){
						while(connect(ClientSocket,(struct sockaddr *)&serv_addr,sizeof(serv_addr))<0);
						flag=1;
					}
					if(write(ClientSocket,"Download",8)<0){
						printf("ERROR while writing to the socket\n");					
						perror("write_upload");
					}
					if(read(ClientSocket,buffer,1023)<0){
						printf("ERROR while reading from Server\n");
						perror("read");
					}
					if(strcmp(buffer,"allow")==0){
					if(send(ClientSocket,locn,strlen(locn),0)<0)
						printf("ERROR while writing to the socket\n");	
					
					strcat(recv_name,"./client_share/");
					strcat(recv_name,locn);
					FILE *fr=fopen(recv_name,"a");
					if(fr==NULL)
						printf("[CLIENT] File %s cannot be opened\n",recv_name);
					else{
						bzero(data,1024);
						int data_block;
						while((data_block=recv(ClientSocket,data,1023,0))>0){
							int write_block = fwrite(data, sizeof(char),data_block,fr);			
							if(write_block<data_block)
								printf("[CLIENT] Error while writing file %s \n",recv_name);
							bzero(data,1024);
							if(data_block==0 || data_block!=1024)
								break;
						}
						fclose(fr);
					}
					}
					bzero(buffer,1024);
					bzero(data,1024);				
				}
			}
			else if(strcmp(comd,"FileUpload")==0){				
				scanf("%s",prot);
				if(strcmp(prot,"--TCP")==0 || strcmp(prot,"--UDP")==0){
					bzero(f_name,1000);
					scanf("%s",f_name);				////////
					bzero(buffer,1024);
					bzero(locn,1024);
					bzero(data,1024);				
					printf("TCP upload\n");
					//printf("f_name=%s\n",f_name);
					char * last;
					char temp[1000];
					bzero(temp,1000);
					strcat(temp,f_name);
					last=strtok(f_name,"/");
					while(last!=NULL){
						bzero(locn,1024);
						strcat(locn,last);
						last=strtok(NULL,"/");
					}
					//printf("locn=%s\n",locn);
					printf("temp=%s\n",temp);
					//Connection Establishment	
					if(flag==0){
						while(connect(ClientSocket,(struct sockaddr *)&serv_addr,sizeof(serv_addr))<0);
						flag=1;
					}
					if(write(ClientSocket,"Upload",6)<0){
						printf("ERROR while writing to the socket\n");					
						perror("write_upload");
					}
					if(read(ClientSocket,buffer,1023)<0){
						printf("ERROR while reading from Server\n");
						perror("read");
					}
					if(strcmp(buffer,"allow")==0){
						printf("\nFile Upload Allowed\n");
			//MD5 Checksum
			char checksum[1000],tmp[1000];
			bzero(checksum,1000);
			unsigned char c[MD5_DIGEST_LENGTH];
    			int i;
    			FILE *inFile = fopen (temp, "rb");
    			MD5_CTX mdContext;
    			int bytes;
    			unsigned char dta[1024];
    			if (inFile == NULL) {
        			printf ("%s can't be opened.\n", temp);
    			}
    			MD5_Init (&mdContext);
    			while ((bytes = fread (dta, 1, 1024, inFile)) != 0)
    			MD5_Update (&mdContext, dta, bytes);
    			MD5_Final (c,&mdContext);
    			for(i = 0; i < MD5_DIGEST_LENGTH; i++){
				bzero(tmp,1000);
				sprintf(tmp,"%02x", c[i]);
				strcat(checksum,tmp);
			}
    			fclose (inFile);
						strcat(locn," ");
						strcat(locn,checksum);
						if(write(ClientSocket,locn,strlen(locn))<0){
							printf("ERROR while writing to the socket\n");					
							perror("write_upload");
						}
						FILE *fs=fopen(temp,"r");
						if(fs==NULL)
							printf("[CLIENT] Error:File %s not found \n",temp);
						else
							printf("[CLIENT] File %s is being shared......\n",temp);
						int data_blocks;
						while((data_blocks=fread(data, sizeof(char), 1024, fs))>0){
							if(write(ClientSocket,data,data_blocks)<0)
								printf("[CLIENT] Error while sending file %s \n",f_name);
							bzero(data,1024);
						}
						
						fclose(fs);
						bzero(locn,1024);
					}
					else
						printf("\nFile Upload Denied\n");
					bzero(buffer,1024);
					bzero(data,1024);
				}
				/*else if(strcmp(prot,"--UDP")==0){
					bzero(f_name,1000);
					scanf("%s",f_name);				////////
					bzero(buffer,1024);
					bzero(locn,1024);
					bzero(data,1024);				
					printf("UDP upload\n");
					printf("f_name=%s\n",f_name);
					char * last;
					char temp[1000];
					bzero(temp,1000);
					strcat(temp,f_name);
					last=strtok(f_name,"/");
					while(last!=NULL){
						bzero(locn,1024);
						strcat(locn,last);
						last=strtok(NULL,"/");
					}
					printf("locn=%s\n",locn);
					printf("temp=%s\n",temp);
					ser_len = sizeof(serv_addr);
					if(write(ClientSocket,"Upload",6)<0){
						printf("ERROR while writing to the socket\n");					
						perror("write_upload");
					}
					if(read(ClientSocket,buffer,1023)<0){
						printf("ERROR while reading from Server\n");
						perror("read");
					}
					if(strcmp(buffer,"allow")==0){
						printf("allowed\n");
						if(write(ClientSocket,locn,strlen(locn))<0){
							printf("ERROR while writing to the socket\n");
							perror("write_upload");
						}
						FILE *fs=fopen(temp,"r");
						if(fs==NULL)
							printf("[CLIENT] Error:File %s not found \n",temp);
						else
							printf("[CLIENT] File %s is being shared......\n",temp);
						int data_blocks;
						while((data_blocks=fread(data, sizeof(char), 1024, fs))>0){
							if(write(ClientSocket,data,data_blocks)<0)
								printf("[CLIENT] Error while sending file %s \n",f_name);
							bzero(data,1024);
						}
						fclose(fs);
						bzero(locn,1024);
					}
					else
						printf("Not Allowed\n");
					bzero(buffer,1024);
					bzero(data,1024);
				}*/
				bzero(f_name,1000);
			}
			else if(strcmp(comd,"FileHash")==0){
				scanf("%s",hash);
				if(strcmp(hash,"--verify")==0){
					scanf("%s",f_name);
					char t[1000];
					bzero(t,1000);
					strcat(t,"--verify ");
					strcat(t,f_name);
					//printf("%s",t);
					if(flag==0){
						while(connect(ClientSocket,(struct sockaddr *)&serv_addr,sizeof(serv_addr))<0);
						flag=1;
					}
					if(write(ClientSocket,t,strlen(t))<0){
						printf("ERROR while writing to the socket\n");					
						perror("write_upload");
					}
						int num=0;
						bzero(buffer,1024);
						num=recv(ClientSocket,buffer,1024,0);
						printf("%s",buffer);
					printf("    [verify]\n------DONE-------\n");
					
				}
				else if(strcmp(hash,"--checkall")==0){
					if(flag==0){
						while(connect(ClientSocket,(struct sockaddr *)&serv_addr,sizeof(serv_addr))<0);
						flag=1;
					}
					if(write(ClientSocket,"--checkall",10)<0){
						printf("ERROR while writing on Server\n");
						perror("read");
					}
					while(1){
						bzero(buffer,1024);
						int num;
						num=recv(ClientSocket,buffer,1024,0);
						buffer[num]='\0';
						if(strcmp(buffer,"End Of File")==0)
							break;
						printf("%s",buffer);
					}
					printf("    [checkall]\n--------DONE---------\n");
				}
				bzero(f_name,1000);
			}
			else if(strcmp(comd,"IndexGet")==0){
				
				d=opendir("./server_share");
				bzero(buffer,1024);
				scanf("%s",comd);
				int num=0;
				if(comd==NULL)
					break;
				if(strcmp(comd,"--longlist")==0){
					strcat(history[cmd_no],"IndexGet --longlist");
					cmd_no += 1;
					printf("Shared Folder\n");
					if(flag==0){
						while(connect(ClientSocket,(struct sockaddr *)&serv_addr,sizeof(serv_addr))<0);
						flag=1;
					}
					if(write(ClientSocket,"--longlist",10)<0){
						printf("ERROR while writing on Server\n");
						perror("read");
					}
					while(1){
						bzero(buffer,1024);
						num=recv(ClientSocket,buffer,1024,0);
						buffer[num]='\0';
						if(strcmp(buffer,"End Of File")==0)
							break;
						printf("%s",buffer);
					}
					printf("    [Longlist]\n--------DONE---------\n");
				}
				else if(strcmp(comd,"--shortlist")==0){
					strcat(history[cmd_no],"IndexGet --shortlist ");
					printf("Implementation errors still there\n");
					scanf("%s",t1);
					scanf("%s",t2);
					strcat(history[cmd_no],t1);
					strcat(history[cmd_no]," ");
					strcat(history[cmd_no],t2);
					cmd_no += 1;
					//printf("%s %s\n",t1,t2);
					char t[1000];
					bzero(t,1000);
					strcat(t,"--shortlist ");
					strcat(t,t1);
					strcat(t," ");
					strcat(t,t2);
					//printf("%s",t);
					if(flag==0){
						while(connect(ClientSocket,(struct sockaddr *)&serv_addr,sizeof(serv_addr))<0);
						flag=1;
					}
					if(write(ClientSocket,t,strlen(t))<0){
						printf("ERROR while writing to the socket\n");					
						perror("write_upload");
					}
					/*while(1){
						bzero(buffer,1024);
						num=recv(ClientSocket,buffer,1024,0);
						buffer[num]='\0';
						if(strcmp(buffer,"End Of File")==0)
							break;
						printf("%s",buffer);
					}*/
					printf("    [shortlist]\n------DONE-------\n");
				}
				else if(strcmp(comd,"--regex")==0){
					strcat(history[cmd_no],"IndexGet --regex ");
					char reg[1000];char t[1000];
					bzero(reg,1000);bzero(t,1000);
					scanf("%s",reg);
					strcat(t,"--regex ");
					strcat(t,reg);
					strcat(history[cmd_no],reg);
					cmd_no += 1;
					if(flag==0){
						while(connect(ClientSocket,(struct sockaddr *)&serv_addr,sizeof(serv_addr))<0);
						flag=1;
					}
					bzero(buffer,1024);
					if(write(ClientSocket,t,strlen(t))<0){
						printf("ERROR while writing on Server\n");
						perror("read");
					}
					while(1){
						bzero(buffer,1024);
						num=recv(ClientSocket,buffer,1024,0);
						buffer[num]='\0';
						if(strcmp(buffer,"End Of File")==0)
							break;
						printf("%s",buffer);
					}
					printf("    [regex]\n------DONE-------\n");
				}
			}
			else if(strcmp(comd,"history")==0){
				int i=0;
				for(i=0;i<cmd_no;i++)
					printf("%s\n",history[i]);
			}
			else if(strcmp(comd,"exit")==0){
					printf("Closing Connection\n");
					close(ClientSocket);
					break;	
			}	
		}
	return 0;
}
int main(){
	pid_t pid;
	pid=fork();
	if(pid==-1){
		printf("Error in creating Fork\n");
		exit(0);
	}
	if (pid==0){
		server();
	}
	else{
		client();
	}
	kill(pid,SIGQUIT);
	return 0;
}
