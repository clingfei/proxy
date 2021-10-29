proxy:proxy.o base64.o
	gcc -o proxy proxy.o base64.o -lpthread
base64.o:
	gcc -c base64.c
proxy.o:
	gcc -c proxy.c
clean:
	rm *.o proxy