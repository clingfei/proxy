proxy:proxy.o base64.o
	cc -o proxy proxy.o base64.o -lpthread
base64.o: base64.h
	cc -c base64.c
proxy.o: proxy.c base64.c base64.h
	cc -c proxy.c
.PHONY: clean
clean:
	-rm *.o proxy