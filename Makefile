
default: AES

AES: AES.c
	gcc -Ofast AES.c -o AES

clean:
	-rm -f AES
