
main: main.c aes.c aes.h
	gcc main.c aes.c -o main 

clean: 
	rm main
