all:
	gcc -O2 -Wall main.c -o procwatchd

clean:
	rm -f procwatchd
