all: start

start:
	./daemon start
stop:
	./daemon stop

clear: clean
	rm -f .*.swp
clean:
	rm -f *.pyc *.pyo
