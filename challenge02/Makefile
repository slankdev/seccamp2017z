
CC     = gcc
CFLAGS = -Wall -Werror
SRC    = main.c
OBJ    = $(SRC:.c=.o)
TARGET = a.out

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET)

clean:
	rm -rf a.out *.o

