TARGET = example
OBJ = example.o

LIBPATH = $(PWD)/../../../target/release
CFLAGS = -I../../include
LDFLAGS = -L$(LIBPATH) -Wl,-Bstatic -lcrypter -Wl,-Bdynamic

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ) $(LIB)
	cargo build --release --lib --features ffi
	$(CC) -o $(TARGET) $(OBJ) $(LDFLAGS)

clean:
	rm -rf $(TARGET) $(OBJ)
