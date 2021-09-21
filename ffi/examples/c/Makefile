TARGET = example
OBJ = example.o

RPATH = $(PWD)/../../../target/release
CFLAGS = -I../../include
LDFLAGS = -L$(RPATH) -Wl,-rpath,$(RPATH)
LIBS = -lcrypter

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ) $(LIB)
	cargo build --release --lib --features ffi
	$(CC) -o $(TARGET) $(OBJ) $(LDFLAGS) $(LIBS)

clean:
	rm -rf $(TARGET) $(OBJ)
