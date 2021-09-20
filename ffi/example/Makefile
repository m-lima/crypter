TARGET = example

OBJ = example.o

RPATH = $(PWD)/../../target/release
CFLAGS = -I../include
LDFLAGS = -L$(RPATH) -Wl,-rpath,$(RPATH)
LIBS = -lcrypter

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) $(LDFLAGS) $(LIBS)

clean:
	rm -rf $(TARGET) $(OBJ)
