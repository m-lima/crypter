INDEX = web/index.html

WASM_BG = $(PWD)/web/crypter.js

WASM = $(PWD)/../../../target/wasm32-unknown-unknown/release/crypter.wasm

.PHONY: all clean

all: $(INDEX)

$(INDEX): $(WASM_BG)
	cp $(PWD)/index.html $(PWD)/web/.

$(WASM_BG): $(WASM)
	wasm-bindgen $(WASM) --out-dir $(PWD)/web --web

$(WASM):
	cargo build --features wasm --target wasm32-unknown-unknown --release --lib

clean:
	rm -rf $(PWD)/web $(PWD)/../../../target/wasm32-unknown-unknown
