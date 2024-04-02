all:
	cd libarchive && ./build/autogen.sh && ./configure --disable-shared  --with-bz2lib && make clean && make
	g++ OAO.cpp -o unOAO ./libarchive/.libs/libarchive.a -Ilibarchive/libarchive -lbz2  -lz  -llzma -lzstd 
	strip unOAO
test:
	 ./unOAO -tx -f msvcp100_withkey.oao
