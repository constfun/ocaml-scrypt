libscrypt
=========

This is a simple `Makefile` for compiling the scrypt source as a library.

1. scrypt depends on OpenSSL, so make sure you have it on your system.

1. If you don't trust me, replace `scrypt-1.1.6` with your own copy from [the source](https://www.tarsnap.com/scrypt.html).

3. Run `make`.

This will compile `libscrypt.a` and `libscrypt.so`, and copy the `scrypt.h` to the repository root.

Since this is a _simple_ Makefile, chances are good that it won't work for you.  
Since this is a _simple_ Makefile, you can modify it to fit your needs.
