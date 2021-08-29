# Origin stub decrypter

This is an attempt of an origin stub decrypter to get a clean version without having to resort to runtime dumping.
I attempted to fix as many parts of PEs as possible. Unfortunately there are lots of tiny changes between origin stub versions, so creating one decrypter for all is probably impossible. Also it seems like most games require origin running anyways, so decrypting exes is most of the time only useful for modding / analysis purposes.

## Requirements
python 3.9+ with the following packages:
* PyCryptodome
* pefile

## How to use this?
Ideally just run `py decryptOriginStub.py [EXE Name]`, wait a couple of seconds and use the [EXE Name].fixed.exe. Unfortunately most of the time it isn't that easy.

## How do I fix this up for other origin stub versions
The easiest way to fix this decrypter for different origin versions is to dump the ooa section of the game, open it with the kaitai script file in the [web editor](https://ide.kaitai.io/)
 and look for very unlikely values. Especially around the end of the file.
I added a few ooa section files of different games in the `sample ooa sections` folder as an example. Even small byte alignment changes break the decryption process and might result in a broken IAT or TLS.

The current version of the struct works for fifa21 and jfo (and probably bf5 too). The recent release of madden changed some things and older games like bf1 won't work without small fixups either. It is unfortunately impossible to guarantee any kind of backwards/forwards compatibility because EA programmers are actively ~~breaking~~ changing things with every new release. Fortunately most of these changes are only a matter of type sizes and alignments and are very easy to spot.

Here is the OOA section of Jedi Fallen Order as an example:

![Jedi Fallen Order Struct](images/kaitai_jfo.png)

not every value is set but all relevant values make sense.

On the other hand the same struct with Battlefield 1:

![Battlefield 1 Struct](images/kaitai_bf1.png)

Everything makes sense until the `sizeOfImage` property. The `sizeOfImage` property of the protected Exe should only slightly differ to unprotected one by about 0x1000 (The size of the added ooa section). Therefore we just change the `unknown_always_1` property to a `u2le` and immediately solve the alignment issue. Now all values past this property start to make sense and the dump will be successful.

![Battlefield 1 Struct Fixed](images/kaitai_bf1_fixed.png)

As a general rule: make sure that the final property (the denuvo dbdata string) is aligned correctly and you shouldn't run into any issues.

### Disclamer
This doesn't allow you to play games for free. You need to have the game installed and have an active license to get the required origin stub decryption key.

### Credits
Greets to Extern for his initial version of the dumper