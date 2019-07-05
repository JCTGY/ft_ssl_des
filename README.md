DES Cipher Encryption

![](https://i.imgur.com/5gbYhtW.jpg)

### Objective
42 school project we will implements cipher text encryption in C without using most of the standard libary.

Allow funtion
* open
* close 
* read
* write
* malloc
* free

### Function cover
* base64
* des
* des-cbc
* des-ecb
* des3
* des3-ede
* des3-ede-cbc

### Flag cover
base64:
* -e, encrption (default)
* -d, decryption
* -i, file input at next argument
* -o, file output at next argument

des:
* -a, decode/encode the input/output in base64, depending on the encrypt mode
* -d, decrypt mode
* -e, encrypt mode (default)
* -i, input file for message
* -k, key in hex is the next arguement.
(Behave like openssl des -K not openssl des -k)
* -o, output file for message
* -p, password in ascii is the next argument.
(Behave like a modifiedd openssl des -pass not like openssl des -p or -P) 
* -s, the salt in hex is the next argument. (Behave like openssl des -S)
* -v, initialization vector in hex is the next argument. (Behave like openssl des -iv not openssl des -v)

### Useful link
[Base64 wiki algorithum](https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64)\
[The DES Algorithm Illustrated by J. Orlin Grabbe](http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm)\
[Data Encryption Standard wiki page](https://en.wikipedia.org/wiki/Data_Encryption_Standard)\
[DES PDF from Cleveland State University](https://academic.csuohio.edu/yuc/security/Chapter_06_Data_Encription_Standard.pdf) \
[Encryption operating modes: ECB vs CBC](https://adayinthelifeof.nl/2010/12/08/encryption-operating-modes-ecb-vs-cbc/)\
[OpenSSL 3DES encrytion parameters](https://superuser.com/questions/769273/openssl-3des-encrytion-parameters)\
[DATA ENCRYPTION STANDARD (DES)](https://csrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf)
