## Cryptography and Network Security
## Programs:
# Caesar Cipher
```
#include<stdio.h>
#include<string.h>
#include<conio.h>
#include<ctype.h>

int main() {
    char plain[10], cipher[10]; 
    int key, i, length;

    printf("\n Enter the plain text:");
    scanf("%s", plain);

    printf("\n Enter the key value:");
    scanf("%d", &key);

    printf("\n \n \t PLAIN TEXT: %s", plain);

    // Encryption
    printf("\n \n \t ENCRYPTED TEXT: ");
    for(i = 0, length = strlen(plain); i < length; i++) {
        cipher[i] = plain[i] + key;
        if (isupper(plain[i]) && (cipher[i] > 'Z')) 
            cipher[i] = cipher[i] - 26;
        if (islower(plain[i]) && (cipher[i] > 'z')) 
            cipher[i] = cipher[i] - 26;
        printf("%c", cipher[i]);
    }

    // Decryption
    printf("\n \n \t AFTER DECRYPTION : ");
    for(i = 0; i < length; i++) {
        plain[i] = cipher[i] - key; 
        if (isupper(cipher[i]) && (plain[i] < 'A')) 
            plain[i] = plain[i] + 26; 
        if (islower(cipher[i]) && (plain[i] < 'a')) 
            plain[i] = plain[i] + 26; 
        printf("%c", plain[i]);
    }
    
    getch();
    return 0;
}
```
# OUTPUT
![1](https://github.com/arulolia/lab-exercises/assets/122069938/09f4ac19-e146-44d9-90eb-b1b7b2001b8f)

# Rail Cipher

```
#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include<string.h>

long int p, q, n, t, flag, e[100], d[100], temp[100], j, m[100], en[100], i;
char msg[100];

int prime(long int);
void ce();
long int cd(long int);
void encrypt();
void decrypt();

void main() {
    printf("\nENTER FIRST PRIME NUMBER\n");
    scanf("%ld", &p);
    flag = prime(p);
    if(flag == 0) {
        printf("\nWRONG INPUT\n");
        exit(0);
    }
    printf("\nENTER ANOTHER PRIME NUMBER\n");
    scanf("%ld", &q);
    flag = prime(q);
    if(flag == 0 || p == q) {
        printf("\nWRONG INPUT\n");
        exit(0);
    }
    printf("\nENTER MESSAGE\n");
    fflush(stdin);
    scanf("%s", msg);
    for(i = 0; msg[i] != '\0'; i++)
        m[i] = msg[i];
    n = p * q;
    t = (p - 1) * (q - 1);
    ce();
    printf("\nPOSSIBLE VALUES OF e AND d ARE\n");
    for(i = 0; i < j - 1; i++)
        printf("\n%ld\t%ld", e[i], d[i]);
    encrypt();
    decrypt();
}

int prime(long int pr) {
    int i;
    j = sqrt(pr);
    for(i = 2; i <= j; i++) {
        if(pr % i == 0)
            return 0;
    }
    return 1;
}

void ce() {
    int k;
    k = 0;
    for(i = 2; i < t; i++) {
        if(t % i == 0)
            continue;
        flag = prime(i);
        if(flag == 1 && i != p && i != q) {
            e[k] = i;
            flag = cd(e[k]);
            if(flag > 0) {
                d[k] = flag;
                k++;
            }
            if(k == 99)
                break;
        }
    }
}

long int cd(long int x) {
    long int k = 1;
    while(1) {
        k = k + t;
        if(k % x == 0)
            return(k / x);
    }
}

void encrypt() {
    long int pt, ct, key = e[0], k, len;
    i = 0;
    len = strlen(msg);
    while(i != len) {
        pt = m[i];
        pt = pt - 96;
        k = 1;
        for(j = 0; j < key; j++) {
            k = k * pt;
            k = k % n;
        }
        temp[i] = k;
        ct = k + 96;
        en[i] = ct;
        i++;
    }
    en[i] = -1;
    printf("\nTHE ENCRYPTED MESSAGE IS\n");
    for(i = 0; en[i] != -1; i++)
        printf("%c", en[i]);
}

void decrypt() {
    long int pt, ct, key = d[0], k;
    i = 0;
    while(en[i] != -1) {
        ct = temp[i];
        k = 1;
        for(j = 0; j < key; j++) {
            k = k * ct;
            k = k % n;
        }
        pt = k + 96;
        m[i] = pt;
        i++;
    }
    m[i] = -1;
    printf("\nTHE DECRYPTED MESSAGE IS\n");
    for(i = 0; m[i] != -1; i++)
        printf("%c", m[i]);
        
}
```
# OUTPUT
![2](https://github.com/arulolia/lab-exercises/assets/122069938/c7d37882-8dcb-4b59-a110-da769bfd58a4)

# HILL CIPHER

```
#include <stdio.h>
#include <conio.h>
#include <string.h>
#include <ctype.h>

int main() {
    unsigned int keyMatrix[3][3] = {{6, 24, 1}, {13, 16, 10}, {20, 17, 15}};
    unsigned int inverseKeyMatrix[3][3] = {{8, 5, 10}, {21, 8, 21}, {21, 12, 8}};
    unsigned int encrypted[3], decrypted[3];
    char msg[20];
    
    printf("Enter plain text: ");
    scanf("%s", msg);

    // Encrypt the message
    printf("Encrypted Cipher Text:");
    for (int i = 0; i < strlen(msg); i++) {
        if (!isalpha(msg[i])) {
            // Skip non-alphabetic characters
            continue;
        }
        unsigned int letter = toupper(msg[i]) - 'A'; // Convert to uppercase and map to 0-25
        printf(" %c", msg[i]);
        encrypted[i] = 0;
        for (int j = 0; j < 3; j++) {
            encrypted[i] += keyMatrix[i % 3][j] * (letter % 26);
            letter /= 26;
        }
        encrypted[i] %= 26;
        printf(" %c", encrypted[i] + 'A'); // Convert back to ASCII
    }
    printf("\n");

    // Decrypt the message
    printf("Decrypted Plain Text:");
    for (int i = 0; i < 3; i++) {
        decrypted[i] = 0;
        for (int j = 0; j < 3; j++) {
            decrypted[i] += inverseKeyMatrix[i][j] * encrypted[j];
        }
        decrypted[i] %= 26;
        printf(" %c", decrypted[i] + 'A'); // Convert back to ASCII
    }
    printf("\n");

    getch();
    return 0;
}
```
# output:
![3](https://github.com/arulolia/lab-exercises/assets/122069938/65986739-0223-4874-9a08-5053d0eb90ef)

# Vigenere Cipher
```
#include<stdio.h>
#include<conio.h>
#include<ctype.h>
#include<string.h>

void encipher();
void decipher();

int main() {
    int choice;
    clrscr();
    while(1) {
        printf("\n1. Encrypt Text");
        printf("\t2. Decrypt Text");
        printf("\t3. Exit");
        printf("\n\nEnter Your Choice : ");
        scanf("%d", &choice);
        
        if(choice == 3)
            exit(0);
        else if(choice == 1)
            encipher();
        else if(choice == 2)
            decipher();
        else
            printf("Please Enter Valid Option.");
    }
}

void encipher() {
    unsigned int i, j;
    char input[50], key[10];
    printf("\n\nEnter Plain Text: ");
    scanf("%s", input);
    printf("\nEnter Key Value: ");
    scanf("%s", key);
    printf("\nResultant Cipher Text: ");
    for(i = 0, j = 0; i < strlen(input); i++, j++) {
        if(j >= strlen(key)) {
            j = 0;
        }
        printf("%c", 65 + (((toupper(input[i]) - 65) + (toupper(key[j]) - 65)) % 26));
    }
}

void decipher() {
    unsigned int i, j;
    char input[50], key[10];
    int value;
    printf("\n\nEnter Cipher Text: ");
    scanf("%s", input);
    printf("\n\nEnter the key value: ");
    scanf("%s", key);
    for(i = 0, j = 0; i < strlen(input); i++, j++) {
        if(j >= strlen(key)) {
            j = 0;
        }
        value = (toupper(input[i]) - 64) - (toupper(key[j]) - 64);
        if(value < 0) {
            value = value * -1;
        }
        printf("%c", 65 + (value % 26));
    }
}

```
# OUTPUT
![4](https://github.com/arulolia/lab-exercises/assets/122069938/27399dfa-1433-427b-bb61-d5e766384a71)

# IMPLEMENTATION OF DES

```
import javax.swing.*;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;

class DES {
    byte[] skey = new byte[1000];
    String skeyString;
    static byte[] raw;
    String inputMessage, encryptedData, decryptedMessage;

    public DES() {
        try {
            generateSymmetricKey();
            inputMessage = JOptionPane.showInputDialog(null, "Enter message to encrypt");
            byte[] ibyte = inputMessage.getBytes();
            byte[] ebyte = encrypt(raw, ibyte);
            encryptedData = new String(ebyte);
            System.out.println("Encrypted message " + encryptedData);
            JOptionPane.showMessageDialog(null, "Encrypted Data " + "\n" + encryptedData);
            byte[] dbyte = decrypt(raw, ebyte);
            decryptedMessage = new String(dbyte);
            System.out.println("Decrypted message " + decryptedMessage);
            JOptionPane.showMessageDialog(null, "Decrypted Data " + "\n" + decryptedMessage);
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    void generateSymmetricKey() {
        try {
            Random r = new Random();
            int num = r.nextInt(10000);
            String knum = String.valueOf(num);
            byte[] knumb = knum.getBytes();
            skey = getRawKey(knumb);
            skeyString = new String(skey);
            System.out.println("DES Symmetric key = " + skeyString);
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private static byte[] getRawKey(byte[] seed) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("DES");
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        kgen.init(56, sr);
        SecretKey skey = kgen.generateKey();
        raw = skey.getEncoded();
        return raw;
    }

    private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(clear);
        return encrypted;
    }

    private static byte[] decrypt(byte[] raw, byte[] encrypted) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return decrypted;
    }

    public static void main(String args[]) {
        DES des = new DES();
    }
}
```
# OUTPUT
![5](https://github.com/arulolia/lab-exercises/assets/122069938/3d56d95b-c411-43a9-84cc-4bd1a1fe0b88)


# IMPLEMENTATION OF RSA
```
#include<stdio.h>
#include<conio.h>
#include<stdlib.h>
#include<math.h>
#include<string.h>

long int p, q, n, t, flag, e[100], d[100], temp[100], j, m[100], en[100], i;
char msg[100];

int prime(long int);
void ce();
long int cd(long int);
void encrypt();
void decrypt();

void main() {
    clrscr();
    printf("\nENTER FIRST PRIME NUMBER\n");
    scanf("%d", &p);
    flag = prime(p);
    if (flag == 0) {
        printf("\nWRONG INPUT\n");
        getch();
    }

    printf("\nENTER ANOTHER PRIME NUMBER\n");
    scanf("%d", &q);
    flag = prime(q);
    if (flag == 0 || p == q) {
        printf("\nWRONG INPUT\n");
        getch();
    }

    printf("\nENTER MESSAGE\n");
    fflush(stdin);
    scanf("%s", msg);
    for (i = 0; msg[i] != NULL; i++)
        m[i] = msg[i];

    n = p * q;
    t = (p - 1) * (q - 1);
    ce();

    printf("\nPOSSIBLE VALUES OF e AND d ARE\n");
    for (i = 0; i < j - 1; i++)
        printf("\n%ld\t%ld", e[i], d[i]);

    encrypt();
    decrypt();
    getch();
}

int prime(long int pr) {
    int i;
    j = sqrt(pr);
    for (i = 2; i <= j; i++) {
        if (pr % i == 0)
            return 0;
    }
    return 1;
}

void ce() {
    int k;
    k = 0;
    for (i = 2; i < t; i++) {
        if (t % i == 0)
            continue;
        flag = prime(i);
        if (flag == 1 && i != p && i != q) {
            e[k] = i;
            flag = cd(e[k]);
            if (flag > 0) {
                d[k] = flag;
                k++;
            }
            if (k == 99)
                break;
        }
    }
}

long int cd(long int x) {
    long int k = 1;
    while (1) {
        k = k + t;
        if (k % x == 0)
            return (k / x);
    }
}

void encrypt() {
    long int pt, ct, key = e[0], k, len;
    i = 0;
    len = strlen(msg);
    while (i != len) {
        pt = m[i];
        pt = pt - 96;
        k = 1;
        for (j = 0; j < key; j++) {
            k = k * pt;
            k = k % n;
        }
        temp[i] = k;
        ct = k + 96;
        en[i] = ct;
        i++;
    }
    en[i] = -1;
    printf("\nTHE ENCRYPTED MESSAGE IS\n");
    for (i = 0; en[i] != -1; i++)
        printf("%c", en[i]);
}

void decrypt() {
    long int pt, ct, key = d[0], k;
    i = 0;
    while (en[i] != -1) {
        ct = temp[i];
        k = 1;
        for (j = 0; j < key; j++) {
            k = k * ct;
            k = k % n;
        }
        pt = k + 96;
        m[i] = pt;
        i++;
    }
    m[i] = -1;
    printf("\nTHE DECRYPTED MESSAGE IS\n");
    for (i = 0; m[i] != -1; i++)
        printf("%c", m[i]);
}
```
# OUTPUT
![6](https://github.com/arulolia/lab-exercises/assets/122069938/9fb5e502-f99e-43db-b3af-4a308e94de58)


# IMPLEMENTATION OF MD5
```
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

typedef union {
    unsigned w; 
    unsigned char b[4];
} MD5union;

typedef unsigned DigestArray[4];

unsigned func0(unsigned abcd[]) {
    return (abcd[1] & abcd[2]) | (~abcd[1] & abcd[3]);
}

unsigned func1(unsigned abcd[]) {
    return (abcd[3] & abcd[1]) | (~abcd[3] & abcd[2]);
}

unsigned func2(unsigned abcd[]) {
    return abcd[1] ^ abcd[2] ^ abcd[3];
}

unsigned func3(unsigned abcd[]) {
    return abcd[2] ^ (abcd[1] | ~abcd[3]);
}

typedef unsigned (*DgstFctn)(unsigned a[]);

unsigned *calctable(unsigned *k) {
    double s, pwr; 
    int i;
    pwr = pow(2, 32); 
    for (i = 0; i < 64; i++) {
        s = fabs(sin(1 + i));
        k[i] = (unsigned)(s * pwr);
    }
    return k;
}

unsigned rol(unsigned r, short N) {
    unsigned mask1 = (1 << N) - 1;
    return ((r >> (32 - N)) & mask1) | ((r << N) & ~mask1);
}

unsigned *md5(const char *msg, int mlen) {
    static DigestArray h0 = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
    static DgstFctn ff[] = { &func0, &func1, &func2, &func3};
    static short M[] = { 1, 5, 3, 7 };
    static short O[] = { 0, 1, 5, 0 };
    static short rot0[] = { 7,12,17,22};
    static short rot1[] = { 5, 9,14,20};
    static short rot2[] = { 4,11,16,23};
    static short rot3[] = { 6,10,15,21};
    static short *rots[] = {rot0, rot1, rot2, rot3 };
    static unsigned kspace[64];
    static unsigned *k;
    static DigestArray h;
    DigestArray abcd;
    DgstFctn fctn;
    short m, o, g;
    unsigned f;
    short *rotn;
    union {
        unsigned w[16];
        char    b[64];
    }mm;
    unsigned w[16]; 
    char    b[64];
    int os = 0;
    int grp, grps, q, p; 
    unsigned char *msg2;
    
    if (k == NULL) 
        k = calctable(kspace);
    for (q = 0; q < 4; q++) 
        h[q] = h0[q]; // initialize
    {
        grps = 1 + (mlen + 8) / 64; 
        msg2 = malloc(64 * grps); 
        memcpy(msg2, msg, mlen);
        msg2[mlen] = (unsigned char)0x80; 
        q = mlen + 1;
        while (q < 64 * grps) 
            msg2[q++] = 0;
        {
            MD5union u;
            u.w = 8 * mlen; 
            q -= 8;
            memcpy(msg2 + q, &u.w, 4);
        }
    }
    for (grp = 0; grp < grps; grp++) {
        memcpy(mm.b, msg2 + os, 64);
        for (q = 0; q < 4; q++) 
            abcd[q] = h[q]; 
        for (p = 0; p < 4; p++) {
            fctn = ff[p]; 
            rotn = rots[p];
            m = M[p]; 
            o = O[p];
            for (q = 0; q < 16; q++) {
                g = (m * q + o) % 16;
                f = abcd[1] + rol(abcd[0] + fctn(abcd) + k[q + 16 * p] + mm.w[g], rotn[q % 4]); 
                abcd[0] = abcd[3];
                abcd[3] = abcd[2];
                abcd[2] = abcd[1]; 
                abcd[1] = f;
            }
        }
        for (p = 0; p < 4; p++) 
            h[p] += abcd[p];
        os += 64;
    }
    return h;
}

void main() {
    int j, k;
    const char *msg = "The quick brown fox jumps over the lazy dog";
    unsigned *d = md5(msg, strlen(msg)); 
    MD5union u;
    printf("\t MD5 ENCRYPTION ALGORITHM IN C \n\n");
    printf("Input String to be Encrypted using MD5 :\n\t%s",msg);
    printf("\n\nThe MD5 code for input string is:\n\t= 0x");
    for (j = 0; j < 4; j++) {
        u.w = d[j];
        for (k = 0; k < 4; k++) 
            printf("%02x", u.b[k]);
    }
    printf("\n\nMD5 Encryption Successfully Completed!!!\n\n");
}
```
# OUTPUT
![7](https://github.com/arulolia/lab-exercises/assets/122069938/76f07b5d-8843-4456-b7d2-5c774beb7442)


# IMPLEMENTATION OF SHA-I
```
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Example {
    public static void main(String[] args) {
        String input = "Hello, World!"; // Input string
        String md5Hash = md5(input); // Compute MD5 hash

        System.out.println("MD5 hash of '" + input + "': " + md5Hash);
    }

    public static String md5(String input) {
        try {
            // Create MD5 MessageDigest instance
            MessageDigest md = MessageDigest.getInstance("MD5");

            // Update input string in message digest
            md.update(input.getBytes());

            // Generate MD5 hash bytes
            byte[] md5Bytes = md.digest();

            // Convert bytes to hexadecimal format
            StringBuilder sb = new StringBuilder();
            for (byte md5Byte : md5Bytes) {
                sb.append(Integer.toString((md5Byte & 0xff) + 0x100, 16).substring(1));
            }

            // Return the hexadecimal string representation of the MD5 hash
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // Handle NoSuchAlgorithmException if MD5 algorithm is not available
            e.printStackTrace();
            return null;
        }
    }
}
```
# OUTPUT
![8](https://github.com/arulolia/lab-exercises/assets/122069938/bfcff9f5-5cb2-4655-ac01-6ba27cf1ce5d)
