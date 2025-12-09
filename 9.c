1)
#include <stdio.h>
void caesar(char text[], int shift) {
    for (int i = 0; text[i] != '\0'; ++i) {
        if (text[i] >= 'a' && text[i] <= 'z')
            text[i] = 'a' + (text[i] - 'a' + shift) % 26;
        else if (text[i] >= 'A' && text[i] <= 'Z')
            text[i] = 'A' + (text[i] - 'A' + shift) % 26;
    }
}

int main() {
    char message[] = "hello how are u";
    int key = 3;

    printf("Original message: %s\n", message);

    // Encryption
    caesar(message, key);
    printf("Encrypted message: %s\n", message);

    // Decryption
    caesar(message, -key);
    printf("Decrypted message: %s\n", message);

    return 0;
}


2)
#include <stdio.h>
#include <ctype.h>
#include <string.h>

int main() {
    char plaintext[] = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG";
    char key[] = "QWERTYUIOPASDFGHJKLZXCVBNM";
    char ciphertext[100], decrypted[100];
    int i, j;

    printf("Plaintext: %s\n", plaintext);

    // Encrypt
    for (i = 0; plaintext[i] != '\0'; i++) {
        char ch = plaintext[i];
        if (ch >= 'A' && ch <= 'Z') {
            ciphertext[i] = key[ch - 'A'];
        } else {
            ciphertext[i] = ch; // Keep spaces
        }
    }
    ciphertext[i] = '\0';
    printf("Ciphertext: %s\n", ciphertext);

    // Decrypt
    for (i = 0; ciphertext[i] != '\0'; i++) {
        char ch = ciphertext[i];
        if (ch >= 'A' && ch <= 'Z') {
            for (j = 0; j < 26; j++) {
                if (key[j] == ch) {
                    decrypted[i] = 'A' + j;
                    break;
                }
            }
        } else {
            decrypted[i] = ch; // Keep spaces
        }
    }
    decrypted[i] = '\0';
    printf("Decrypted text: %s\n", decrypted);

    return 0;

}


3)
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define SIZE 5

int findRow(char matrix[SIZE][SIZE], char ch) {
    for (int i = 0; i < SIZE; i++)
        for (int j = 0; j < SIZE; j++)
            if (matrix[i][j] == ch)
                return i;
    return -1;
}

int findCol(char matrix[SIZE][SIZE], char ch) {
    for (int i = 0; i < SIZE; i++)
        for (int j = 0; j < SIZE; j++)
            if (matrix[i][j] == ch)
                return j;
    return -1;
}

int main() {
    char key[30], msg[100], matrix[SIZE][SIZE];
    int used[26] = {0}, i, j, k = 0;
    char ch;

    printf("Enter the key: ");
    gets(key);

    printf("Enter the message to encrypt: ");
    gets(msg);

    // --- Step 1: Build 5x5 key matrix ---
    for (i = 0; key[i] != '\0'; i++) {
        ch = toupper(key[i]);
        if (ch == 'J') ch = 'I';
        if (ch >= 'A' && ch <= 'Z' && !used[ch - 'A']) {
            matrix[k / 5][k % 5] = ch;
            used[ch - 'A'] = 1;
            k++;
        }
    }
    for (ch = 'A'; ch <= 'Z'; ch++) {
        if (ch == 'J') continue;
        if (!used[ch - 'A']) {
            matrix[k / 5][k % 5] = ch;
            used[ch - 'A'] = 1;
            k++;
        }
    }

    printf("\nPlayfair Key Matrix:\n");
    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++)
            printf("%c ", matrix[i][j]);
        printf("\n");
    }

    // --- Step 2: Encrypt message ---
    printf("\nEncrypted Message: ");
    for (i = 0; i < strlen(msg); i += 2) {
        char a = toupper(msg[i]);
        char b = toupper(msg[i + 1]);
        if (a == 'J') a = 'I';
        if (b == 'J' || b == '\0') b = 'X';
        if (a == b) b = 'X';

        int r1 = findRow(matrix, a);
        int c1 = findCol(matrix, a);
        int r2 = findRow(matrix, b);
        int c2 = findCol(matrix, b);

        if (r1 == r2)
            printf("%c%c", matrix[r1][(c1 + 1) % 5], matrix[r2][(c2 + 1) % 5]);
        else if (c1 == c2)
            printf("%c%c", matrix[(r1 + 1) % 5][c1], matrix[(r2 + 1) % 5][c2]);
        else
            printf("%c%c", matrix[r1][c2], matrix[r2][c1]);
    }

    printf("\n");
    return 0;
}

output
Enter the key: MONARCHY
Enter the message to encrypt: INSTRUMENTS

Playfair Key Matrix:
M O N A R
C H Y B D
E F G I K
L P Q S T
U V W X Z

Encrypted Message: GATLMZCLRQXA














4)
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define SIZE 2   // using 2x2 key matrix for simplicity

int main() {
    int key[SIZE][SIZE];
    char message[100];
    int len, i, j, k;

    printf("Enter 2x2 key matrix (row-wise):\n");
    for (i = 0; i < SIZE; i++)
        for (j = 0; j < SIZE; j++)
            scanf("%d", &key[i][j]);

    printf("Enter message (only letters): ");
    scanf("%s", message);

    // Convert to uppercase
    len = strlen(message);
    for (i = 0; i < len; i++) {
        message[i] = toupper(message[i]);
        if (message[i] < 'A' || message[i] > 'Z')
            message[i] = 'X';
    }

    // Pad with 'X' if odd length
    if (len % 2 != 0) {
        message[len] = 'X';
        message[len + 1] = '\0';
        len++;
    }

    printf("\nEncrypted Message: ");

    // Encrypt 2 letters at a time
    for (i = 0; i < len; i += 2) {
        int P[2], C[2] = {0};

        P[0] = message[i] - 'A';
        P[1] = message[i + 1] - 'A';

        for (j = 0; j < SIZE; j++) {
            for (k = 0; k < SIZE; k++) {
                C[j] += key[j][k] * P[k];
            }
            C[j] %= 26;
        }

        printf("%c%c", C[0] + 'A', C[1] + 'A');
    }

    printf("\n");
    return 0;
}


5)
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main() {
    char plaintext[] = "wearediscoveredsaveyourself";
    char key[] = "deceptive";
    char encrypted[100], decrypted[100];
    int i, j, textLen, keyLen;

    textLen = strlen(plaintext);
    keyLen = strlen(key);

    // Encryption 
    for (i = 0, j = 0; i < textLen; i++) {
        encrypted[i] = ((tolower(plaintext[i]) - 'a' + tolower(key[j]) - 'a') % 26) + 'a';
        j = (j + 1) % keyLen;  // repeat key
    }
    encrypted[i] = '\0';

    // Decryption
    for (i = 0, j = 0; i < textLen; i++) {
        decrypted[i] = ((tolower(encrypted[i]) - 'a' - (tolower(key[j]) - 'a') + 26) % 26) + 'a';
        j = (j + 1) % keyLen;
    }
    decrypted[i] = '\0';

    printf("Plaintext : %s\n", plaintext);
    printf("Key       : %s\n", key);
    printf("Encrypted : %s\n", encrypted);
    printf("Decrypted : %s\n", decrypted);

    return 0;
}


6)
#include <stdio.h>

int main() {
    int p = 3, q = 11;            // prime numbers
    int n = p * q;                // n = 33
    int phi = (p - 1) * (q - 1);  // phi = 20
    int e = 7;                    // public key
    int d = 3;                    // private key
    int msg = 9;                  // message (as number)
    int c, m;

    // Encryption: c = (msg ^ e) % n
    c = 1;
    for (int i = 0; i < e; i++)
        c = (c * msg) % n;

    // Decryption: m = (c ^ d) % n
    m = 1;
    for (int i = 0; i < d; i++)
        m = (m * c) % n;

    printf("Original Message : %d\n", msg);
    printf("Encrypted Message: %d\n", c);
    printf("Decrypted Message: %d\n", m);

    return 0;
}



7)

#include <stdio.h>

// Function to calculate (base^power) % mod
int power(int base, int power, int mod) {
    int result = 1;
    for (int i = 1; i <= power; i++) {
        result = (result * base) % mod;
    }
    return result;
}

int main() {
    int p = 23;   // Prime number (public)
    int g = 5;    // Base value (public)

    int a = 6;    // Client private key
    int b = 15;   // Server private key

    // Public keys
    int A = power(g, a, p);  // Client sends to Server
    int B = power(g, b, p);  // Server sends to Client

    // Shared secret keys
    int clientKey = power(B, a, p);
    int serverKey = power(A, b, p);

    printf("Prime (p) : %d\n", p);
    printf("Base (g)  : %d\n\n", g);

    printf("Client Public Key (A) : %d\n", A);
    printf("Server Public Key (B) : %d\n\n", B);

    printf("Client Secret Key : %d\n", clientKey);
    printf("Server Secret Key : %d\n", serverKey);

    if (clientKey == serverKey)
        printf("\nSecure Channel Established Successfully \n");
    else
        printf("\nSecure Channel Failed \n");

    return 0;

}



8)
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>

int main() {
    // Original Message
    unsigned char message[32] = "welcome to ISE";
    unsigned char encrypted[32];
    unsigned char decrypted[32];

    // 128-bit AES Key
    unsigned char key[16] = "networksecurity";

    AES_KEY encryptKey, decryptKey;

    // Set Encryption Key
    AES_set_encrypt_key(key, 128, &encryptKey);

    // Encrypt the message
    AES_encrypt(message, encrypted, &encryptKey);

    printf("Original Message  : %s\n", message);

    printf("Encrypted Message : ");
    for (int i = 0; i < 16; i++)
        printf("%x ", encrypted[i]);

    // Set Decryption Key
    AES_set_decrypt_key(key, 128, &decryptKey);

    // Decrypt the message
    AES_decrypt(encrypted, decrypted, &decryptKey);

    printf("\nDecrypted Message : %s\n", decrypted);

    return 0;
}


running command  for 8

gcc z.c -o z -lcrypto
./z























}

