/*
 *
 *
 *
 * O objetivo é reescrever a lógica de encriptação e decriptação como a anterior.
 * A função agora é encriptar e decritar arquivos ao invés de pequenos texto.
 * Deve se utilizar chunks de memória de 1024bytes tanto para a memória quanto para escrita.
 *
 * O algoritmo continuará sendo o ChaCha20.
 * Em outro momento, eu o implemente na mão.
 *
 *
 *
 */

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

#include<openssl/evp.h>
#include<openssl/kdf.h>
#include<openssl/rand.h>

#define CHUNK 1024
#define KEY 32
#define IV 12
#define SALT 16

#define INFILE "passwords.csv"
#define OUTFILE "passwords.enc"

int write_csv(char *servico, char *usr, char *password);
int encrypt_file(const char *master);
int generate_key(const char *master, unsigned char *store, const unsigned char *salt);
int decrypt_file(const char *master);

int main(int argc, char **argv) {
    char master[128];
    if (argc == 4) {
        printf("Digite a senha do arquivo: ");
        
        if (fgets(master, sizeof(master), stdin)) {
            master[strcspn(master, "\n")] = 0;
        }

        if (access(OUTFILE, F_OK) == 0) {
            decrypt_file(master);
        }

        write_csv(argv[1], argv[2], argv[3]);
        
        encrypt_file(master);
        
        printf("Senha salva. Serviço: %s - Senha: %s\n", argv[1], argv[2]);

    } else if (argc == 1) {
        printf("Digite a senha do arquivo: ");
        
        if (fgets(master, sizeof(master), stdin)) {
            master[strcspn(master, "\n")] = 0;
        }

        decrypt_file(master);

    } else {
        printf("Uso: save <nome_do_serviço> <senha_do_serviço>.\n");
    }

    return 0;
}

int write_csv(char *servico, char *usr, char *password) {
    //Escrver em chunks o arquivo csv.
    //Separador é a vírgula e ponto e vígula ao final de cada entrada
    //ex:
    //  nome_do_serviço, usuario, senha;
    //  google, google1234;
    
    char *csv_header = "serviço|usuario|senha\n";

    char to_write[CHUNK];
    snprintf(to_write, sizeof(to_write), "%s|%s|%s\n", servico, usr, password);
    
    FILE *fp;

    if (access(INFILE, F_OK) == -1) {
        fp = fopen(INFILE, "w");
        fputs(csv_header, fp);

        fputs(to_write, fp);
        fclose(fp);
    } else {
        fp = fopen(INFILE, "a");
        fputs(to_write, fp);

        fclose(fp);
    }

    return 0;
}

int read_csv() {
    return 0;
}

int encrypt_file(const char *master) {
    FILE *in, *out;
    unsigned char kdf[KEY];
    unsigned char iv[IV];
    unsigned char salt[SALT]; 
    unsigned char inbuf[CHUNK];
    unsigned char outbuf[CHUNK + EVP_MAX_BLOCK_LENGTH];

    int inlen, outlen;

    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher;

    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(NULL, "ChaCha20", NULL);

    //Gerar IV
    if (!RAND_bytes(iv, IV)) {
        perror("Erro ao gerar IV\n");
        return -1;
    }

    //Gerar SALT
    if (!RAND_bytes(salt, SALT)) {
        perror("Erro ao gerar salt\n");
        return -1;
    }

    generate_key(master, (unsigned char *)kdf, salt);
    if (!EVP_EncryptInit_ex2(ctx, cipher, kdf, iv, NULL)) {
        perror("Erro em init_ex2\n");

        EVP_CIPHER_CTX_free(ctx);

        return -1;
    }


    in = fopen(INFILE, "rb");
    out = fopen(OUTFILE, "wb");

    if (in == NULL || out == NULL) {
        perror("Error no arquivo\n");
    }

    fwrite(salt, 1, SALT, out);
    fwrite(iv, 1, IV, out);

    while ((inlen = fread(inbuf, 1, CHUNK, in)) > 0) {
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            perror("Erro em CipherUpdate\n");

            EVP_CIPHER_CTX_free(ctx);

            return -1;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if(!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        perror("Erro em CipherFinal\n");

        EVP_CIPHER_CTX_free(ctx);

        return -1;
    }
    fwrite(outbuf, 1, outlen, out);
    
    fclose(out);
    fclose(in);

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(kdf, KEY);
    return 0;
}

int decrypt_file(const char *master) {
    FILE *in, *out;
    unsigned char kdf[KEY];
    unsigned char iv[IV];
    unsigned char salt[SALT]; 
    unsigned char inbuf[CHUNK];
    unsigned char outbuf[CHUNK + EVP_MAX_BLOCK_LENGTH];

    int inlen, outlen;

    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher;

    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(NULL, "ChaCha20", NULL);

    in = fopen(OUTFILE, "rb");
    out = fopen(INFILE, "wb");
    fread(salt, 1, SALT, in);
    fread(iv, 1, IV, in);

    generate_key(master, (unsigned char *)kdf, salt);
    if (!EVP_DecryptInit_ex2(ctx, cipher, kdf, iv, NULL)) {
        perror("Erro em init_ex2\n");

        EVP_CIPHER_CTX_free(ctx);

        return -1;
    }
 
    while ((inlen = fread(inbuf, 1, CHUNK, in)) > 0) {
        if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            perror("Erro em CipherUpdate\n");

            EVP_CIPHER_CTX_free(ctx);

            return -1;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if(!EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) {
        perror("Erro em CipherFinal\n");

        EVP_CIPHER_CTX_free(ctx);

        return -1;
    }
    fwrite(outbuf, 1, outlen, out);
    
    fclose(out);
    fclose(in);

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(kdf, KEY);
    
    return 0;
}

int generate_key(const char *master, unsigned char *store, const unsigned char *salt) {
    if (!PKCS5_PBKDF2_HMAC(master, strlen(master), 
                salt, SALT, 600000, 
                EVP_sha3_256(), KEY, store)) {

        perror("Erro ao gerar KDF\n");

        return -1;
    }

    return 0;
}

