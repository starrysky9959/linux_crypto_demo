#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

extern errno;

void print(char* src, int len)
{

    int i;
    for (i=0; i < len; i++)
    {
        printf("%x",(unsigned char)src[i]);
    }
    putchar('\n');
}


int setkey(int fd, char* key,int keylen)
{
    int err = setsockopt(fd, SOL_ALG, ALG_SET_KEY, key, keylen);
    if (err)
    {
        perror("setkey err");
        goto out;
    }
out:
    err = errno;
    return err;
}

int sendmsg_to_crypto(int opfd, int cmsg_type, int cmsg_data, char* plaintext_buf, int buflen)
{
    struct msghdr msg = {};
    //struct cmsghdr *cmsg = malloc(CMSG_SPACE(sizeof(cmsg_data)));
    struct cmsghdr *cmsg = NULL;
    char buff[CMSG_SPACE(sizeof(cmsg_data))] = {0};
    struct iovec iov;
    int err;



    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buff;
    msg.msg_controllen = sizeof(buff);

    cmsg = CMSG_FIRSTHDR(&msg);

    
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = cmsg_type;
    cmsg->cmsg_len = CMSG_SPACE(sizeof(cmsg_data));
    //memcpy(CMSG_DATA(cmsg), &cmsg_data, sizeof(cmsg_data));
    *(__u32 *)CMSG_DATA(cmsg) = cmsg_data;

    iov.iov_base = plaintext_buf;
    iov.iov_len = buflen;

    err = sendmsg(opfd, &msg, 0);
    
    if (err == -1)
    {
        perror("sendmsg err");
        goto out;
    }
    else
        return err;
out:
    err = errno;
    return err;


}


int sendmsg_to_crypto_de(int opfd, int cmsg_type, int cmsg_data, char* plaintext_buf, int buflen)
{
    struct msghdr msg = {};
    //struct cmsghdr *cmsg = malloc(CMSG_SPACE(sizeof(cmsg_data)));
    struct cmsghdr *cmsg = NULL;
    char buff[CMSG_SPACE(sizeof(cmsg_data))] = {0};
    struct iovec iov;
    int err;



    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buff;
    msg.msg_controllen = sizeof(buff);

    cmsg = CMSG_FIRSTHDR(&msg);

    
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = cmsg_type;
    cmsg->cmsg_len = CMSG_SPACE(sizeof(cmsg_data));
    //memcpy(CMSG_DATA(cmsg), &cmsg_data, sizeof(cmsg_data));
    *(__u32 *)CMSG_DATA(cmsg) = ALG_OP_DECRYPT;

    iov.iov_base = plaintext_buf;
    iov.iov_len = buflen;

    err = sendmsg(opfd, &msg, 0);
    
    if (err == -1)
    {
        perror("sendmsg err");
        goto out;
    }
    else
        return err;
out:
    err = errno;
    return err;


}

int recvmsg_from_crypto(int opfd, char* src, int len)
{

    struct msghdr msg = {};
    struct iovec iov;
    int err;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    iov.iov_base = src;
    iov.iov_len = len - 1;


    err = recvmsg(opfd, &msg,  0);
    if (err == -1)
    {
        perror("recvmsg err");
        goto out;
    }
    else
    {

        print(src,len);
        return err;

    }


out:
    err = errno;
    return err;
}

int main(void)
{

    
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "skcipher",
        .salg_name = "ecb(aes)",
    };
    char key_buf[] = {0xff, 0xd7, 0x40, 0x57, 0x47, 0x68, 0x5e, 0xd6, 0xe0, 0x0b, 0xc6, 0x82, 0xa7, 0x72, 0x86, 0x09};
    //char plaintext_buf[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x90, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xf0, 0x11};
    char plaintext_buf[] = "Single block msgSingle block msg";
    char encrypt_buf[32] = {0};
    char decrypt_buf[32] = {0};
    int tfmfd;
    int opfd;
    int err;
    tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    err = bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
    if (err)
    {
        perror("bind err");
        goto bind_err;
    }

    err = setkey(tfmfd, key_buf, sizeof(key_buf));
    if (err)
    {
        goto setkey_err;
    }

    opfd = accept(tfmfd, NULL, 0);
    if (opfd == -1)
    {
        perror("accept err");
    }
    //encrypt

    err = sendmsg_to_crypto(opfd, ALG_SET_OP, ALG_OP_ENCRYPT, plaintext_buf, sizeof(plaintext_buf));

    if (err == -1)
    {
        goto sendmsg_err;
    }
    
    err = recvmsg_from_crypto(opfd, encrypt_buf, sizeof(plaintext_buf));
    if (err == -1)
    {
        goto recv_err;
    }
    close(tfmfd);
    close(opfd);

    // new section

    tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    err = bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
    if (err)
    {
        perror("bind err");
        goto bind_err;
    }

    err = setkey(tfmfd, key_buf, sizeof(key_buf));
    if (err)
    {
        goto setkey_err;
    }

    opfd = accept(tfmfd, NULL, 0);
    if (opfd == -1)
    {
        perror("accept err");
    }
    // print(plaintext_buf, sizeof(plaintext_buf));

    err = sendmsg_to_crypto(opfd, ALG_SET_OP, ALG_OP_DECRYPT, encrypt_buf, sizeof(encrypt_buf));

    if (err == -1)
    {
        goto sendmsg_err;
    }
    
    err = recvmsg_from_crypto(opfd, decrypt_buf, sizeof(encrypt_buf));
    if (err == -1)
    {
        goto recv_err;
    }


    for (int i=0; i < sizeof(decrypt_buf); i++)
    {
        printf("%c",decrypt_buf[i]);
    }
 
    close(tfmfd);
    close(opfd);

bind_err:
setkey_err:
    close(tfmfd);
accept_err:
sendmsg_err:
recv_err:
    close(tfmfd);
    close(opfd);

    return 0;
}
