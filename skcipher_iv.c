#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <string.h>
#include <errno.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifdef SOL_ALG
#define SOL_ALG 279
#endif

extern errno;
int main(void)
{
    int opfd;
    int tfmfd;
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_name = "cbc(aes)",
        .salg_type = "skcipher",

    };
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {0}; //CMSG_SPACE 8 byte align, len(cbuf) = CMSG_ALIGN(sizeof(cmsg_len) + sizeof(cmsg_level) + sizeof(cmsg_type) + len(cmsg_data))
    char buf[18];
    struct af_alg_iv *iv;
    struct iovec iov;
    int i;
    //char plaintext_buf[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x10, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x90, 0x11};
    char plaintext_buf[] = "Single block msg";
    char key_buf[] = {0xff, 0xd7, 0x40, 0x57, 0x47, 0x68, 0x5e, 0xd6, 0xe0, 0x0b, 0xc6, 0x82, 0xa7, 0x72, 0x86, 0x09};
    char iv_buf[] = {0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30, 0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41};
    int error;

    tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);//TCP
    bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
    error = setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key_buf, sizeof(key_buf));
    if (error)
    {
        printf("bind error\n");
        goto bind_err;
    }
    opfd = accept(tfmfd, NULL, 0);
    if (opfd == -1)
    {
        printf("accept err\n");
        goto accept_err;
    }

    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(4);
    *(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

    cmsg = CMSG_NXTHDR(&msg,cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(20);
    iv = (void *)CMSG_DATA(cmsg);
    iv->ivlen = 16;
    memcpy(iv->iv,iv_buf,16);

    iov.iov_base = plaintext_buf;
    iov.iov_len = sizeof(plaintext_buf);

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    sendmsg(opfd,&msg,0);
    //read(opfd,buf,16);
    error = recv(opfd, buf, 16, 0);
    if (error == -1){
	    perror("recv error:");
	    goto recv_err;
    }

    for (i=0; i < 16; i++)
    {
        printf("%x ",(unsigned char)buf[i]);
    }
    putchar('\n');

accept_err:
bind_err:
recv_err:
    close(tfmfd);
    close(opfd);

    return 0;
}
