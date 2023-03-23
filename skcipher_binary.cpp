#include <errno.h>
#include <fstream>
#include <iostream>
#include <linux/if_alg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

extern errno;

void print(char *src, int len) {

  int i;
  for (i = 0; i < len; i++) {
    printf("%x", (unsigned char)src[i]);
  }
  putchar('\n');
}

int setkey(int fd, char *key, int keylen) {
  int err = setsockopt(fd, SOL_ALG, ALG_SET_KEY, key, keylen);
  if (err) {
    perror("setkey err");
    goto out;
  }
out:
  err = errno;
  return err;
}

int sendmsg_to_crypto(int opfd, int cmsg_type, int cmsg_data,
                      char *plaintext_buf, int buflen) {
  struct msghdr msg = {};
  // struct cmsghdr *cmsg = malloc(CMSG_SPACE(sizeof(cmsg_data)));
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
  // memcpy(CMSG_DATA(cmsg), &cmsg_data, sizeof(cmsg_data));
  *(__u32 *)CMSG_DATA(cmsg) = cmsg_data;

  iov.iov_base = plaintext_buf;
  iov.iov_len = buflen;

  err = sendmsg(opfd, &msg, 0);

  if (err == -1) {
    perror("sendmsg err");
    goto out;
  } else
    return err;
out:
  err = errno;
  return err;
}

int recvmsg_from_crypto(int opfd, char *src, int len) {

  struct msghdr msg = {};
  struct iovec iov;
  int err;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  iov.iov_base = src;
  iov.iov_len = len - 1;

  err = recvmsg(opfd, &msg, 0);
  if (err == -1) {
    perror("recvmsg err");
    goto out;
  } else {

    print(src, len);
    return err;
  }

out:
  err = errno;
  return err;
}

std::vector<char> read_bin_file(const std::string &file_name) {
  std::ifstream file(file_name, std::ios::binary | std::ios::ate);
  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<char> buffer(size);
  if (file.read(buffer.data(), size)) {
    return buffer;
  }
  return buffer;
}

void write_bin_file(const char *buf, int len) {
  std::ofstream file("new_demo", std::ios::binary);
  file.write(buf, len);
  file.close();
}

int main(void) {
  auto binary_buf = read_bin_file("./demo");
  print(binary_buf.data(), binary_buf.size());

  //   return 0;
  struct sockaddr_alg sa = {
      .salg_family = AF_ALG,
      .salg_type = {'s', 'k', 'c', 'i', 'p', 'h', 'e', 'r', 0},
      .salg_name = {'e', 'c', 'b', '(', 'a', 'e', 's', ')', 0},
  };

  //   char key_buf[] = reinterpret_cast<char*>(buffer.data());
  //   std::cout << std::endl;
  //   std::cout << *key_buf<<sizeof(key_buf);

  char key_buf[] = {0xff, 0xd7, 0x40, 0x57, 0x47, 0x68, 0x5e, 0xd6,
                    0xe0, 0x0b, 0xc6, 0x82, 0xa7, 0x72, 0x86, 0x09};
  // char plaintext_buf[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  // 0x99, 0x90, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xf0, 0x11};
  char plaintext_buf[] = "Single block msgSingle block msg";
  char encrypt_buf[17352] = {0};
  char decrypt_buf[17352] = {0};
  int tfmfd;
  int opfd;
  int err;

  //   encrypt
  {
    tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    err = bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
    if (err) {
      perror("bind err");
      goto bind_err;
    }

    err = setkey(tfmfd, key_buf, sizeof(key_buf));
    if (err) {
      goto setkey_err;
    }

    opfd = accept(tfmfd, NULL, 0);
    if (opfd == -1) {
      perror("accept err");
    }

    err = sendmsg_to_crypto(opfd, ALG_SET_OP, ALG_OP_ENCRYPT, binary_buf.data(),
                            binary_buf.size());

    if (err == -1) {
      goto sendmsg_err;
    }

    err = recvmsg_from_crypto(opfd, encrypt_buf, binary_buf.size());

    if (err == -1) {
      goto recv_err;
    }

    close(tfmfd);
    close(opfd);
  }

  // decrypt
  {
    tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    err = bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
    if (err) {
      perror("bind err");
      goto bind_err;
    }

    err = setkey(tfmfd, key_buf, sizeof(key_buf));
    if (err) {
      goto setkey_err;
    }

    opfd = accept(tfmfd, NULL, 0);
    if (opfd == -1) {
      perror("accept err");
    }

    err = sendmsg_to_crypto(opfd, ALG_SET_OP, ALG_OP_DECRYPT, encrypt_buf,
                            binary_buf.size());

    if (err == -1) {
      goto sendmsg_err;
    }

    err = recvmsg_from_crypto(opfd, decrypt_buf, binary_buf.size());
    write_bin_file(decrypt_buf, binary_buf.size());
    if (err == -1) {
      goto recv_err;
    }

    close(tfmfd);
    close(opfd);
  }

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
