/* Opal RC6
 * 32-bit
 * for Unix
 * written in August 2019 by DonaldET3
 */


/* pieces section */

#include <errno.h>
/* errno
 */

#include <stdio.h>
/* fputs()
 * puts()
 * printf()
 * fprintf()
 * sscanf()
 * getchar()
 * getc()
 * putc()
 * getline()
 * getdelim()
 * fwrite()
 * fopen()
 * fclose()
 * FILE
 * EOF
 * stdin
 * stdout
 * stderr
 */

#include <stdlib.h>
/* malloc()
 * calloc()
 * realloc()
 * free()
 * exit()
 * size_t
 * NULL
 * EXIT_SUCCESS
 * EXIT_FAILURE
 */

#include <string.h>
/* strlen()
 * strtok()
 * strerror_l()
 */

#include <stdint.h>
/* uint8_t
 * uint32_t
 * uintmax_t
 */

#include <stdbool.h>
/* bool
 * true
 * false
 */

#include <locale.h>
/* uselocale()
 */

#include <unistd.h>
/* getopt()
 * access()
 * F_OK
 */


/* definitions section */

/* ORC6-32 */
uint8_t magic[] = {0x4F, 0x52, 0x43, 0x36, 0x2D, 0x33, 0x32, 0x00};

/* cipher parameters */
struct cipher_params {
 /* number of rounds */
 uintmax_t rounds;
 /* counter block */
 uint32_t counter[4];
 /* round keys */
 uint32_t *r_keys;
};

/* text input buffer */
char *i_buf;
/* buffer size */
size_t ib_s;


/* functions section */

/* print error message and quit */
void fail(char *message)
{
 /* print error message */
 fputs(message, stderr);
 /* elaborate on the error if possible */
 if(errno) fprintf(stderr, ": %s", strerror_l(errno, uselocale((locale_t)0)));
 putc('\n', stderr);
 exit(EXIT_FAILURE);
}

/* "failed to" <error message> and quit */
void failed(char *message)
{
 /* prepend "failed to" to the error message */
 fputs("failed to ", stderr);
 fail(message);
}

/* print help */
void help()
{
 char message[] = "Opal RC6\n"
 "32-bit\n\n"
 "options\n"
 "h: output help and exit\n"
 "d: decryption mode\n"
 "e: re-encryption mode\n"
 "r: number of rounds to encrypt file data (default: 34)\n"
 "x: password and nonce input are interpreted as hexadecimal\n\n"
 "By default, the program is in encryption mode.\n";
 fputs(message, stderr);
}

/* bad command line value */
void invalid(char c)
{
 fprintf(stderr, "value supplied to -%c is invalid\n", c);
 exit(EXIT_FAILURE);
}

/* allocate space and put an input line in it */
char *input_line()
{
 size_t space = 0;
 char *line = NULL;

 if(getline(&line, &space, stdin) == -1) failed("read input line");
 strtok(line, "\n");
 return line;
}

/* write hexadecimal number */
void write_number(uintmax_t x, FILE *fp)
{
 if(fprintf(fp, "%jX", x) < 0) failed("write number value");
 if(putc('\0', fp) == EOF) failed("write number terminator");
 return;
}

/* read hexadecimal number */
uintmax_t read_number(FILE *fp)
{
 uintmax_t x;
 if(getdelim(&i_buf, &ib_s, '\0', fp) == -1) failed("read number");
 if(sscanf(i_buf, "%jx", &x) != 1) failed("comprehend number");
 return x;
}

/* read little-endian word */
uint32_t read_word(FILE *fp)
{
 int i, c;
 uint32_t x = 0;

 for(i = 0; i < 4; i++)
 {
  if((c = getc(fp)) == EOF) failed("read word");
  x |= ((uint32_t)c) << (i * 8);
 }

 return x;
}

/* write a block of little-endian words */
void write_block(uint32_t *x, FILE *fp)
{
 int i, j;

 for(i = 0; i < 4; i++)
  for(j = 0; j < 4; j++)
   if(putc(0xFF & (x[i] >> (j * 8)), fp) == EOF)
    failed("write block");

 return;
}

/* write a partial block of plaintext bytes */
void write_last_block(uint32_t *x, FILE *fp)
{
 int i, end;

 /* find the last byte in the block */
 for(end = 15; end > 0; end--)
  if((x[end / 4] >> ((end % 4) * 8)) & 0xFF)
   break;

 /* write the bytes that contain data */
 for(i = 0; i < end; i++)
  if(putc((x[i / 4] >> ((i % 4) * 8)) & 0xFF, fp) == EOF)
   failed("write last block");

 return;
}

/* read a block of little-endian words */
bool read_block(uint32_t *x, FILE *fp)
{
 int i, j, c;

 /* clear block */
 for(i = 0; i < 4; i++) x[i] = 0;

 /* for each word */
 for(i = 0; i < 4; i++)
  /* for each byte */
  for(j = 0; j < 4; j++)
  {
   /* if end of file, terminate data with a single set bit */
   if((c = getc(fp)) == EOF)
   {
    x[i] |= ((uint32_t)0x80) << (j * 8);
    return false;
   }
   /* add byte to the word */
   x[i] |= ((uint32_t)c) << (j * 8);
  }

 return true;
}

/* rotate left */
uint32_t rot_l(uint32_t x, uint32_t n)
{
 n &= 0x1F;
 return (x << n) | (x >> (32 - n));
}

/* rotate right */
uint32_t rot_r(uint32_t x, uint32_t n)
{
 n &= 0x1F;
 return (x >> n) | (x << (32 - n));
}

/* RC6 encryption */
void encrypt(uint32_t *block, uintmax_t r, uint32_t *s)
{
 uintmax_t i;
 uint32_t a, b, c, d, t, u, tmp;

 /* pre-whitening */
 a = block[0];
 b = block[1] + s[0];
 c = block[2];
 d = block[3] + s[1];

 for(i = 1; i <= r; i++)
 {
  /* t = (B * (2B + 1)) <<< log2(w) */
  t = rot_l(b * ((b << 1) | 1), 5);
  /* u = (D * (2D + 1)) <<< log2(w) */
  u = rot_l(d * ((d << 1) | 1), 5);
  /* A = ((A XOR t) <<< u) + S[2i] */
  a = rot_l(a ^ t, u) + s[i << 1];
  /* C = ((C XOR u) <<< t) + S[2i + 1] */
  c = rot_l(c ^ u, t) + s[(i << 1) | 1];
  /* (A, B, C, D) = (B, C, D, A) */
  tmp = a; a = b; b = c; c = d; d = tmp;
 }

 /* post-whitening */
 block[0] = a + s[(r * 2) + 2];
 block[1] = b;
 block[2] = c + s[(r * 2) + 3];
 block[3] = d;

 return;
}

/* RC6 decryption */
void decrypt(uint32_t *block, uintmax_t r, uint32_t *s)
{
 uintmax_t i;
 uint32_t a, b, c, d, t, u, tmp;

 /* remove post-whitening */
 d = block[3];
 c = block[2] - s[(r * 2) + 3];
 b = block[1];
 a = block[0] - s[(r * 2) + 2];

 for(i = r; i; i--)
 {
  /* (A, B, C, D) = (D, A, B, C) */
  tmp = d; d = c; c = b; b = a; a = tmp;
  /* u = (D * (2D + 1)) <<< log2(w) */
  u = rot_l(d * ((d << 1) | 1), 5);
  /* t = (B * (2B + 1)) <<< log2(w) */
  t = rot_l(b * ((b << 1) | 1), 5);
  /* C = ((C - S[2i + 1]) >>> t) XOR u */
  c = rot_r(c - s[(i << 1) | 1], t) ^ u;
  /* A = ((A - S[2i]) >>> u) XOR t */
  a = rot_r(a - s[i << 1], u) ^ t;
 }

 /* remove pre-whitening */
 block[3] = d - s[1];
 block[2] = c;
 block[1] = b - s[0];
 block[0] = a;

 return;
}

void encrypt_block(uint32_t *block, struct cipher_params *params)
{
 int i;
 uint32_t key_stream[4];

 /* counter state */
 for(i = 0; i < 4; i++) key_stream[i] = params->counter[i];
 /* generate key stream (CTR encryption) */
 encrypt(key_stream, params->rounds, params->r_keys);
 /* apply key stream to plaintext */
 for(i = 0; i < 4; i++) block[i] ^= key_stream[i];
 /* ECB encryption */
 encrypt(block, params->rounds, params->r_keys);

 /* increment counter */
 for(i = 0; (!(++params->counter[i])) && (i < 3); i++)

 return;
}

void decrypt_block(uint32_t *block, struct cipher_params *params)
{
 int i;
 uint32_t key_stream[4];

 /* ECB decryption */
 decrypt(block, params->rounds, params->r_keys);
 /* counter state */
 for(i = 0; i < 4; i++) key_stream[i] = params->counter[i];
 /* generate key stream (CTR decryption) */
 encrypt(key_stream, params->rounds, params->r_keys);
 /* apply key stream to get plaintext */
 for(i = 0; i < 4; i++) block[i] ^= key_stream[i];

 /* increment counter */
 for(i = 0; (!(++params->counter[i])) && (i < 3); i++)

 return;
}

/* convert hexadecimal digit to binary quartet */
int hex_quartet(int c)
{
 switch(c)
 {
  case '0': return 0x0;
  case '1': return 0x1;
  case '2': return 0x2;
  case '3': return 0x3;
  case '4': return 0x4;
  case '5': return 0x5;
  case '6': return 0x6;
  case '7': return 0x7;
  case '8': return 0x8;
  case '9': return 0x9;
  case 'A': return 0xA;
  case 'B': return 0xB;
  case 'C': return 0xC;
  case 'D': return 0xD;
  case 'E': return 0xE;
  case 'F': return 0xF;
  case 'a': return 0xA;
  case 'b': return 0xB;
  case 'c': return 0xC;
  case 'd': return 0xD;
  case 'e': return 0xE;
  case 'f': return 0xF;
  default: fail("not a hexadecimal number");
 }

 /* This is just to quiet Clang. */
 return 0;
}

void write_header(FILE *out_file, struct cipher_params *params)
{
 int i;
 uint32_t block[4];

 /* write magic */
 if(fwrite(magic, 1, 8, out_file) != 8) failed("write magic");

 /* write file version number */
 putc(1, out_file);

 /* write number of rounds */
 write_number(params->rounds, out_file);

 /* write nonce */
 write_block(params->counter, out_file);

 /* generate password check */
 for(i = 0; i < 4; i++) block[i] = 0;
 encrypt_block(block, params);
 /* write password check */
 write_block(block, out_file);

 return;
}

void read_header(FILE *in_file, struct cipher_params *params)
{
 int i;
 uint32_t block[4];

 /* verify magic */
 for(i = 0; i < 8; i++)
  if(magic[i] != getc(in_file))
   fail("incompatible file");

 /* read file version number */
 if(1 != getc(in_file)) fail("incompatible version");

 /* read number of rounds */
 params->rounds = read_number(in_file);

 /* check values */
 if(params->rounds < 1) fail("invalid value in file for rounds");

 /* read nonce */
 if(!read_block(params->counter, in_file)) failed("read nonce");

 return;
}

/* check password */
void check_pw(FILE *in_file, struct cipher_params *params)
{
 int i;
 uint32_t block[4];

 /* generate check */
 for(i = 0; i < 4; i++) block[i] = 0;
 encrypt_block(block, params);

 /* compare check */
 for(i = 0; i < 4; i++)
  if(block[i] != read_word(in_file))
   fail("password does not match");

 return;
}

/* generate key schedule */
uint32_t *gen_sched(char *string, uintmax_t rounds, bool hex_in)
{
 uintmax_t i, j, k, t, c, v, len;
 uint32_t a, b, *kw, *s;

 /* interpret as hexadecimal digits */
 if(hex_in)
 {
  /* allocate key words */
  if((len = strlen(string))) c = (len / 8) + ((len % 8) != 0);
  else c = 1;
  if((kw = calloc(c, sizeof(uint32_t))) == NULL) failed("allocate keywords");

  /* put bytes into words; little-endian octet order; big-endian quartet order within octets */
  for(i = 0; i < len; i++) kw[i / 8] |= ((uint32_t)hex_quartet(string[i])) << (((i % 8) ^ 1) * 4);
 }
 /* interpret as a string */
 else
 {
  /* allocate key words */
  if((len = strlen(string))) c = (len / 4) + ((len % 4) != 0);
  else c = 1;
  if((kw = calloc(c, sizeof(uint32_t))) == NULL) failed("allocate keywords");

  /* put bytes into words; little-endian octet order */
  for(i = 0; i < len; i++) kw[i / 4] |= ((uint32_t)string[i]) << ((i % 4) * 8);
 }

 /* allocate round key array */
 t = ((rounds * 2) + 4);
 if((s = malloc(t * sizeof(uint32_t))) == NULL) failed("allocate schedule");

 /* initialize array */
 s[0] = 0xB7E15163;
 for(i = 1; i < t; i++) s[i] = s[i - 1] + 0x9E3779B9;

 a = b = i = j = 0;
 /* v = 3 * max(c, 2r + 4) */
 if(c > t) v = c * 3;
 else v = t * 3;

 for(k = 0; k < v; k++)
 {
  /* A = S[i] = (S[i] + A + B) <<< 3 */
  a = s[i] = rot_l(s[i] + a + b, 3);
  /* B = L[j] = (L[j] + A + B) <<< (A + B) */
  b = kw[j] = rot_l(kw[j] + a + b, a + b);
  /* i = (i + 1) mod (2r + 4) */
  if(++i >= t) i = 0;
  /* j = (j + 1) mod c */
  if(++j >= c) j = 0;
 }

 free(kw);

 return s;
}

void encrypt_string(char *string, FILE *out_file, struct cipher_params *params)
{
 int i;
 uint32_t block[4];

 while(true)
 {
  /* clear block */
  for(i = 0; i < 4; i++) block[i] = 0;

  /* for each byte */
  for(i = 0; i < 16; i++)
  {
   /* if end of string */
   if(string[i] == '\0')
   {
    encrypt_block(block, params);
    write_block(block, out_file);
    return;
   }
   /* add byte to block */
   block[i / 4] |= ((uint32_t)string[i]) << ((i % 4) * 8);
  }
  encrypt_block(block, params);
  write_block(block, out_file);
  /* move on to next block of bytes */
  string += 16;
 }
}

char *decrypt_string(FILE *in_file, struct cipher_params *params)
{
 uintmax_t i, base = 0;
 uint32_t block[4];
 char *string;

 if((string = malloc(16)) == NULL) failed("allocate string space");

 while(true)
 {
  /* read and decrypt block */
  if(!read_block(block, in_file)) failed("read encrypted string");
  decrypt_block(block, params);

  /* for each byte */
  for(i = 0; i < 16; i++)
   if((string[base + i] = (block[i / 4] >> ((i % 4) * 8)) & 0xFF) == 0)
    return string;

  /* increase string space */
  base += 16;
  if((string = realloc(string, base + 16)) == NULL) failed("allocate string space");
 }
}

void encrypt_stream(FILE *in_file, FILE *out_file, struct cipher_params *params)
{
 uint32_t block[4];

 /* encrypt blocks */
 while(read_block(block, in_file))
 {
  encrypt_block(block, params);
  write_block(block, out_file);
 }

 /* encrypt last block */
 encrypt_block(block, params);
 write_block(block, out_file);

 return;
}

void decrypt_stream(FILE *in_file, FILE *out_file, struct cipher_params *params)
{
 int i;
 uint32_t block[4], next[4];

 /* read first block */
 if(!read_block(block, in_file)) failed("read encrypted data");

 /* decrypt blocks */
 while(read_block(next, in_file))
 {
  decrypt_block(block, params);
  write_block(block, out_file);
  for(i = 0; i < 4; i++) block[i] = next[i];
 }

 /* decrypt last block */
 decrypt_block(block, params);
 write_last_block(block, out_file);

 return;
}

void reencrypt_stream(FILE *in_file, FILE *out_file, struct cipher_params *old_params, struct cipher_params *new_params)
{
 uint32_t block[4];

 while(read_block(block, in_file))
 {
  decrypt_block(block, old_params);
  encrypt_block(block, new_params);
  write_block(block, out_file);
 }

 return;
}

void encrypt_file(uintmax_t rounds, bool hex_in)
{
 int i;
 char *in_name, *out_name, *key_string, *nonce_string;
 uint32_t *nonce_keys;
 FILE *in_file, *out_file;
 struct cipher_params params;

 params.rounds = rounds;
 for(i = 0; i < 4; i++) params.counter[i] = 0;

 /* open input file */
 fputs("file to encrypt: ", stdout);
 in_name = input_line();
 if((in_file = fopen(in_name, "rb")) == NULL) fail(in_name);

 /* open output file */
 fputs("encrypted file name: ", stdout);
 out_name = input_line();
 if((out_file = fopen(out_name, "wb")) == NULL) fail(out_name);

 /* get password */
 fputs("password: ", stdout);
 key_string = input_line();
 params.r_keys = gen_sched(key_string, rounds, hex_in);

 /* get nonce */
 fputs("nonce: ", stdout);
 nonce_string = input_line();
 nonce_keys = gen_sched(nonce_string, rounds, hex_in);
 encrypt(params.counter, rounds, nonce_keys);
 free(nonce_keys);

 /* write file header */
 write_header(out_file, &params);

 /* write encrypted string */
 encrypt_string(in_name, out_file, &params);

 /* encrypt data */
 puts("encrypting data...");
 encrypt_stream(in_file, out_file, &params);
 puts("done");

 /* free space */
 free(in_name);
 free(out_name);
 free(key_string);
 free(nonce_string);
 free(params.r_keys);

 /* close files */
 fclose(in_file);
 fclose(out_file);

 return;
}

void decrypt_file(uintmax_t rounds, bool hex_in)
{
 char *in_name, *out_name, *key_string;
 FILE *in_file, *out_file;
 struct cipher_params params;

 /* open input file */
 fputs("encrypted file name: ", stdout);
 in_name = input_line();
 if((in_file = fopen(in_name, "rb")) == NULL) fail(in_name);

 /* read file header */
 read_header(in_file, &params);
 rounds = params.rounds;

 /* get password */
 fputs("password: ", stdout);
 key_string = input_line();
 params.r_keys = gen_sched(key_string, rounds, hex_in);

 /* check password */
 check_pw(in_file, &params);

 /* read encrypted string */
 out_name = decrypt_string(in_file, &params);

 if(out_name[0])
 {
  printf("real file name: \"%s\"\n", out_name);

  /* see whether file already exists */
  if(access(out_name, F_OK) == 0)
  {
   puts("A file with this name already exists.");
   free(out_name);
   fputs("decrypted file name: ", stdout);
   out_name = input_line();
  }
  errno = 0;
 }
 /* if there is no file name */
 else
 {
  puts("no stored file name");
  free(out_name);
  fputs("decrypted file name: ", stdout);
  out_name = input_line();
 }

 /* open output file */
 if((out_file = fopen(out_name, "wb")) == NULL) fail(out_name);

 /* decrypt data */
 puts("decrypting data...");
 decrypt_stream(in_file, out_file, &params);
 puts("done");

 /* free space */
 free(in_name);
 free(out_name);
 free(key_string);
 free(params.r_keys);

 /* close files */
 fclose(in_file);
 fclose(out_file);

 return;
}

void reencrypt_file(uintmax_t rounds, bool hex_in)
{
 int i;
 char *in_name, *out_name, *real_name, *old_key_str, *new_key_str, *new_nonce_str;
 uint32_t *nonce_keys;
 FILE *in_file, *out_file;
 struct cipher_params old_params, new_params;

 new_params.rounds = rounds;
 for(i = 0; i < 4; i++) new_params.counter[i] = 0;

 /* open input file */
 fputs("old file name: ", stdout);
 in_name = input_line();
 if((in_file = fopen(in_name, "rb")) == NULL) fail(in_name);

 /* read file header */
 read_header(in_file, &old_params);

 /* get old password */
 fputs("old password: ", stdout);
 old_key_str = input_line();
 old_params.r_keys = gen_sched(old_key_str, old_params.rounds, hex_in);

 /* check password */
 check_pw(in_file, &old_params);

 /* read real file name string */
 real_name = decrypt_string(in_file, &old_params);

 /* open output file */
 fputs("new file name: ", stdout);
 out_name = input_line();
 if((out_file = fopen(out_name, "wb")) == NULL) fail(out_name);

 /* get new password */
 fputs("new password: ", stdout);
 new_key_str = input_line();
 new_params.r_keys = gen_sched(new_key_str, new_params.rounds, hex_in);

 /* get nonce */
 fputs("nonce: ", stdout);
 new_nonce_str = input_line();
 nonce_keys = gen_sched(new_nonce_str, new_params.rounds, hex_in);
 encrypt(new_params.counter, new_params.rounds, nonce_keys);
 free(nonce_keys);

 /* write file header */
 write_header(out_file, &new_params);

 /* write encrypted string */
 encrypt_string(real_name, out_file, &new_params);

 /* re-encrypt data */
 puts("re-encrypting data...");
 reencrypt_stream(in_file, out_file, &old_params, &new_params);
 puts("done");

 /* free space */
 free(in_name);
 free(out_name);
 free(real_name);
 free(old_key_str);
 free(new_key_str);
 free(new_nonce_str);
 free(old_params.r_keys);
 free(new_params.r_keys);

 /* close files */
 fclose(in_file);
 fclose(out_file);

 return;
}

int main(int argc, char **argv)
{
 int c, mode = 1;
 uintmax_t rounds;
 bool hex_in;
 extern char *optarg;
 extern int opterr, optind, optopt;

 /* the errno symbol is defined in errno.h */
 errno = 0;

 /* initialize global variables */
 i_buf = NULL;
 ib_s = 0;

 /* prepare default settings */
 rounds = 34;
 hex_in = false;

 /* parse command line */
 while((c = getopt(argc, argv, "hder:x")) != -1)
  switch(c)
  {
   case 'h': help(); exit(EXIT_SUCCESS);
   case 'd': mode = -1; break;
   case 'e': mode = 2; break;
   case 'r': if(sscanf(optarg, "%ju", &rounds) != 1) invalid(c); break;
   case 'x': hex_in = true; break;
   case '?': exit(EXIT_FAILURE);
  }

 /* check values */
 if(rounds < 1) fail("\"r\" must be at least 1");

 /* process file */
 if(mode == 1) encrypt_file(rounds, hex_in);
 else if(mode == -1) decrypt_file(rounds, hex_in);
 else if(mode == 2) reencrypt_file(rounds, hex_in);
 else return EXIT_FAILURE;

 free(i_buf);

 return EXIT_SUCCESS;
}
