// Decompose the v1 cost: inflate alone vs SHA alone vs both.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <zlib.h>
#include <omp.h>
static uint32_t rd32(const uint8_t*p){return p[0]|(p[1]<<8)|(p[2]<<16)|((uint32_t)p[3]<<24);}
static uint16_t rd16(const uint8_t*p){return p[0]|(p[1]<<8);}
typedef struct { uint64_t off; uint32_t csize, usize; uint16_t method; } Ent;

int main(int argc,char**argv){
    int mode = atoi(argv[2]);   // 0=inflate only 1=sha only (over compressed) 2=both
    int fd=open(argv[1],O_RDONLY); struct stat st; fstat(fd,&st);
    size_t sz=st.st_size; const uint8_t*m=mmap(NULL,sz,PROT_READ,MAP_PRIVATE,fd,0);
    ssize_t e=-1;
    for(ssize_t i=sz-22;i>=0&&i>(ssize_t)sz-22-65535;i--) if(rd32(m+i)==0x06054b50){e=i;break;}
    uint32_t n=rd16(m+e+10), cd=rd32(m+e+16);
    Ent *ents=malloc(n*sizeof(Ent)); size_t p=cd,k=0,totalu=0,totalc=0,stored=0,tiny=0;
    for(uint32_t i=0;i<n&&rd32(m+p)==0x02014b50;i++){
        uint16_t nl=rd16(m+p+28),el=rd16(m+p+30),cl=rd16(m+p+32);
        ents[k].method=rd16(m+p+10); ents[k].csize=rd32(m+p+20);
        ents[k].usize=rd32(m+p+24); ents[k].off=rd32(m+p+42);
        if(ents[k].usize>0){ totalu+=ents[k].usize; totalc+=ents[k].csize;
            if(ents[k].method==0) stored++; if(ents[k].usize<4096) tiny++; k++; }
        p+=46+nl+el+cl;
    }
    volatile uint64_t sink=0;
    double t0=omp_get_wtime();
    #pragma omp parallel reduction(+:sink)
    {
        z_stream zs; uint8_t*buf=malloc(1<<20); EVP_MD_CTX*ctx=EVP_MD_CTX_new(); uint8_t d[32];
        #pragma omp for schedule(dynamic,8)
        for(size_t i=0;i<k;i++){
            const uint8_t*lh=m+ents[i].off;
            const uint8_t*data=lh+30+rd16(lh+26)+rd16(lh+28);
            if(mode==1){ // SHA over raw compressed bytes = what v2 does, same entries
                unsigned o; EVP_DigestInit_ex(ctx,EVP_sha256(),NULL);
                EVP_DigestUpdate(ctx,data,ents[i].csize);
                EVP_DigestFinal_ex(ctx,d,&o); sink+=d[0]; continue;
            }
            unsigned o; if(mode==2) EVP_DigestInit_ex(ctx,EVP_sha256(),NULL);
            if(ents[i].method==0){
                if(mode==2) EVP_DigestUpdate(ctx,data,ents[i].usize); else sink+=data[0];
            } else {
                memset(&zs,0,sizeof zs); inflateInit2(&zs,-15);
                zs.next_in=(Bytef*)data; zs.avail_in=ents[i].csize;
                do{ zs.next_out=buf; zs.avail_out=1<<20;
                    int r=inflate(&zs,Z_NO_FLUSH);
                    size_t got=(1<<20)-zs.avail_out;
                    if(mode==2) EVP_DigestUpdate(ctx,buf,got); else sink+=buf[0];
                    if(r==Z_STREAM_END||r<0) break;
                }while(zs.avail_in||zs.avail_out==0);
                inflateEnd(&zs);
            }
            if(mode==2){ EVP_DigestFinal_ex(ctx,d,&o); sink+=d[0]; }
        }
        EVP_MD_CTX_free(ctx); free(buf);
    }
    double t1=omp_get_wtime();
    const char*names[]={"inflate only        ","sha256 over compressed","inflate + sha256    "};
    if(mode==0) fprintf(stderr,"  entries=%zu stored(no deflate)=%zu <4KiB=%zu compressed=%.1fMiB uncompressed=%.1fMiB\n",
        k,stored,tiny,totalc/1048576.0,totalu/1048576.0);
    printf("  %s : %6.1f ms\n",names[mode],(t1-t0)*1000);
    return 0;
}
