#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <zlib.h>
#include <time.h>
static uint32_t rd32(const uint8_t*p){return p[0]|(p[1]<<8)|(p[2]<<16)|((uint32_t)p[3]<<24);}
static uint16_t rd16(const uint8_t*p){return p[0]|(p[1]<<8);}
static double now(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
int main(int argc,char**argv){
    int fd=open(argv[1],O_RDONLY); struct stat st; fstat(fd,&st);
    size_t sz=st.st_size; const uint8_t*m=mmap(NULL,sz,PROT_READ,MAP_PRIVATE,fd,0);
    ssize_t e=-1; for(ssize_t i=sz-22;i>=0;i--) if(rd32(m+i)==0x06054b50){e=i;break;}
    uint32_t n=rd16(m+e+10), cd=rd32(m+e+16); size_t p=cd;
    double worst=0; char wname[512]=""; double sum=0;
    uint8_t*buf=malloc(1<<20);
    for(uint32_t i=0;i<n&&rd32(m+p)==0x02014b50;i++){
        uint16_t nl=rd16(m+p+28),el=rd16(m+p+30),cl=rd16(m+p+32);
        uint16_t meth=rd16(m+p+10); uint32_t cs=rd32(m+p+20); uint64_t off=rd32(m+p+42);
        const char*nm=(const char*)(m+p+46);
        if(meth==8){
            const uint8_t*lh=m+off; const uint8_t*data=lh+30+rd16(lh+26)+rd16(lh+28);
            z_stream zs; memset(&zs,0,sizeof zs); inflateInit2(&zs,-15);
            zs.next_in=(Bytef*)data; zs.avail_in=cs;
            double t0=now();
            do{ zs.next_out=buf; zs.avail_out=1<<20;
                int r=inflate(&zs,Z_NO_FLUSH); if(r==Z_STREAM_END||r<0) break;
            }while(zs.avail_in||zs.avail_out==0);
            double dt=now()-t0; inflateEnd(&zs); sum+=dt;
            if(dt>worst){worst=dt; snprintf(wname,sizeof wname,"%.*s",nl,nm);}
        }
        p+=46+nl+el+cl;
    }
    printf("  slowest single deflated entry : %.1f ms  (%s)\n",worst*1000,wname);
    printf("  sum of all inflate time       : %.1f ms  (serial total)\n",sum*1000);
    printf("  => perfect-parallel lower bound = max(sum/16, slowest) = %.1f ms\n",
           (sum/16>worst?sum/16:worst)*1000);
    return 0;
}
