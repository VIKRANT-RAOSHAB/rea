#include <stdio.h>
#include <string.h>
#include "lfs.h"
static unsigned char flash[32*256];
static int rd(const struct lfs_config *c,lfs_block_t block,lfs_off_t off,void *buffer,lfs_size_t size) { (void)c; memcpy(buffer,flash+block*256+off,size); return 0; }
static int wr(const struct lfs_config *c,lfs_block_t block,lfs_off_t off,const void *buffer,lfs_size_t size) { (void)c; memcpy(flash+block*256+off,buffer,size); return 0; }
static int er(const struct lfs_config *c,lfs_block_t block) { (void)c; memset(flash+block*256,255,256); return 0; }
static int sy(const struct lfs_config *c) { (void)c; return 0; }
int main(void) {
  struct lfs_config cfg={0}; cfg.read=rd;cfg.prog=wr;cfg.erase=er;cfg.sync=sy;cfg.read_size=16;cfg.prog_size=16;cfg.block_size=256;cfg.block_count=32;cfg.block_cycles=500;cfg.cache_size=64;cfg.lookahead_size=8;
  memset(flash,255,sizeof(flash));lfs_t lfs={0};lfs_file_t file={0};
  if (lfs_format(&lfs,&cfg) || lfs_mount(&lfs,&cfg)) return 1;
  if(lfs_mkdir(&lfs,"dir"))return 2;
  if(lfs_file_open(&lfs,&file,"hello.txt",LFS_O_CREAT|LFS_O_WRONLY))return 3;
  if(lfs_file_write(&lfs,&file,"hello-upstream",14)!=14 || lfs_file_close(&lfs,&file))return 4;
  if(lfs_file_open(&lfs,&file,"dir/large.bin",LFS_O_CREAT|LFS_O_WRONLY))return 5;
  unsigned char data[1000];for(int i=0;i<1000;i++)data[i]=(unsigned char)i;
  if(lfs_file_write(&lfs,&file,data,1000)!=1000 || lfs_file_close(&lfs,&file))return 6;
  if(lfs_file_open(&lfs,&file,"remove",LFS_O_CREAT|LFS_O_WRONLY)||lfs_file_write(&lfs,&file,"x",1)!=1||lfs_file_close(&lfs,&file)||lfs_remove(&lfs,"remove"))return 7;
  if(lfs_unmount(&lfs))return 8;
  FILE *out=fopen("upstream-littlefs.bin","wb");if(!out)return 9;size_t n=fwrite(flash,1,sizeof(flash),out);fclose(out);return n==sizeof(flash)?0:10;
}
