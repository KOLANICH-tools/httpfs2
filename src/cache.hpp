#include "dependencies.h"
#include "struct_url.hpp"

// ========== CACHE  ============
#define CACHEMAXSIZE 2147483648LL
#define CRCLEN 32
typedef struct range struct_range;
typedef struct range {
    off_t start;
    size_t size;
    off_t cstart;
    char md5[33];
//    sizef_t csize; // actually, the same as size
    struct_range *next;
} struct_range;

struct_range *idxhead = 0, *lastidx = 0;
int fdcache = 0, fdidx = 0; // cache files descriptors are global for all theads
off_t cacheMaxSize = CACHEMAXSIZE; // default cache file size
//size_t cacheMaxSize = 327680; // debug

int init_cache(char *filename) {
    off_t s;
    struct_range *p = 0;
    int i, c, l;
    if ((fdcache = open(filename, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR)) == -1) {
        fprintf(stderr, "Can't open cache file: %s\n", filename);
        return -1;
    }
    strcat(filename,".idx");
    if ((fdidx = open(filename, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR)) == -1) {
        fprintf(stderr, "Can't open cache index file: %s\n", filename);
        close(fdcache);
        return -1;
    }
    s = lseek(fdidx, 0, SEEK_END);
    if ( s == 0 ) return 0; // nothing caches yet
    lseek(fdidx, 0, SEEK_SET);
    read(fdidx, &c, sizeof(c)); // number of entries
    read(fdidx, &l, sizeof(l)); // lask block index

    for (i = 0; i < c; i++) {
        if (idxhead == nullptr){
            p = idxhead = new struct_range;
        } else {
            p->next = new struct_range;
            p = p->next;
        }
        if (i==l) lastidx = p;
        read(fdidx, &p->start, sizeof(p->start));
        read(fdidx, &p->size, sizeof(p->size));
        read(fdidx, &p->cstart, sizeof(p->cstart));
        read(fdidx, &p->md5, CRCLEN);
        p->md5[32] = 0;
        p->next = 0;
    }
    return 0;
}

ssize_t get_cached(struct_url *url, off_t start, size_t rsize) {

    ssize_t bytes = 0;
    struct_range *p, *p2;
    char md5[2][33];

#ifdef USE_THREAD
    //pthread_mutex_lock(&cache_lock);
    cache_lock.lock();
#endif
    p = idxhead;

    while (p) {
        if ( (p->start <= start) && ((p->start + (off_t)p->size-1) >= start+(off_t)rsize-1) ) {

            lseek(fdcache, p->cstart, SEEK_SET); // set to start of block to read header
            read(fdcache, md5[0], CRCLEN);
            md5[0][32] = 0;

            lseek(fdcache, p->cstart + (start - p->start)+CRCLEN ,SEEK_SET);
            bytes = (ssize_t)read(fdcache, url->req_buf, rsize);

            lseek(fdcache, p->cstart + (off_t)p->size + CRCLEN, SEEK_SET); // set to start of block to read header
            read(fdcache, md5[1], CRCLEN);
            md5[1][32] = 0;


            if (strcmp(p->md5, md5[0]) || strcmp(p->md5, md5[1])){ // Everything is bad. cache corrupted. reset cache
                bytes = 0;
                if (p == idxhead) { // some trick: make range zero; we should keep zero cstart for head;
                    p->start = 0;
                    p->size = 0;
                    memset(p->md5,0, 32);
                    if (lastidx == idxhead) { // need to revert lastidx to last element
                        while(lastidx->next) lastidx = lastidx->next;
                    }
                    if (p->next == nullptr) {
                        idxhead = lastidx = 0; free(p); // there was only one cached block; can delete it
                    }
                    break;
                }
                p2=idxhead;
                while (p2->next) {
                    if (p2->next == p) {
                        if (p == lastidx) lastidx = p2; // newest block is
                        p2->next = p->next;
                        free(p);
                        break;
                    }
                    p2 = p2->next;
                }
                break;
            }

            break;
        }

        p = p->next;
    }
#ifdef USE_THREAD
    //pthread_mutex_unlock(&cache_lock);
    cache_lock.unlock();
#endif
    return bytes;
}

ssize_t update_cache(struct_url *url, off_t start, size_t rsize, char *md5) {
    struct_range *p, *t;
    int c, last;
#ifdef USE_THREAD
    //pthread_mutex_lock(&cache_lock);
    cache_lock.lock();
#endif
    if (idxhead == nullptr) { // nothing is cached yet
        lastidx = idxhead = new struct_range;
        lastidx->next = 0;
        lastidx->cstart = 0;
    } else if (lastidx->cstart + (off_t)lastidx->size + CRCLEN*2 > cacheMaxSize) {
        lastidx = idxhead; // reached max file size. start from brginning
    } else if (lastidx->next == nullptr) { // we may add one more block into cache
        lastidx->next = new struct_range;
        lastidx->next->cstart = lastidx->cstart + (off_t)lastidx->size + CRCLEN*2;
        lastidx = lastidx->next;
        lastidx->next = 0;
    } else { // we are in a middle of cache file.
        if (lastidx->next->cstart > lastidx->cstart + (off_t)lastidx->size + CRCLEN*2 + (off_t)rsize + CRCLEN*2) { // there is enough space till oldest block (large block was deleted earlier
            p = new struct_range;
            p->next = lastidx->next;
            p->cstart = lastidx->cstart + (off_t)lastidx->size + CRCLEN*2;
            lastidx->next = p;
            lastidx = p;
        } else {
            lastidx->next->cstart = lastidx->cstart + (off_t)lastidx->size + CRCLEN*2;
            lastidx = lastidx->next;
        }
    }
    lastidx->start = start;
    lastidx->size = rsize;
    strncpy(lastidx->md5, md5, 32);
    lastidx->md5[32]=0;

    // now we need remove indexes, which blocks will be overwritten
    p = lastidx->next;
    while (p) {
        if (p->cstart < lastidx->cstart + (off_t)lastidx->size + CRCLEN*2) {
            t = p;
            p = p->next;
            lastidx->next = p;
            free(t);
        } else p=0;
    }

    lseek(fdcache, lastidx->cstart, SEEK_SET);
    write(fdcache, md5, CRCLEN);
    write(fdcache, url->req_buf, rsize);
    write(fdcache, md5, CRCLEN);


    lseek(fdidx, sizeof(c)+sizeof(last), SEEK_SET);
    p = idxhead; c = 0, last = 0;;
    do {
        if (p == lastidx) last=c;
        write(fdidx, &p->start, sizeof(p->start));
        write(fdidx, &p->size, sizeof(p->size));
        write(fdidx, &p->cstart, sizeof(p->cstart));
        write(fdidx, &p->md5, CRCLEN);
        c++;
    } while ( (p = p->next) );
    lseek(fdidx, 0, SEEK_SET);
    write(fdidx, &c, sizeof(c));
    write(fdidx, &last, sizeof(last));

#ifdef USE_THREAD
    //pthread_mutex_unlock(&cache_lock);
    cache_lock.unlock();
#endif
    return 0;
}

// ========== CACHE ============
