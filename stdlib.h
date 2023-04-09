#ifndef STDLIB_H_
#define STDLIB_H_

// We don't use these, but they need to be defined for mm_malloc to not have a hissy fit
extern void *malloc(size_t size);
extern void free(void *ptr);

#endif
