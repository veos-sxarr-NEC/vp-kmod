PROGRAM = hugetlb_test transhuge_test  pfnmap_test
OBJS_HUGE = hugetlb_test.o
OBJS_TRANS = transhuge_test.o
OBJS_PFN = pfnmap_test.o
CC = gcc

CFLAGS = -Wall -I../src

.PHONY: all
all: $(PROGRAM)

debug: $(PROGRAM) 
debug: CFLAGS += -g

hugetlb_test: $(OBJS_HUGE)
	$(CC) $(CFLAGS) -o $@ $^
hugetlb_test.o: hugetlb_test.c
	$(CC) $(CFLAGS) -c -o $@ $<

transhuge_test: $(OBJS_TRANS)
	$(CC) $(CFLAGS) -o $@ $^
transhuge_test.o: transhuge_test.c
	$(CC) $(CFLAGS) -c -o $@ $<

pfnmap_test: $(OBJS_PFN)
	$(CC) $(CFLAGS) -o $@ $^
pfnmap_test.o: pfnmap_test.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f $(PROGRAM) *.o
