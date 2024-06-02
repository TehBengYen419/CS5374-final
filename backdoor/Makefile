KERNEL_SRC := $(abspath ../linux)
SUBDIR= $(PWD)

obj-m := backdoor.o

.PHONY: clean

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(SUBDIR) modules

clean:
	$(RM) *~ *.ko *.o *.mod *.mod.c .*.cmd Module.symvers modules.order
