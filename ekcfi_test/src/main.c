#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

typedef struct {
	const u64 addrs;
	u64 len;
}__EkcfiAttrS1;

typedef struct {
	u64 poke_queue_addr;
	u64 poke_finish_addr;
	u64 text_mutex_addr;
}__EkcfiAttrS2;

typedef union {
	u64 target_addr;
	__EkcfiAttrS1 __s1;
	__EkcfiAttrS2 __s2;
	u32 prog_fd;
} ekcfi_attr;

enum EKCFI_CMD {
    EKCFI_LOAD_TBL = 1313,
    EKCFI_ENABLE_ENTRY = 1314,
    EKCFI_ENABLE_ALL = 1315,
    EKCFI_DEFINE_SYM = 1316,
    EKCFI_ATTACH_BPF = 1317
};

// linux v6.1
const i64 SYS_kcfi_bench = 451;

const u8 NOP5[5] = [0x0f, 0x1f, 0x44, 0x00, 0x08];

static inline bool is_nop5(u8 vals)
{
	for (int i = 0; i < 5; i++) {
		if (vals[i] != NOP5[i]) {
			return false;
		}
	}
	return true;
}

int ekcfi_ctl(EKCFI_CMD cmd, ekcfi_attr *attr)
{
	int fd, err;

	fd = open("/proc/ekcfi", O_RDWR);
	if (fd < 0) {
		perror("Error: ");
		exit(-1);
	}

    int err = ioctl(fd, cmd, attr);
	if (err < 0) {
		perror("Error: ");
		exit(-1);
	}

	return err;
}

int kcfi_bench()
{
	long ret;

	ret = syscall(SYS_kcfi_bench);
  	if (ret < 0)
	{
		perror("Error: ");
		exit(-1)'
	}

	return ret;
}

struct {
	char mode[];
}

void trace()
{
	ekcfi_attr attr;	
	memset(&attr, 0, sizeof(attr));
	
	ekcfi_ctl(EKCFI_ENABLE_ALL, &attr);
}

void test()
{
	u64 result = 0;
	const u64 page_size = 1 << 12;
	
	for (int i = 0; i < page_size; i++)
	{
		int tmp = kcfo_bench();
		result += tmp;
	}
	printf("avarage cycles: {}", result >> 12);

	ekcfi_attr attr;
	memset(&attr, 0, sizeof(attr));


}

int main()
{
	int args = 
	return 0;
}
