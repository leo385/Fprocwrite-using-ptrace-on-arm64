#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sched.h>
#include <string.h>
#include <inttypes.h>

#define BUFFER_SIZE 512
const char* process_name = "main";

const char* getCommandOutput(const char* command) {
	FILE* pfile;
	char output[BUFFER_SIZE] = "\0";
	
	pfile = popen(command, "r");
	if(pfile == NULL) {
		perror("Failed to open pip stream\n");
		exit(EXIT_SUCCESS);
	}
	
	const char* saveOutputIntoBuffer = fgets(output, BUFFER_SIZE, pfile);
	if(saveOutputIntoBuffer == NULL ) {
		perror("Failed to save pip stream into output array\n");
		exit(EXIT_SUCCESS);
	}
	
	pclose(pfile);
	saveOutputIntoBuffer = &output[0];
	return saveOutputIntoBuffer;
}	

int get_process_pid(const char* process_name) {
	char command[20] = "\0";
	sprintf(command, "pidof %s", process_name);
	int pid = atoi(getCommandOutput(&command[0]));
	if(pid == 0) {
		printf("Failed to convert pid into integer\n");
		return 1;
	}
	
	return pid;
}

uintptr_t get_base_address() {
	char baseAddress[11] = "\0";
	char fullBaseAddress[20] = "\0";
	// cat shell command
	char read_proc_maps[128] = "\0";
	sprintf(read_proc_maps, "cat /proc/`pidof %s`/maps", process_name);
	const char* command = &read_proc_maps[0];
	memcpy(baseAddress, getCommandOutput(command), 9);
	const char* buffer = &baseAddress[0];
	
	sprintf(fullBaseAddress, "0x%s", buffer); 
	buffer = &fullBaseAddress[0];
	
	uintptr_t real_base_address = (uintptr_t)strtoull(buffer, NULL, 16);
	return real_base_address;
	
	
}

uintptr_t appendOffsetToBaseAddress(const char* offset) {
	char base_address_buffer[32] = "\0";
	char offset_buffer[45] = "\0";
	
	snprintf(base_address_buffer, sizeof(base_address_buffer), "0x%" PRIxPTR, get_base_address());
	snprintf(offset_buffer, sizeof(offset_buffer), "%s%s", base_address_buffer, offset);
	
	uintptr_t real_offset = (uintptr_t)strtoull(&offset_buffer[0], NULL, 16);
	return real_offset;
}

int main(void) {
	
	pid_t pid = {get_process_pid(process_name)};
	uint32_t code[sizeof(long)] = {0};
	long* pcode = (long*)code;
	
	if(-1 == ptrace(PTRACE_ATTACH, pid, NULL, NULL))
	{
		perror("Failed attach to process\n");
		return 1;
	}
	
	waitpid(pid, NULL, 0);
	
	errno = 0;
	
	uintptr_t real_offset = appendOffsetToBaseAddress("960");
	*pcode = ptrace(PTRACE_PEEKTEXT, pid, real_offset, 0);
	if(errno != 0)
	{
		perror("Failed to peek text\n");
		return 1;
	}
	
	// jump bytes
	code[0] = 0x58000050;
	code[1] = 0xD61F0200;
	
	if(-1 == ptrace(PTRACE_POKETEXT, pid, real_offset, *pcode)) {
		perror("Failed to poke text with jump bytes\n");
		return 1;
	}
	
	uintptr_t write_to_this_address = appendOffsetToBaseAddress("968");
	uintptr_t target_address = appendOffsetToBaseAddress("918");
	if(-1 == ptrace(PTRACE_POKETEXT, pid, write_to_this_address, target_address)) {
		perror("Failed to poke text with target address where we jump\n");
		return 1;
	}
	
	if(-1 == ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("Failed to detach the process\n");
		return 1;
	}
	
	printf("Patch injected!\n");

	return 0;
}
