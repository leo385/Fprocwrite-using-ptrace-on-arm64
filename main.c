#include <stdio.h>

void func(char* val) {
	printf("%d\n", *val);
}

int main(void) {
	 char val;
	 fread(&val, 1, 1, stdin);
	 func(&val);
	 
	 return 0;	
}
