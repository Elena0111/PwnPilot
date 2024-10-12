#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <bsd/string.h>
char input[10];

int size=0;

int checkInput(const char *line){
 return strstr(line, "1") != NULL;}

void function7(){
 char ar2[32];
  printf("Hello");
  printf("Hello");
  printf("Hello");

}

void function6(){
 char ar2[88];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
//printf("size %d", size);
fgets(ar2, sizeof(ar2)+size, stdin);

}

void function5(){
 char ar2[56];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

}

void function4(){
 char ar2[47];
  
char line[88];
  puts("Hello"); fflush(stdout);
if (line=='53') { 
  __asm__("pop %rdi");
  __asm__("ret"); 
}

}

void function3(){
 char ar2[85];
puts("checking input: What do you choose: 1, 2 ,3?"); fflush(stdout);
char input[0x10];
fgets(input,0x10,stdin);
int checkinput = checkInput(input);
 printf("input checked %d", checkinput);

puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
if(checkinput==1) size = 300;
 fgets(ar2, sizeof(ar2)+size, stdin);
 size = 0;
 function6();

}

void function2(){
 char ar2[35];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);

fgets(ar2, sizeof(ar2)+size, stdin);

 function1();

 function4();

 function5();

 function7();

 function3();

}

void function1(){
 char ar2[62];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

}

int main(int argc, char* argv[]){
 puts("Hello");
 char ar2[29];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

 function2();

}