#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <bsd/string.h>
char input[10];

int size=0;

int checkInput(const char *line){
 return strstr(line, "1") != NULL;}

void function7(){
 char ar2[33];
  printf("Hello");
  printf("Hello");
  printf("Hello");

 function4();

}

void function6(){
 char ar2[76];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

 function7();

}

void function5(){
 char ar2[98];
puts("checking input: What do you choose: 1, 2 ,3?"); fflush(stdout);
char input[0x10];
fgets(input,0x10,stdin);
int checkinput = checkInput(input);
 printf("input checked %d", checkinput);

puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
if(checkinput==1) size = 300;
 fgets(ar2, sizeof(ar2)+size, stdin); 
size = 0;

}

void function4(){
 char ar2[40];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

 function2();

}

void function3(){
 char ar2[94];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

}

void function2(){
 char ar2[30];
  
char line[88];
  puts("Hello"); fflush(stdout);
if (line=='53') { 
  __asm__("pop %rdi");
  __asm__("ret"); 
}

}

void function1(){
 char ar2[71];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

}

int main(int argc, char* argv[]){
 puts("Hello");
 char ar2[67];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

 function1();

 function6();

 function3();

 function5();

}