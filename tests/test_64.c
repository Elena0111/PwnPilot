#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <bsd/string.h>
char input[10];

int size=0;

int checkInput(const char *line){
 return strstr(line, "1") != NULL;}

void function8(){
 char ar2[89];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

}

void function7(){
 char ar2[49];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

}

void function6(){
 char ar2[58];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

 function8();

 function7();

}

void function5(){
 char ar2[99];
puts("checking input: What do you choose: 1, 2 ,3?"); fflush(stdout);
char input[0x10];
fgets(input,0x10,stdin);
int checkinput = checkInput(input);
 printf("input checked %d", checkinput);

puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
if(checkinput==1) size = 300;
 fgets(ar2, sizeof(ar2)+size, stdin); 
size = 0;

 function1();

}

void function4(){
 char ar2[81];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

}

void function3(){
 char ar2[40];
  
char line[88];
  puts("Hello"); fflush(stdout);
if (line=='53') { 
  __asm__("pop %rdi");
  __asm__("ret"); 
}

}

void function2(){
 char ar2[53];
  printf("Hello");
  printf("Hello");
  printf("Hello");

 function6();

 function5();

 function3();

}

void function1(){
 char ar2[63];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

 function4();

}

int main(int argc, char* argv[]){
 puts("Hello");
 char ar2[77];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

 function2();

}