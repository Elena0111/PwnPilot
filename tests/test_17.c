#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <bsd/string.h>
char input[10];

int size=0;

int checkInput(const char *line){
 return strstr(line, "1") != NULL;}

void function3(){
 char ar2[36];
  printf("Hello");
  printf("Hello");
  printf("Hello");

 function2();

}

void function2(){
 char ar2[24];
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

void function1(){
 char ar2[80];
  
char line[88];
  puts("Hello"); fflush(stdout);
if (line=='53') { 
  __asm__("pop %rdi");
  __asm__("ret"); 
}

}

int main(int argc, char* argv[]){
 puts("Hello");
 char ar2[26];
puts("What do you choose: 1, 2 ,3?"); fflush(stdout);
fgets(ar2, sizeof(ar2)+size, stdin);

 function3();

}