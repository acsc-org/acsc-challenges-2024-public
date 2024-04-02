#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include"junks.h"

typedef struct {
  char junk1[69];
  char pin_digit;
  char junk2[0x69];
} Pin;

volatile Pin pins[10] = {
  {{JUNK1_1},  '1'^ 1, {JUNK2_1}},
  {{JUNK1_2},  '2'^ 2, {JUNK2_2}},
  {{JUNK1_3},  '3'^ 3, {JUNK2_3}},
  {{JUNK1_4},  '4'^ 4, {JUNK2_4}},
  {{JUNK1_5},  '5'^ 5, {JUNK2_5}},
  {{JUNK1_6},  '6'^ 6, {JUNK2_6}},
  {{JUNK1_7},  '7'^ 7, {JUNK2_7}},
  {{JUNK1_8},  '8'^ 8, {JUNK2_8}},
  {{JUNK1_9},  '9'^ 9, {JUNK2_9}},
  {{JUNK1_10}, '0'^ 10, {JUNK2_10}}
};

// Obfuscated constant time delay function
void delay() {
  usleep(100*1000);
}

void printart(){
  printf("@@@  @@@   @@@@@@   @@@  @@@  @@@       @@@@@@@\n");
  printf("@@@  @@@  @@@@@@@@  @@@  @@@  @@@       @@@@@@@\n");
  printf("@@!  @@@  @@!  @@@  @@!  @@@  @@!         @@!\n");
  printf("!@!  @!@  !@!  @!@  !@!  @!@  !@!         !@!\n");
  printf("@!@  !@!  @!@!@!@!  @!@  !@!  @!!         @!!\n");
  printf("!@!  !!!  !!!@!!!!  !@!  !!!  !!!         !!!\n");
  printf(":!:  !!:  !!:  !!!  !!:  !!!  !!:         !!:\n");
  printf(" ::!!:!   :!:  !:!  :!:  !:!  :!:        :!:\n");
  printf("  ::::    ::   :::  ::::: ::  :: ::::     ::\n");
  printf("   :       :   : :   : :  :   : :: : :     :\n");
}


void xor_strings(char *str1, char *str2, char *result) {
  int length = strlen(str1); // Assuming both strings are of equal length
  int i=0;
  for (i = 0; i < length; i++) {
    result[i] = str1[i] ^ str2[i];
  }
  result[length] = '\0'; // Null-terminate the result string
}

void printflag(char *seed) {
  puts("flag: ACSC{**** REDACTED ****}");
}


void main(){
  printart();

  static char input[4096] = {0};
  printf("Enter your PIN: ");
  fflush(stdout);
  int count = read(0, input, 10);

  //printflag(input);

  if (count != 10) {
    puts("Access Denied\n It didn't take me any time to verify that it's not the pin");
    return;
  } else {
    delay();
  }

  static int flag = 1;
  for (int i = 0; i < 10; i++) {
    if (input[i] != ((pins[i].pin_digit) ^ i+1)) {
      flag = 0;
      puts("Access Denied\n It didn't take me any time to verify that it's not the pin");
      return;
    } else {
      delay();
    }
  }
  if (flag){
    printflag(input);
  }
  return;
}
