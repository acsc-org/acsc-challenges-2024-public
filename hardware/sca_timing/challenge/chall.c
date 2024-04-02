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

  {{JUNK1_1},  '8'^ 1, {JUNK2_1}},
  {{JUNK1_2},  '5'^ 2, {JUNK2_2}},
  {{JUNK1_3},  '7'^ 3, {JUNK2_3}},
  {{JUNK1_4},  '4'^ 4, {JUNK2_4}},
  {{JUNK1_5},  '2'^ 5, {JUNK2_5}},
  {{JUNK1_6},  '1'^ 6, {JUNK2_6}},
  {{JUNK1_7},  '9'^ 7, {JUNK2_7}},
  {{JUNK1_8},  '3'^ 8, {JUNK2_8}},
  {{JUNK1_9},  '6'^ 9, {JUNK2_9}},
  {{JUNK1_10}, '2'^ 10, {JUNK2_10}}

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
  /*
  unsigned int seed_int = atoi(seed);
  char flag[32];
  srand(seed_int); 
  // char hex_value[100] = {"0e1a151519144a58501c07390958284c0b42112b5611530a3b3c42195f0a0c"};
  char hex_value[100] ={0};
  strcpy(hex_value, "2935273119144a58501c07390958284c0b42112b5611530a3b3c42195f0a0c");
  size_t len = strlen(hex_value);
  char value[40];    
  for (size_t i = 0, j = 0; i < len; i += 2, j++) {

    sscanf(&hex_value[i], "%2hhx", &value[j]);
  }
  value[len / 2] = '\0'; // Null-terminate the decoded string

  char random_string[32];
  for (int i = 0; i < 31; i++) {
    random_string[i] = 'a' + (rand() % 26);
  }
  random_string[31] = '\0';

  xor_strings(random_string, value, flag); 

  printf("flag: %s\n", flag);
  */
  puts("flag: ACSC{b377er_d3L4y3d_7h4n_N3v3r_b42fd3d840948f3e}");
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
