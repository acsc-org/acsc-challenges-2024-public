#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<stdint.h>
#include<time.h>
#include<math.h>

#define FAIL 0
#define SUCCESS 1

#define MAX_HISTORY 10
#define MAX_COMMENT_SIZE 0x100

#define MAX_PIECES 0x100
#define BOARD_SIZE 81
#define BOARD_WIDTH 9
#define BOARD_HEIGHT 9
#define PLAYER_CNT 2
#define MAX_PER_TYPE 19

#define BASE_PIECE_TYPES 8
#define PIECE_TYPES 11

#define ENDGAME_ONGOING 0
#define ENDGAME_WON 1
#define ENDGAME_LOST 2

#define MOVE_FORFEIT -1
#define MOVE_ILLEGAL -2

#define AI_ID 0
#define PLAYER_ID 1

#define NO_PROMOTE 0
#define PROMOTE 1

typedef struct Type {
  int8_t moves[9];
  int8_t ranged[9];
} TYPE;

typedef struct Piece {
  int8_t type;
  int8_t pos;
  int8_t owner;
} PIECE;

typedef struct Board {
  PIECE piece[MAX_PIECES];
  int total_moves;
  int8_t last_move_piece;
  int8_t last_move_promote;
  int8_t first_P;
  int8_t game_finished;
  int8_t board_lay[BOARD_SIZE];
  int8_t held[PLAYER_CNT][BASE_PIECE_TYPES][MAX_PER_TYPE + 1]; //Index 0 is used to store count
} BOARD;

typedef struct History {
  BOARD hist_board;
  struct History *next, *prev;
} HISTORY;

typedef struct Game {
  char *comment;
  HISTORY *hist;
} GAME;

char piece_set[PIECE_TYPES][8] = {"王", "飛", "角", "金", "銀", "桂", "香", "歩",
                                  "王", "竜", "馬"};

int8_t promote_map[PIECE_TYPES] = {-1, 9, 10, -1, 3, 3, 3, 3, -1, -1, -1};

int piece_value[PIECE_TYPES] = {100000, 200, 100, 50, 30, 10, 10, 2, 100000, 500, 400};

//idx : ( x,  y)
//  0 : (-1, -1)
//  1 : ( 0, -1)
//  2 : ( 1, -1)
//  3 : (-1,  0)
//  4 : ( 1,  0)
//  5 : (-1,  1)
//  6 : ( 0,  1)
//  7 : ( 1,  1)
//  8 : L
TYPE ptypes[PLAYER_CNT][PIECE_TYPES] = {{{{1,1,1,1,1,1,1,1,0}, {0,0,0,0,0,0,0,0,0}},   //王
                                         {{0,1,0,1,1,0,1,0,0}, {0,1,0,1,1,0,1,0,0}},   //飛
                                         {{1,0,1,0,0,1,0,1,0}, {1,0,1,0,0,1,0,1,0}},   //角
                                         {{0,1,0,1,1,1,1,1,0}, {0,0,0,0,0,0,0,0,0}},   //金
                                         {{1,0,1,0,0,1,1,1,0}, {0,0,0,0,0,0,0,0,0}},   //銀
                                         {{0,0,0,0,0,0,0,0,1}, {0,0,0,0,0,0,0,0,0}},   //桂
                                         {{0,0,0,0,0,0,1,0,0}, {0,0,0,0,0,0,1,0,0}},   //香
                                         {{0,0,0,0,0,0,1,0,0}, {0,0,0,0,0,0,0,0,0}},   //歩
                                         {{0,0,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0,0}},   //dummy
                                         {{1,1,1,1,1,1,1,1,0}, {0,1,0,1,1,0,1,0,0}},   //竜
                                         {{1,1,1,1,1,1,1,1,0}, {1,0,1,0,0,1,0,1,0}}},  //馬
                                        {{{1,1,1,1,1,1,1,1,0}, {0,0,0,0,0,0,0,0,0}},   //王
                                         {{0,1,0,1,1,0,1,0,0}, {0,1,0,1,1,0,1,0,0}},   //飛
                                         {{1,0,1,0,0,1,0,1,0}, {1,0,1,0,0,1,0,1,0}},   //角
                                         {{1,1,1,1,1,0,1,0,0}, {0,0,0,0,0,0,0,0,0}},   //金
                                         {{1,1,1,0,0,1,0,1,0}, {0,0,0,0,0,0,0,0,0}},   //銀
                                         {{0,0,0,0,0,0,0,0,1}, {0,0,0,0,0,0,0,0,0}},   //桂
                                         {{0,1,0,0,0,0,0,0,0}, {0,1,0,0,0,0,0,0,0}},   //香
                                         {{0,1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0,0}},   //歩
                                         {{0,0,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0,0}},   //dummy
                                         {{1,1,1,1,1,1,1,1,0}, {0,1,0,1,1,0,1,0,0}},   //竜
                                         {{1,1,1,1,1,1,1,1,0}, {1,0,1,0,0,1,0,1,0}}}}; //馬

char vertical_axis[BOARD_HEIGHT][8] = {"一", "二", "三", "四", "五", "六", "七", "八", "九"};
char horizontal_axis[BOARD_WIDTH][8] = {"9", "8", "7", "6", "5", "4", "3", "2", "1"};

char game_board[] = "        9   8   7   6   5   4   3   2   1  \n"
                    "      ┌───┬───┬───┬───┬───┬───┬───┬───┬───┐\n"
                    "   一 │   │   │   │   │   │   │   │   │   │\n"
                    "      ├───┼───┼───┼───┼───┼───┼───┼───┼───┤\n"
                    "   二 │   │   │   │   │   │   │   │   │   │\n"
                    "      ├───┼───┼───┼───┼───┼───┼───┼───┼───┤\n"
                    "   三 │   │   │   │   │   │   │   │   │   │\n"
                    "      ├───┼───┼───┼───┼───┼───┼───┼───┼───┤\n"
                    "   四 │   │   │   │   │   │   │   │   │   │\n"
                    "      ├───┼───┼───┼───┼───┼───┼───┼───┼───┤\n"
                    "   五 │   │   │   │   │   │   │   │   │   │\n"
                    "      ├───┼───┼───┼───┼───┼───┼───┼───┼───┤\n"
                    "   六 │   │   │   │   │   │   │   │   │   │\n"
                    "      ├───┼───┼───┼───┼───┼───┼───┼───┼───┤\n"
                    "   七 │   │   │   │   │   │   │   │   │   │\n"
                    "      ├───┼───┼───┼───┼───┼───┼───┼───┼───┤\n"
                    "   八 │   │   │   │   │   │   │   │   │   │\n"
                    "      ├───┼───┼───┼───┼───┼───┼───┼───┼───┤\n"
                    "   九 │   │   │   │   │   │   │   │   │   │\n"
                    "      └───┴───┴───┴───┴───┴───┴───┴───┴───┘\n";

int pos_index[] = { 173,  179,  185,  191,  197,  203,  209,  215,  221,
                    356,  362,  368,  374,  380,  386,  392,  398,  404,
                    539,  545,  551,  557,  563,  569,  575,  581,  587,
                    722,  728,  734,  740,  746,  752,  758,  764,  770,
                    905,  911,  917,  923,  929,  935,  941,  947,  953,
                   1088, 1094, 1100, 1106, 1112, 1118, 1124, 1130, 1136,
                   1271, 1277, 1283, 1289, 1295, 1301, 1307, 1313, 1319,
                   1454, 1460, 1466, 1472, 1478, 1484, 1490, 1496, 1502,
                   1637, 1643, 1649, 1655, 1661, 1667, 1673, 1679, 1685,
                   1858};

BOARD cur_board;
GAME game[MAX_HISTORY];

void printerror(char *msg) {
  puts(msg);
  _exit(0);
}

void init_proc() {
  srand(time(NULL));
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  return;
}

void read_str(char *buf, int len) {
  int L = read(STDIN_FILENO, buf, len - 1);
  if (L <= 0) {
    printerror("read error");
  }
  if (buf[L - 1] == '\n') {
    buf[L - 1] = '\0';
  } else {
    buf[L] = '\0';
  }
  return;
}

int read_int() {
  char buf[16] = {0};
  read_str(buf, 16);
  return atoi(buf);
}

void set_piece(PIECE *P, int type, int8_t pos, int8_t owner) {
  P->type = type;
  P->pos = pos;
  P->owner = owner;
  return;
}

void init_board() {
  for (int i = 0; i < MAX_PIECES; i++) {
    //NOTE: clear all pieces
    set_piece(&cur_board.piece[i], 0, -1, 0);
  }
  for (int i = 0; i < BOARD_SIZE; i++) {
    //NOTE: clear all board cells
    cur_board.board_lay[i] = -1;
  }
  for (int i = 0; i < PLAYER_CNT; i++) {
    for (int j = 0; j < BOARD_WIDTH; j++) {
      set_piece(&cur_board.piece[i * 20 + j], 7, i * 36 + 18 + j, i); //歩
      cur_board.board_lay[i * 36 + 18 + j] = i * 20 + j; //歩
    }
    set_piece(&cur_board.piece[i * 20 + 9 ], 6, i * 72,      i); //香
    set_piece(&cur_board.piece[i * 20 + 10], 6, i * 72 + 8,  i); //香
    set_piece(&cur_board.piece[i * 20 + 11], 5, i * 72 + 1,  i); //桂
    set_piece(&cur_board.piece[i * 20 + 12], 5, i * 72 + 7,  i); //桂
    set_piece(&cur_board.piece[i * 20 + 13], 4, i * 72 + 2,  i); //銀
    set_piece(&cur_board.piece[i * 20 + 14], 4, i * 72 + 6,  i); //銀
    set_piece(&cur_board.piece[i * 20 + 15], 3, i * 72 + 3,  i); //金
    set_piece(&cur_board.piece[i * 20 + 16], 3, i * 72 + 5,  i); //金
    set_piece(&cur_board.piece[i * 20 + 17], 2, i * 48 + 16, i); //角
    set_piece(&cur_board.piece[i * 20 + 18], 1, i * 60 + 10, i); //飛
    set_piece(&cur_board.piece[i * 20 + 19], 0, i * 72 + 4,  i); //王
    cur_board.board_lay[i * 72     ] = i * 20 + 9;  //香
    cur_board.board_lay[i * 72 + 8 ] = i * 20 + 10; //香
    cur_board.board_lay[i * 72 + 1 ] = i * 20 + 11; //桂
    cur_board.board_lay[i * 72 + 7 ] = i * 20 + 12; //桂
    cur_board.board_lay[i * 72 + 2 ] = i * 20 + 13; //銀
    cur_board.board_lay[i * 72 + 6 ] = i * 20 + 14; //銀
    cur_board.board_lay[i * 72 + 3 ] = i * 20 + 15; //金
    cur_board.board_lay[i * 72 + 5 ] = i * 20 + 16; //金
    cur_board.board_lay[i * 48 + 16] = i * 20 + 17; //角
    cur_board.board_lay[i * 60 + 10] = i * 20 + 18; //飛
    cur_board.board_lay[i * 72 + 4 ] = i * 20 + 19; //王
    for (int j = 0; j < BASE_PIECE_TYPES; j++) {
      cur_board.held[i][j][0] = 0;
    }
  }
  cur_board.total_moves = 0;
  cur_board.game_finished = ENDGAME_ONGOING;
  return;
}

void print_board(BOARD *B){
  char buffer[4000];
  int L = 0;
  puts("\n\n    AI   Held \u2616 : 王 飛 角 金 銀 桂 香 歩");
  printf(
    "                  %2hhd %2hhd %2hhd %2hhd %2hhd %2hhd %2hhd %2hhd\n\n",
    B->held[0][0][0],
    B->held[0][1][0],
    B->held[0][2][0],
    B->held[0][3][0],
    B->held[0][4][0],
    B->held[0][5][0],
    B->held[0][6][0],
    B->held[0][7][0]
  );
  memcpy(buffer, game_board, pos_index[0]);
  L = pos_index[0];
  for (int i = 0; i < BOARD_SIZE; i++) {
    if (B->board_lay[i] == -1) {
      memcpy(&buffer[L], "  ", 2);
      L += 2;
    } else {
      if (B->piece[B->board_lay[i]].owner == 0) {
        sprintf(&buffer[3000], "\033[1;33m%s\033[0m", piece_set[B->piece[B->board_lay[i]].type]);
      } else {
        sprintf(&buffer[3000], "\033[1;36m%s\033[0m", piece_set[B->piece[B->board_lay[i]].type]);
      }
      memcpy(&buffer[L], &buffer[3000], 14);
      L += 14;
    }
    memcpy(&buffer[L], &game_board[pos_index[i] + 2], pos_index[i + 1] - (pos_index[i] + 2));
    L += pos_index[i + 1] - (pos_index[i] + 2);
  }
  buffer[L] = '\0';
  puts(buffer);
  puts("  Player Held \u2616 : 王 飛 角 金 銀 桂 香 歩");
  printf(
    "                  %2hhd %2hhd %2hhd %2hhd %2hhd %2hhd %2hhd %2hhd\n\n",
    B->held[1][0][0],
    B->held[1][1][0],
    B->held[1][2][0],
    B->held[1][3][0],
    B->held[1][4][0],
    B->held[1][5][0],
    B->held[1][6][0],
    B->held[1][7][0]
  );
  printf("  Total Moves Made : %d\n", B->total_moves);
  if (B->total_moves > 0) {
    if (B->last_move_piece == MOVE_FORFEIT) {
      printf("  Last    Move   : 投了");
    } else if (B->last_move_piece == MOVE_ILLEGAL) {
      printf("  Last    Move   : Illegal Move");
    } else if(B->piece[B->last_move_piece].owner == B->first_P) {
      printf(
        "  Last    Move   : ▲ %s%s%s",
        piece_set[B->piece[B->last_move_piece].type],
        horizontal_axis[B->piece[B->last_move_piece].pos % 9],
        vertical_axis[B->piece[B->last_move_piece].pos / 9]
      );
    } else {
      printf(
        "  Last    Move   : ▽ %s%s%s",
        piece_set[B->piece[B->last_move_piece].type],
        horizontal_axis[B->piece[B->last_move_piece].pos % 9],
        vertical_axis[B->piece[B->last_move_piece].pos / 9]
      );
    }
    if (B->last_move_promote == PROMOTE) {
      printf("成");
    }
    puts("");
    if (B->game_finished == ENDGAME_LOST) {
      //NOTE: AI won't make losing moves (forfeit / illegal), so we can safely assume it's the player losing here
      if (B->first_P == PLAYER_ID) {
        printf("  まで%d手で%sの勝ち\n", B->total_moves, "後手");
      } else {
        printf("  まで%d手で%sの勝ち\n", B->total_moves, "先手");
      }
    } else if (B->game_finished == ENDGAME_WON) {
      if (B->piece[B->last_move_piece].owner == B->first_P) {
        printf("  まで%d手で%sの勝ち\n", B->total_moves, "先手");
      } else {
        printf("  まで%d手で%sの勝ち\n", B->total_moves, "後手"); 
      }
    }
  }
  puts("\n");
  return;
}

int menu() {
  puts("\n");
  puts("                          将  棋                  \n");
  puts("        \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617");
  puts("        \u2616                                       \u2616 ");
  puts("        \u2617    1. New Game                        \u2617 ");
  puts("        \u2616    2. View History                    \u2616 ");
  puts("        \u2617    3. Manage History                  \u2617 ");
  puts("        \u2616    4. Leave                           \u2616 ");
  puts("        \u2617                                       \u2617 ");
  puts("        \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616");
  puts("\n");
  printf("Your Choice > ");
  return read_int();
}

int play_menu() {
  puts("\n");
  puts("                          Levels                   \n");
  puts("        \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617");
  puts("        \u2616                                       \u2616 ");
  puts("        \u2617    1. 振り駒                          \u2617 ");
  puts("        \u2616    2. 後手                            \u2617 ");
  puts("        \u2617    3. 香落ち                          \u2617 ");
  puts("        \u2616    4. 角落ち                          \u2616 ");
  puts("        \u2617    5. 飛車落ち                        \u2617 ");
  puts("        \u2616    6. 飛香落ち                        \u2616 ");
  puts("        \u2617    7. 二枚落ち                        \u2617 ");
  puts("        \u2616    8. 四枚落ち                        \u2616 ");
  puts("        \u2617    9. 六枚落ち                        \u2617 ");
  puts("        \u2616    10. 十九枚落ち                     \u2616 ");
  puts("        \u2617                                       \u2617 ");
  puts("        \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 \u2617 \u2616 ");
  puts("\n");
  printf("Your Choice > ");
  return read_int();
}

int make_move(int player, int *move, BOARD *B) {
  //NOTE: Checks not implemented for some 禁手 (打步詰,千日手,應將...)
  int8_t P1, P2;
  if (move[0] < 0) {
    //NOTE: play held pieces
    P1 = B->held[player][-move[0]][0]; //held count
    P2 = B->board_lay[move[1]]; //dst
    if (P1 <= 0 || P2 != -1) {
      //NOTE: assert player holds piece + dst cell is empty
      return ENDGAME_LOST;
    }
    P1 = B->held[player][-move[0]][P1];
    if (B->piece[P1].type == 6 || B->piece[P1].type == 7) {
      //NOTE: not allowed to play 香, 歩 in the final row
      if (move[1] / BOARD_WIDTH + player * (BOARD_HEIGHT - 1) == BOARD_HEIGHT - 1) {
        return ENDGAME_LOST;
      }
    } else if(B->piece[P1].type == 5) {
      //NOTE: not allowed to play 桂 in the last two rows
      if (move[1] / BOARD_WIDTH + player * (BOARD_HEIGHT - 2) == BOARD_HEIGHT - 2 || move[1] / BOARD_WIDTH + player * (BOARD_HEIGHT - 2) == BOARD_HEIGHT - 1) {
        return ENDGAME_LOST;
      }
    }
    if (B->piece[P1].type == 7) {
      //NOTE: not allowed to have two 歩 in same rank
      for (int i = move[1] % BOARD_WIDTH; i < BOARD_SIZE; i += BOARD_WIDTH) {
        if(B->board_lay[i] >= 0 && B->piece[B->board_lay[i]].type == 7 && B->piece[B->board_lay[i]].owner == player) {
          return ENDGAME_LOST;
        }
      }
    }
    B->board_lay[move[1]] = P1;
    B->piece[P1].pos = move[1];
    B->held[player][-move[0]][0] -= 1;
  } else{
    //NOTE: move pieces
    P1 = B->board_lay[move[0]];
    P2 = B->board_lay[move[1]];
    if (P1 < 0 || B->piece[P1].owner != player) {
      //NOTE: moving pieces not owned by player
      return ENDGAME_LOST;
    }
    if (P2 >= 0 && B->piece[P2].owner == player) {
      //NOTE: moving pieces to dst occupied by player's own piece
      return ENDGAME_LOST;
    }
    int deltax, deltay;
    deltax = move[1] % BOARD_WIDTH - move[0] % BOARD_WIDTH;
    deltay = move[1] / BOARD_WIDTH - move[0] / BOARD_WIDTH;
    if (deltax != 0 && deltay != 0) {
      //NOTE: L or diagonal moves
      if ((deltax == 1 || deltax == -1) && ((deltay == 2 && player == AI_ID) || (deltay == -2 && player == PLAYER_ID))) {
        //NOTE: L shape movement
        if(ptypes[player][B->piece[P1].type].moves[8] != 1) {
          return ENDGAME_LOST;
        }
      } else if (deltax == 1 && deltay == 1) {
        //NOTE: down-right * 1 movement
        if (ptypes[player][B->piece[P1].type].moves[7] != 1) {
          return ENDGAME_LOST;
        }
      } else if (deltax == -1 && deltay == 1) {
        //NOTE: down-left * 1 movement
        if (ptypes[player][B->piece[P1].type].moves[5] != 1) {
          return ENDGAME_LOST;
        }
      } else if (deltax == 1 && deltay == -1) {
        //NOTE: up-right * 1 movement
        if (ptypes[player][B->piece[P1].type].moves[2] != 1) {
          return ENDGAME_LOST;
        }
      } else if (deltax == -1 && deltay == -1) {
        //NOTE: up-left * 1 movement
        if (ptypes[player][B->piece[P1].type].moves[0] != 1) {
          return ENDGAME_LOST;
        }
      } else if (deltax == deltay) {
        if (deltax > 0) {
          //NOTE: down-right * n movement
          if (ptypes[player][B->piece[P1].type].moves[7] != 1 || ptypes[player][B->piece[P1].type].ranged[7] != 1) {
            return ENDGAME_LOST;
          }
          for (int i = move[0] + (BOARD_WIDTH + 1); i < move[1]; i += (BOARD_WIDTH + 1)) {
            if (B->board_lay[i] >= 0) {
              return ENDGAME_LOST;
            }
          }
        } else {
          //NOTE: up-left * n movement
          if (ptypes[player][B->piece[P1].type].moves[0] != 1 || ptypes[player][B->piece[P1].type].ranged[0] != 1) {
            return ENDGAME_LOST;
          }
          for (int i = move[0] - (BOARD_WIDTH + 1); i > move[1]; i -= (BOARD_WIDTH + 1)) {
            if (B->board_lay[i] >= 0) return -1;
          }
        }
      }
      else if (deltax == -deltay) {
        if (deltax > 0) {
          //NOTE: up-right * n movement
          if (ptypes[player][B->piece[P1].type].moves[2] != 1 || ptypes[player][B->piece[P1].type].ranged[2] != 1) {
            return ENDGAME_LOST;
          }
          for (int i = move[0] - (BOARD_WIDTH - 1);i > move[1]; i -= (BOARD_WIDTH - 1)) {
            if (B->board_lay[i] >= 0) {
              return ENDGAME_LOST;
            }
          }
        } else {
          //NOTE: down-left * n movement
          if (ptypes[player][B->piece[P1].type].moves[5] != 1 || ptypes[player][B->piece[P1].type].ranged[5] != 1) {
            return ENDGAME_LOST;
          }
          for(int i = move[0] + (BOARD_WIDTH - 1); i < move[1]; i += (BOARD_WIDTH - 1)) {
            if(B->board_lay[i] >= 0) {
              return ENDGAME_LOST;
            }
          }
        }
      } else {
        return ENDGAME_LOST;
      }
    } else if (deltax != 0) {
      //NOTE: vertical moves
      if (deltax < 0) {
        //NOTE: left movement
        if (ptypes[player][B->piece[P1].type].moves[3] != 1) {
          return ENDGAME_LOST;
        }
        if (deltax < -1) {
          //NOTE: ranged movement
          if (ptypes[player][B->piece[P1].type].ranged[3] != 1) {
            return ENDGAME_LOST;
          }
          for (int i = move[0] - 1;i > move[1]; i--) {
            if (B->board_lay[i] >= 0) {
              return ENDGAME_LOST;
            }
          }
        }
      } else {
        //NOTE: right movement
        if (ptypes[player][B->piece[P1].type].moves[4] != 1) {
          return ENDGAME_LOST;
        }
        if (deltax > 1) {
          //NOTE: ranged movement
          if (ptypes[player][B->piece[P1].type].ranged[4] != 1) {
            return ENDGAME_LOST;
          }
          for (int i = move[0] + 1; i < move[1]; i++) {
            if (B->board_lay[i] >= 0) {
              return ENDGAME_LOST;
            }
          }
        }
      }
    } else if (deltay != 0) {
      //NOTE: horizontal movement
      if (deltay < 0) {
        //NOTE: up movement
        if (ptypes[player][B->piece[P1].type].moves[1] != 1) {
          return ENDGAME_LOST;
        }
        if (deltay < -1) {
          //NOTE: ranged movement
          if (ptypes[player][B->piece[P1].type].ranged[1] != 1) {
            return ENDGAME_LOST;
          }
          for (int i = move[0] - BOARD_WIDTH; i > move[1]; i -= BOARD_WIDTH) {
            if (B->board_lay[i] >= 0) {
              return ENDGAME_LOST;
            }
          }
        }
      } else {
        //NOTE: down movement
        if (ptypes[player][B->piece[P1].type].moves[6] != 1) {
          return ENDGAME_LOST;
        }
        if (deltay > 1) {
          //NOTE: ranged movement
          if (ptypes[player][B->piece[P1].type].ranged[6] != 1) {
            return ENDGAME_LOST;
          }
          for (int i = move[0] + BOARD_WIDTH; i < move[1]; i += BOARD_WIDTH) {
            if (B->board_lay[i] >= 0) {
              return ENDGAME_LOST;
            }
          }
        }
      }
    } else {
      return ENDGAME_LOST;
    }
    B->last_move_promote = NO_PROMOTE;
    if (P2 >= 0) {
      //NOTE: demote back to original piece before capturing and insert captured piece to held list
      B->piece[P2].type %= BASE_PIECE_TYPES;
      B->held[player][B->piece[P2].type][0] += 1;
      B->held[player][B->piece[P2].type][B->held[player][B->piece[P2].type][0]] = P2;
      B->piece[P2].owner = player;
      B->piece[P2].pos = -1;
    }
    B->board_lay[move[1]] = P1;
    B->board_lay[move[0]] = -1;
    if (player == PLAYER_ID && (move[1] < BOARD_WIDTH * 3 || move[0] < BOARD_WIDTH * 3) && promote_map[B->piece[P1].type] != -1) {
      if (((B->piece[P1].type == 6 || B->piece[P1].type == 7) && move[1] < BOARD_WIDTH) || (B->piece[P1].type == 5 && move[1] < BOARD_WIDTH * 2)) {
        //NOTE: forced promote
        B->last_move_promote = PROMOTE;
      } else {
        //NOTE: can promote
        puts("Promote ? ");
        char buf[8];
        read_str(buf, 8);
        if (!strncmp(buf, "yes", 3)) {
          B->last_move_promote = PROMOTE;
        }
      }
      if (B->last_move_promote == PROMOTE) {
        B->piece[P1].type = promote_map[B->piece[P1].type];
      }
    } else if (player == AI_ID && (move[0] >= BOARD_SIZE - BOARD_WIDTH * 3 || move[1] >= BOARD_SIZE - BOARD_WIDTH * 3) && promote_map[B->piece[P1].type] != -1) {
      //NOTE: AI always promote since it leads to a higher board value estimation
      B->piece[P1].type = promote_map[B->piece[P1].type];
      B->last_move_promote = PROMOTE;
    }
  }
  B->last_move_piece = P1;
  B->piece[P1].pos = move[1];
  if (P2 >= 0 && B->piece[P2].type == 0) {
    //NOTE: captured 王, end of game
    return ENDGAME_WON;
  }
  return ENDGAME_ONGOING;
}

int parse_move(char *buf, int *move) {
  move[0] = 0;
  move[1] = 0;
  if (!memcmp("打", buf, 3)) {
    //NOTE: play held pieces
    for (int i = 1; i < BASE_PIECE_TYPES; i++) {
      //NOTE: piece type
      if (!memcmp(piece_set[i], &buf[3], 3)) {
        //NOTE: negative src means that we are playing a held piece
        move[0] = -i;
        break;
      }
      if (i == (BASE_PIECE_TYPES - 1)) {
        return FAIL;
      }
    }
    for (int i = 0; i < BOARD_HEIGHT; i++) {
      //NOTE: dst y
      if (!memcmp(vertical_axis[i], &buf[9], 3)) {
        move[1] += BOARD_WIDTH * i;
        break;
      }
      if (i == (BOARD_HEIGHT - 1)) {
        return FAIL;
      }
    }
    for (int i = 0; i < BOARD_WIDTH; i++) {
      //NOTE: dst x
      if (!memcmp(horizontal_axis[i], &buf[7], 1)) {
        move[1] += i;
        break;
      }
      if (i == (BOARD_WIDTH - 1)) {
        return FAIL;
      }
    }
  } else {
    for (int i = 0; i < BOARD_HEIGHT; i++) {
      //NOTE: src y
      if (!memcmp(vertical_axis[i], &buf[3], 3)) {
        move[0] += BOARD_WIDTH * i;
        break;
      }
      if (i == (BOARD_HEIGHT - 1)) {
        return FAIL;
      }
    }
    for (int i = 0; i < BOARD_WIDTH; i++) {
      //NOTE: src x
      if (!memcmp(horizontal_axis[i], &buf[1], 1)) {
        move[0] += i;
        break;
      }
      if (i == (BOARD_WIDTH - 1)) {
        return FAIL;
      }
    }
    for (int i = 0; i < BOARD_HEIGHT; i++) {
      //NOTE: dst y
      if (!memcmp(vertical_axis[i], &buf[10], 3)) {
        move[1] += BOARD_WIDTH * i;
        break;
      }
      if (i == (BOARD_HEIGHT - 1)) {
        return FAIL;
      }
    }
    for (int i = 0; i < BOARD_WIDTH; i++) {
      //NOTE: dst x
      if (!memcmp(horizontal_axis[i], &buf[8], 1)) {
        move[1] += i;
        break;
      }
      if (i == (BOARD_WIDTH - 1)) {
        return FAIL;
      }
    }
  }
  return SUCCESS;
}

int player_move(int *move) {
  cur_board.total_moves += 1;
  char buf[24];
  printf("Player > ");
  memset(buf, 0, 24);
  read_str(buf, 24);
  if (!strncmp(buf, "投了", 6)) {
    cur_board.game_finished = ENDGAME_LOST;
    cur_board.last_move_piece = MOVE_FORFEIT;
    cur_board.last_move_promote = NO_PROMOTE;
    return ENDGAME_LOST;
  }
  if (parse_move(buf, move) == FAIL) {
    cur_board.game_finished = ENDGAME_LOST;
    cur_board.last_move_piece = MOVE_ILLEGAL;
    cur_board.last_move_promote = NO_PROMOTE;
    return ENDGAME_LOST;
  }
  int res = make_move(PLAYER_ID, move, &cur_board);
  if (res == ENDGAME_LOST) {
    cur_board.game_finished = ENDGAME_LOST;
    cur_board.last_move_piece = MOVE_ILLEGAL;
    cur_board.last_move_promote = NO_PROMOTE;
    return ENDGAME_LOST;
  } else if (res == ENDGAME_WON) {
    cur_board.game_finished = ENDGAME_WON;
    return ENDGAME_WON;
  }
  return ENDGAME_ONGOING;
}

int evaluate_board(int8_t player, BOARD *B) {
  int val = 0;
  for (int i = 0;i < BOARD_SIZE; i++) {
    if (B->board_lay[i] >= 0 && B->piece[B->board_lay[i]].owner == player) {
      val += piece_value[B->piece[B->board_lay[i]].type];
    }
  }
  for (int i = 0; i < BASE_PIECE_TYPES; i++) {
    //NOTE: value of held pieces are half of pieces on board
    val += (piece_value[i] * (int)B->held[player][i][0]) / 2;
  }
  return val;
}

void search_move(int *move) {
  int value = -1, tmove[2], tval;
  BOARD search;
  for (int i = 0; i < BOARD_SIZE; i++) {
    for (int j = 0; j < BOARD_SIZE; j++) {
      memcpy(&search, &cur_board, sizeof(BOARD));
      tmove[0] = i;
      tmove[1] = j;
      if (make_move(0, tmove, &search) == ENDGAME_LOST) {
        continue;
      }
      tval = evaluate_board(0, &search);
      if (tval > value) {
        value = tval;
        move[0] = tmove[0];
        move[1] = tmove[1];
      }
    }
  }
  for (int i = 1; i < BASE_PIECE_TYPES; i++) {
    for (int j = 0; j < BOARD_SIZE; j++) {
      search = cur_board;
      tmove[0] = -i;
      tmove[1] = j;
      if (make_move(0, tmove, &search) == ENDGAME_LOST) {
        continue;
      }
      tval = evaluate_board(0, &search);
      if (tval > value) {
        value = tval;
        move[0] = tmove[0];
        move[1] = tmove[1];
      }
    }
  }
  return;
}

int AI_move(int *move) {
  //NOTE: mirror shogi
  cur_board.total_moves += 1;
  if (move[0] >= 0) {
    move[0] = (BOARD_SIZE - 1) - move[0];
  }
  move[1] = (BOARD_SIZE - 1) - move[1];
  int res = make_move(0, move, &cur_board);
  if (res == ENDGAME_LOST) {
    //NOTE: mirror failed, search for move
    search_move(move);
    res = make_move(AI_ID, move, &cur_board);
  }
  if (res == ENDGAME_WON) {
    cur_board.game_finished = ENDGAME_WON;
    return ENDGAME_WON;
  }
  return ENDGAME_ONGOING;
}

HISTORY *log_board(HISTORY *cur) {
  HISTORY *H = (HISTORY *)malloc(sizeof(HISTORY));
  memcpy(&(H->hist_board), &cur_board, sizeof(BOARD));
  H->next = NULL;
  H->prev = cur;
  if (cur != NULL) {
    cur->next = H;
  }
  return H;
}

void play_game() {
  int game_idx, res = ENDGAME_ONGOING;
  HISTORY *last = NULL;
  for (game_idx = 0; game_idx < MAX_HISTORY; game_idx++) {
    if (game[game_idx].hist == NULL) {
      break;
    }
  }
  if (game_idx == MAX_HISTORY) {
    printf("At most %d game histories can be stored at a time\nClean old game history to play new games\n", MAX_HISTORY);
    return;
  }
  init_board();
  int difficulty = play_menu();
  cur_board.first_P = PLAYER_ID;
  switch (difficulty) {
    case 1:
      cur_board.first_P = rand() % PLAYER_CNT;
      break;
    case 2:
      cur_board.first_P = AI_ID;
      break;
    case 10:
      for(int i = 20; i < 29; i++) {
        cur_board.board_lay[cur_board.piece[i].pos] = -1;
        cur_board.piece[i].pos = -1;
      }
      for(int i = 33; i < 37; i++) {
        cur_board.board_lay[cur_board.piece[i].pos] = -1;
        cur_board.piece[i].pos = -1;
      }
    case 9:
      cur_board.piece[31].pos = -1;
      cur_board.piece[32].pos = -1;
      cur_board.board_lay[73] = -1;
      cur_board.board_lay[79] = -1;
    case 8:
      cur_board.piece[29].pos = -1;
      cur_board.piece[30].pos = -1;
      cur_board.board_lay[72] = -1;
      cur_board.board_lay[80] = -1;
    case 7:
      cur_board.piece[38].pos = -1;
      cur_board.board_lay[70] = -1;
    case 4:
      cur_board.piece[37].pos = -1;
      cur_board.board_lay[64] = -1;
      break;
    case 6:
      cur_board.piece[29].pos = -1;
      cur_board.board_lay[72] = -1;
    case 5:
      cur_board.piece[38].pos = -1;
      cur_board.board_lay[70] = -1;
      break;
    case 3:
      cur_board.piece[29].pos = -1;
      cur_board.board_lay[72] = -1;
      break;
    default:
      puts("Invalid Level");
      return;
  }
  int move[2] = {0, 0};
  last = log_board(last);
  print_board(&cur_board);
  if (cur_board.first_P == AI_ID) {
    res = AI_move(move);
    last = log_board(last);
    print_board(&cur_board);
  }
  while (res == ENDGAME_ONGOING) {
    res = player_move(move);
    last = log_board(last);
    print_board(&cur_board);
    if (res != ENDGAME_ONGOING) {
      break;
    }
    res = AI_move(move);
    last = log_board(last);
    print_board(&cur_board);
  }
  while (last->prev != NULL) {
    last = last->prev;
  }
  game[game_idx].hist = last;
  printf("Provide some comments on this game > ");
  char buf[MAX_COMMENT_SIZE];
  read_str(buf, MAX_COMMENT_SIZE);
  game[game_idx].comment = strdup(buf);
  return;
}

void show_history() {
  int map[MAX_HISTORY];
  int cnt = 0;
  for (int i = 0; i < MAX_HISTORY; i++) {
    if (game[i].hist != NULL) {
      map[cnt] = i;
      cnt+=1;
    }
  }
  while (1) {
    puts("\n\n                         History                   ");
    for (int i = 0; i < cnt; i++) {
      printf("    \u2616    game%3d : %s\n", i + 1, game[map[i]].comment);
    }
    puts("\n\nSelect game you want to view or insert 0 to Exit : ");
    int res = read_int();
    if (res == 0) {
      break;
    } else if (res > cnt || res < 0) {
      puts("Invalid Index");
    } else {
      HISTORY *H = game[map[res - 1]].hist;
      while (H != NULL) {
        print_board(&(H->hist_board));
        H = H->next;
      }
    }
    puts("\n\n");
  }
  return;
}

void manage_history() {
  int map[MAX_HISTORY];
  int cnt = 0;
  for (int i = 0; i < MAX_HISTORY; i++) {
    if (game[i].hist != NULL) {
      map[cnt] = i;
      cnt += 1;
    }
  }
  while (1) {
    puts("\n\n                         History                   ");
    for (int i = 0; i < cnt; i++) {
      printf("    \u2616    game%3d : %s\n", i + 1, game[map[i]].comment);
    }
    puts("\n\nSelect game you want to delete or insert 0 to Exit : ");
    int res = read_int();
    if (res == 0) {
      break;
    } else if (res > cnt || res < 0) {
      puts("Invalid Index");
    } else {
      HISTORY *H = game[map[res - 1]].hist, *N;
      while (H != NULL) {
        N = H->next;
        free(H);
        H = N;
      }
      game[map[res - 1]].hist = NULL;
      free(game[map[res - 1]].comment);
      game[map[res - 1]].comment = NULL;
      for (int i = res; i < cnt; i++) {
        map[i - 1] = map[i];
      }
      cnt -= 1;
    }
    puts("\n\n");
  }
  return;
}

int main() {
  init_proc();
  while (1) {
    int choice = menu();
    switch (choice) {
      case 1:
        play_game();
        break;
      case 2:
        show_history();
        break;
      case 3:
        manage_history();
        break;
      case 4:
        puts("Goodbye");
        _exit(0);
      default:
        puts("Invalid Command");
    }
  }
  return 0;
}
