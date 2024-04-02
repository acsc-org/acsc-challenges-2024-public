#include <stdio.h>
#include <windows.h>

#define FLAG_EAX 0x00000001
#define FLAG_EBX 0x00000002
#define FLAG_ECX 0x00000004
#define FLAG_EDX 0x00000008
#define FLAG_EDI 0x00000010
#define FLAG_ESI 0x00000020
#define FLAG_CALL 0x00000040

#define SEH_SHELLCODE_SIZE 0x100

#define FLAG_KEY_SIZE 41
#define RC4_KEY_SIZE 16
#define IDX_ADDR 1
#define IDX_SHL 9
#define IDX_SHR 13



/*
Flag: "ACSC{VectOred_EecepTi0n_H@nd1ing_14_C0Ol}"
*/

unsigned char flag_key[] = { 25, 129, 59, 179, 151, 235, 147, 148, 175, 251, 160, 255, 49, 44, 34, 39, 169, 242, 226, 150, 185, 122, 39, 160, 164, 243, 159, 146, 170, 106, 141, 248, 37, 28, 152, 103, 111, 198, 123, 238, 244 };

//int key_list[4] = { 0xcfe7a999, 0x8cb4ead8, 0x15d89f4f, 0x21eaaf7d }; // Answer
int key_list[4] = { 0, 0, 0, 0 }; // User's input


/*
unsigned char get_ntdll_base[] =
	"\xcc" // STATUS_BREAKPOINT
	"\x55\x89\xE5\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C\x8B\x40\x14\x8B\x00\x8B\x40\x10\x5D\xC3";
*/
unsigned char get_ntdll_base[] = { 212, 77, 145, 253, 124, 185, 40, 24, 24, 24, 147, 88, 20, 147, 88, 12, 147, 24, 147, 88, 8, 69, 219 };

/*
unsigned char RtlAddVectoredExceptionHandler_shellcode[] =
	"\xcc" // STATUS_BREAKPOINT
	"\x55\x89\xE5\x83\xEC\x1C\x31\xC0\x89\x45\xFC\x89\x45\xF8\x89\x45\xF4\x89\x45\xF0\x89\x45\xEC\x89\x45\xE8\x89\x45\xE4\x68\x65\x72\x00\x00\x68\x61\x6E\x64\x6C\x68\x69\x6F\x6E\x48\x68\x63\x65\x70\x74\x68\x65\x64\x45\x78\x68\x63\x74\x6F\x72\x68\x64\x64\x56\x65\x68\x52\x74\x6C\x41\x89\x65\xEC\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C\x8B\x40\x14\x8B\x00\x8B\x40\x10\x89\xC3\x8B\x43\x3C\x01\xD8\x8B\x40\x78\x01\xD8\x8B\x48\x14\x89\x4D\xFC\x8B\x48\x1C\x01\xD9\x89\x4D\xF8\x8B\x48\x20\x01\xD9\x89\x4D\xF4\x8B\x48\x24\x01\xD9\x89\x4D\xF0\x31\xC0\x31\xC9\x8B\x75\xEC\x8B\x7D\xF4\xFC\x8B\x3C\x87\x01\xDF\x66\xB9\x1F\x00\xF3\xA6\x74\x06\x40\x3B\x45\xFC\x75\xE6\x8B\x4D\xF0\x8B\x55\xF8\x66\x8B\x04\x41\x8B\x04\x82\x01\xD8\xEB\x00\x31\xD2\x8B\x4D\x08\x51\x6A\x01\xFF\xD0\x83\xC4\x1C\x83\xC4\x20\x5D\xC3";
*/
unsigned char RtlAddVectoredExceptionHandler_shellcode[] = { 198, 95, 131, 239, 137, 230, 22, 59, 202, 131, 79, 246, 131, 79, 242, 131, 79, 254, 131, 79, 250, 131, 79, 230, 131, 79, 226, 131, 79, 238, 98, 111, 120, 10, 10, 98, 107, 100, 110, 102, 98, 99, 101, 100, 66, 98, 105, 111, 122, 126, 98, 111, 110, 79, 114, 98, 105, 126, 101, 120, 98, 110, 110, 92, 111, 98, 88, 126, 102, 75, 131, 111, 230, 110, 171, 58, 10, 10, 10, 129, 74, 6, 129, 74, 30, 129, 10, 129, 74, 26, 131, 201, 129, 73, 54, 11, 210, 129, 74, 114, 11, 210, 129, 66, 30, 131, 71, 246, 129, 66, 22, 11, 211, 131, 71, 242, 129, 66, 42, 11, 211, 131, 71, 254, 129, 66, 46, 11, 211, 131, 71, 250, 59, 202, 59, 195, 129, 127, 230, 129, 119, 254, 246, 129, 54, 141, 11, 213, 108, 179, 21, 10, 249, 172, 126, 12, 74, 49, 79, 246, 127, 236, 129, 71, 250, 129, 95, 242, 108, 129, 14, 75, 129, 14, 136, 11, 210, 225, 10, 59, 216, 129, 71, 2, 91, 96, 11, 245, 218, 137, 206, 22, 137, 206, 42, 87, 201 };

/*
0:  55                      push   ebp
1:  89 e5                   mov    ebp,esp
3:  8b 4d 08                mov    ecx,DWORD PTR [ebp+0x8]
6:  8b 55 10                mov    edx,DWORD PTR [ebp+0x10]
9:  52                      push   edx
a:  ff d1                   call   ecx
c:  5d                      pop    ebp
d:  c3                      ret
*/
unsigned char ScanForInstructions_wrapper_shellcode[] =
"\x55\x89\xE5\x8B\x4D\x08\x8B\x55\x10\x52\xFF\xD1\x5D\xC3";

// STATUS_BREAKPOINT
// "\xcc"
unsigned char breakpoint_shellcode[] = "\xcc";


// STATUS_ILLEGAL_INSTRUCTION
unsigned char illegal_instruction_shellcode[] = "\xd1\xd1\xd1\xd1";

// STATUS_ACCESS_VIOLATION
/*
0: 31 c0	xor eax,eax
2: ff e0	jmp eax

"\x31\xc0\xff\xe0"
*/
unsigned char access_violation_shellcode[] = "\x31\xc0\xff\xe0";



// STATUS_INTEGER_DIVIDE_BY_ZERO
unsigned char int_divide_by_zero_shellcode[] = "\x31\xC0\xF7\xF0";


void* exec = 0;
unsigned int key = 0;

BOOL seh_stage_pass[] = { FALSE, FALSE, FALSE, FALSE };
DWORD seh_expected_exception[] = { STATUS_GUARD_PAGE_VIOLATION, STATUS_BREAKPOINT, STATUS_BREAKPOINT, STATUS_ILLEGAL_INSTRUCTION };
DWORD seh_shellcode_list[] = { (DWORD)get_ntdll_base, (DWORD)RtlAddVectoredExceptionHandler_shellcode, (DWORD)illegal_instruction_shellcode, (DWORD)illegal_instruction_shellcode, };
DWORD seh_shellcode_offset[] = { 1, 1, 0, 0 };
DWORD seh_shellcode_size[] = { 23, 197, 8, 8 };

BOOL veh_stage_pass[] = { FALSE, FALSE, FALSE, FALSE };
DWORD veh_expected_exception[] = { STATUS_BREAKPOINT, STATUS_ACCESS_VIOLATION, STATUS_ILLEGAL_INSTRUCTION, STATUS_INTEGER_DIVIDE_BY_ZERO };


DWORD checker_key_list[] = { 0x2c330cfd, 0x10080000, 0x0f083fce, 0x33333333 };
DWORD key_checksum[] = { 0x252d0d17, 0x253f1d15, 0xbea57768, 0xbaa5756e };



typedef struct InstructionEntryStruct
{
	const char* pLabel;

	BYTE bInstruction[16];
	DWORD dwInstructionLength;

	DWORD dwInstructionAddr;

	DWORD dwEax;
	DWORD dwEbx;
	DWORD dwEcx;
	DWORD dwEdx;
	DWORD dwEdi;
	DWORD dwEsi;
	DWORD dwInstructionFlags;
} InstructionEntryStruct;

DWORD dwGlobal_CurrInstruction = 0;
CONTEXT Global_OrigContext;

int check(unsigned char* checksum);
void xor_flag(unsigned char* encrypted_flag_key, unsigned char* encrypted_flag);

InstructionEntryStruct Global_InstructionList[] =
{
	// allocate 1kb buffer for messagebox text using GlobalAlloc
	{ "", { 0x51 }, 1, 0, 0, 0, 1024, 0, 0, 0, FLAG_ECX },									// push ecx
	{ "", { 0x51 }, 1, 0, 0, 0, GMEM_FIXED, 0, 0, 0, FLAG_ECX },							// push ecx
	{ "", { 0xFF, 0xD0 }, 2, 0, (DWORD)GlobalAlloc, 0, 0, 0, 0, 0, FLAG_EAX | FLAG_CALL },	// call eax ; (GlobalAlloc)

	// set messagebox text 
	{ "", { 0x8B, 0xD8 }, 2, 0, 0, 0, 0, 0, 0, 0, 0 },				// mov ebx, eax
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '-', 0, 0, FLAG_EDX },		// mov byte ptr [ebx], dl ;
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },					// inc ebx
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '-', 0, 0, FLAG_EDX },		// mov byte ptr [ebx], dl ;
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },					// inc ebx
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '-', 0, 0, FLAG_EDX },		// mov byte ptr [ebx], dl ;  
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },					// inc ebx
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '-', 0, 0, FLAG_EDX },		// mov byte ptr [ebx], dl ; 
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },					// inc ebx
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },		// mov byte ptr [ebx], dl ; 
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },					// inc ebx
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'Y', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'O', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'U', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '_', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'S', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'H', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'A', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'L', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'L', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '_', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'N', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'O', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'T', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '_', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'P', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'A', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'S', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'S', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '_', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '!', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '-', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '-', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '-', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '-', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '\0', 0, 0, FLAG_EDX },	// mov byte ptr [ebx], dl ; (null) 
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },					// inc ebx

	// store messagebox title ptr in edi register
	{ "", { 0x89, 0xc6 }, 2, 0, 0, 0, 0, 0, 0, 0, 0 },				// mov esi, eax


	// allocate 1kb buffer for messagebox text using GlobalAlloc
	{ "", { 0x51 }, 1, 0, 0, 0, 1024, 0, 0, 0, FLAG_ECX },									// push ecx
	{ "", { 0x51 }, 1, 0, 0, 0, GMEM_FIXED, 0, 0, 0, FLAG_ECX },							// push ecx
	{ "", { 0xFF, 0xD0 }, 2, 0, (DWORD)GlobalAlloc, 0, 0, 0, 0, 0, FLAG_EAX | FLAG_CALL },	// call eax ; (GlobalAlloc)


	{ "", { 0x8B, 0xD8 }, 2, 0, 0, 0, 0, 0, 0, 0, 0 },			// mov ebx, eax
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 25, 0, 0, FLAG_EDX },	// mov byte ptr [ebx], dl ;
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },				// inc ebx
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 129, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 59, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 179, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 151, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 235, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 147, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 148, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 175, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 251, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 160, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 255, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 49, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 44, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 34, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 39, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 169, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 242, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 226, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 150, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 185, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 122, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 39, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 160, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 164, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 243, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 159, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 146, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 170, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 106, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 141, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 248, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 37, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 28, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 152, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 103, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 111, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 198, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 123, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 238, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 244, 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '\0', 0, 0, FLAG_EDX },	// mov byte ptr [ebx], dl ; (null)  
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },					// inc ebx

	// call xor_flag
	{ "", { 0x56 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },										// push esi
	{ "", { 0x50 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },										// push eax
	{ "", { 0xFF, 0xD0 }, 2, 0, (DWORD)xor_flag, 0, 0, 0, 0, 0, FLAG_EAX | FLAG_CALL }, // call eax ; (xor_flag)

	// allocate 1kb buffer for messagebox title using GlobalAlloc
	{ "", { 0x51 }, 1, 0, 0, 0, 1024, 0, 0, 0, FLAG_ECX },									// push ecx 
	{ "", { 0x51 }, 1, 0, 0, 0, GMEM_FIXED, 0, 0, 0, FLAG_ECX },							// push ecx
	{ "", { 0xFF, 0xD0 }, 2, 0, (DWORD)GlobalAlloc, 0, 0, 0, 0, 0, FLAG_EAX | FLAG_CALL },	// call eax ; (GlobalAlloc)

	// set messagebox title 
	{ "", { 0x8B, 0xD8 }, 2, 0, 0, 0, 0, 0, 0, 0, 0 },			// mov ebx, eax
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'A', 0, 0, FLAG_EDX }, // mov byte ptr [ebx], dl ;
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },				// inc ebx
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'C', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'S', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'C', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '2', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '0', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '2', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '4', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '\0', 0, 0, FLAG_EDX },
	{ "", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },

	// store messagebox title ptr in edi register
	{ "", { 0x8B, 0xF8 }, 2, 0, 0, 0, 0, 0, 0, 0, 0 },									// mov edi, eax
	{ "", { 0x57 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },										// push edi
	{ "", { 0xFF, 0xD0 }, 2, 0, (DWORD)check, 0, 0, 0, 0, 0, FLAG_EAX | FLAG_CALL },	// call eax ; (check)

	// call MessageBoxA
	{ "", { 0x50 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },											// push eax
	{ "", { 0x57 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },											// push edi
	{ "", { 0x56 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },											// push esi
	{ "", { 0x51 }, 1, 0, 0, 0, 0, 0, 0, 0, FLAG_ECX },										// push ecx
	{ "", { 0xFF, 0xD0 }, 2, 0, (DWORD)MessageBoxA, 0, 0, 0, 0, 0, FLAG_EAX | FLAG_CALL },	// call eax; (MessageBoxA)
};



void rc4(unsigned char* key, int key_len, unsigned char* data, int data_len) 
{
	unsigned char s[256];
	unsigned char tmp = 0;
	int i = 0, j = 0, k = 0;

	// Initialization
	for (i = 0; i < 256; i++) {
		s[i] = i;
	}

	for (i = 0; i < 256; i++) {
		j = (j + s[i] + key[i % key_len]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}

	// Encryption
	i = j = 0;
	for (int idx = 0; idx < data_len; idx++) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		k = s[(s[i] + s[j]) % 256];
		data[idx] ^= k;
	}
}

void xor_flag(unsigned char* encrypted_flag_key, unsigned char* encrypted_flag)
{
	unsigned char* key_char = (unsigned char*)key_list;
	unsigned char* flag_key_char = encrypted_flag_key;
	
	rc4((unsigned char*)key_list, RC4_KEY_SIZE, encrypted_flag_key, FLAG_KEY_SIZE);
	
	for (int i = 0; i < FLAG_KEY_SIZE; i++) {
		*(encrypted_flag + i) ^= *(flag_key_char + i);
	}
}

int check(unsigned char* checksum) {
	int res = 0;
	int* ptr = (int*)checksum;

	res |= (((key_list[1]^ (int)*ptr) & 0xff) == 0x99) ? 0 : 0x10;
	res |= (((key_list[3] ^ (int)*(ptr+1)) & 0xff) == 0x4f) ? 0 : 0x10;
	res |= ((key_list[0] ^ key_list[1]) == (int)*ptr) ? 0 : 0x10;
	res |= ((key_list[2] ^ key_list[3]) == (int)*(ptr + 1)) ? 0 : 0x10;
	return res;
}

DWORD veh_stage_pass_checker(EXCEPTION_POINTERS* pExceptionInfo) {
	DWORD ExceptionCode = pExceptionInfo->ExceptionRecord->ExceptionCode;
	DWORD PreviousEip = pExceptionInfo->ContextRecord->Eip;
	DWORD NewEip = 0;

	// stage 1
	DWORD key1 = 0;
	DWORD key2 = 0;
	unsigned char* exec_ptr = 0;
	unsigned char* checker_key_ptr = 0;
	DWORD res = 0;
	DWORD checksum = 0;
	DWORD checker_key = 0;
	for (int st = 0; st < 4; st++) {
		checker_key = checker_key_list[st];
		exec_ptr = (unsigned char*)exec;
		checker_key_ptr = (unsigned char*)&checker_key;
		if ((ExceptionCode == veh_expected_exception[st]) && !veh_stage_pass[st])
		{

			for (int i = 0; i < 4; i++) {
				exec_ptr[i] ^= *(checker_key_ptr + i);
			}
			
			switch (st) {
			case 0:
				key1 = key_list[0];
				key2 = key_list[1];
				break;
			case 1:
				key1 = key_list[1];
				key2 = key_list[0];
				break;
			case 2:
				key1 = key_list[2];
				key2 = key_list[3];
				break;
			case 3:
				key1 = key_list[3];
				key2 = key_list[2];
				break;
			};

			checksum = (( ((key1 >> 24) & 0xff) | ((key1 >> 8) & 0xff00) | ((key1 << 16) & 0xffff0000) ) ^ key2) & 0xffffffff;


			if (checksum == key_checksum[st]) {
				veh_stage_pass[st] = TRUE;
				NewEip = (DWORD)exec;
			}
			break;
		}
	}
	return NewEip;
}

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo)
{
	InstructionEntryStruct* pCurrInstruction = NULL;
	DWORD NewEip = 0;

	// ensure this is a breakpoint / single step exception

	if (pExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_BREAKPOINT
		&& pExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP
		&& pExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_ACCESS_VIOLATION
		&& pExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_ILLEGAL_INSTRUCTION
		&& pExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_INTEGER_DIVIDE_BY_ZERO
		)
	{
		// this is not the exception that we expected - pass this exception to the next handler
		return EXCEPTION_CONTINUE_SEARCH;
	}

	// check the flag and jump to the new eip in the shellcode
	NewEip = veh_stage_pass_checker(pExceptionInfo);
	if (NewEip) {
		pExceptionInfo->ContextRecord->Eip = NewEip;
		return EXCEPTION_CONTINUE_EXECUTION;
	}


	// reset hardware breakpoints
	pExceptionInfo->ContextRecord->Dr0 = 0;
	pExceptionInfo->ContextRecord->Dr7 = 0;

	if (dwGlobal_CurrInstruction == 0)
	{
		// store original context
		memcpy((void*)&Global_OrigContext, (void*)pExceptionInfo->ContextRecord, sizeof(CONTEXT));
	}
	else if (dwGlobal_CurrInstruction >= (sizeof(Global_InstructionList) / sizeof(Global_InstructionList[0])))
	{
		// finished executing all instructions - restore original context
		memcpy((void*)pExceptionInfo->ContextRecord, (void*)&Global_OrigContext, sizeof(CONTEXT));

		// move to the next instruction (after int3)
		pExceptionInfo->ContextRecord->Eip++;

		// continue execution
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// get current instruction entry
	pCurrInstruction = &Global_InstructionList[dwGlobal_CurrInstruction];

	// set instruction ptr to next instruction
	pExceptionInfo->ContextRecord->Eip = pCurrInstruction->dwInstructionAddr;

	// check register flags
	if (pCurrInstruction->dwInstructionFlags & FLAG_EAX)
	{
		// set eax
		pExceptionInfo->ContextRecord->Eax = pCurrInstruction->dwEax;
	}
	else if (pCurrInstruction->dwInstructionFlags & FLAG_EBX)
	{
		// set ebx
		pExceptionInfo->ContextRecord->Ebx = pCurrInstruction->dwEbx;
	}
	else if (pCurrInstruction->dwInstructionFlags & FLAG_ECX)
	{
		// set ecx
		pExceptionInfo->ContextRecord->Ecx = pCurrInstruction->dwEcx;
	}
	else if (pCurrInstruction->dwInstructionFlags & FLAG_EDX)
	{
		// set edx
		pExceptionInfo->ContextRecord->Edx = pCurrInstruction->dwEdx;
	}
	else if (pCurrInstruction->dwInstructionFlags & FLAG_EDI)
	{
		// set edi
		pExceptionInfo->ContextRecord->Edi = pCurrInstruction->dwEdi;
	}
	else if (pCurrInstruction->dwInstructionFlags & FLAG_ESI)
	{
		// set esi
		pExceptionInfo->ContextRecord->Esi = pCurrInstruction->dwEsi;
	}

	// check if this is a 'call' instruction
	if (pCurrInstruction->dwInstructionFlags & FLAG_CALL)
	{
		// set a hardware breakpoint on the first instruction after the 'call'
		pExceptionInfo->ContextRecord->Dr0 = pCurrInstruction->dwInstructionAddr + pCurrInstruction->dwInstructionLength;
		pExceptionInfo->ContextRecord->Dr7 = 1;
	}
	else
	{
		// single step
		pExceptionInfo->ContextRecord->EFlags |= 0x100;
	}

	// move to the next instruction
	dwGlobal_CurrInstruction++;

	// continue execution
	return EXCEPTION_CONTINUE_EXECUTION;
}

DWORD GetModuleCodeSection(DWORD dwModuleBase, DWORD* pdwCodeSectionStart, DWORD* pdwCodeSectionLength)
{
	IMAGE_DOS_HEADER* pDosHeader = NULL;
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_SECTION_HEADER* pCurrSectionHeader = NULL;
	char szCurrSectionName[16];
	DWORD dwFound = 0;
	DWORD dwCodeSectionStart = 0;
	DWORD dwCodeSectionLength = 0;

	// get dos header ptr (start of module)
	pDosHeader = (IMAGE_DOS_HEADER*)dwModuleBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 1;
	}

	// get nt header ptr
	pNtHeader = (IMAGE_NT_HEADERS*)((BYTE*)pDosHeader + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return 1;
	}

	// loop through all sections
	for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		// get current section header
		pCurrSectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)pNtHeader + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

		// pCurrSectionHeader->Name is not null terminated if all 8 characters are used - copy it to a larger local buffer
		memset(szCurrSectionName, 0, sizeof(szCurrSectionName));
		memcpy(szCurrSectionName, pCurrSectionHeader->Name, sizeof(pCurrSectionHeader->Name));

		// check if this is the main code section
		if (strcmp(szCurrSectionName, ".text") == 0)
		{
			// found code section
			dwFound = 1;
			dwCodeSectionStart = dwModuleBase + pCurrSectionHeader->VirtualAddress;
			dwCodeSectionLength = pCurrSectionHeader->SizeOfRawData;

			break;
		}
	}

	// ensure the code section was found
	if (dwFound == 0)
	{
		return 1;
	}

	// store values
	*pdwCodeSectionStart = dwCodeSectionStart;
	*pdwCodeSectionLength = dwCodeSectionLength;

	return 0;
}

DWORD ScanForInstructions(DWORD ntdll_base)
{
	DWORD dwInstructionCount = 0;
	DWORD dwCurrSearchPos = 0;
	DWORD dwBytesRemaining = 0;
	DWORD dwFoundAddr = 0;
	DWORD dwCodeSectionStart = 0;
	DWORD dwCodeSectionLength = 0;

	// calculate instruction count
	dwInstructionCount = sizeof(Global_InstructionList) / sizeof(Global_InstructionList[0]);

	// find ntdll code section range
	if (GetModuleCodeSection((DWORD)ntdll_base, &dwCodeSectionStart, &dwCodeSectionLength) != 0)
	{
		return 1;
	}

	// scan for instructions
	for (DWORD i = 0; i < dwInstructionCount; i++)
	{
		// check if an address has already been found for this instruction
		if (Global_InstructionList[i].dwInstructionAddr != 0)
		{
			continue;
		}

		// find this instruction in the ntdll code section
		dwCurrSearchPos = dwCodeSectionStart;
		dwBytesRemaining = dwCodeSectionLength;
		dwFoundAddr = 0;
		for (;;)
		{
			// check if the end of the code section has been reached
			if (Global_InstructionList[i].dwInstructionLength > dwBytesRemaining)
			{
				break;
			}

			// check if the instruction exists here
			if (memcmp((void*)dwCurrSearchPos, (void*)Global_InstructionList[i].bInstruction, Global_InstructionList[i].dwInstructionLength) == 0)
			{
				dwFoundAddr = dwCurrSearchPos;
				break;
			}

			// update search indexes
			dwCurrSearchPos++;
			dwBytesRemaining--;
		}

		// ensure the opcode was found
		if (dwFoundAddr == 0)
		{
			//printf("Error: Instruction not found in ntdll: '%s'\n", Global_InstructionList[i].pLabel);

			return 1;
		}

		// store address
		Global_InstructionList[i].dwInstructionAddr = dwFoundAddr;

		// copy this instruction address to any other matching instructions in the list
		for (DWORD ii = 0; ii < dwInstructionCount; ii++)
		{
			// check if the instruction lengths match
			if (Global_InstructionList[ii].dwInstructionLength == Global_InstructionList[i].dwInstructionLength)
			{
				// check if the instruction opcodes match
				if (memcmp(Global_InstructionList[ii].bInstruction, Global_InstructionList[i].bInstruction, Global_InstructionList[i].dwInstructionLength) == 0)
				{
					// copy instruction address
					Global_InstructionList[ii].dwInstructionAddr = Global_InstructionList[i].dwInstructionAddr;
				}
			}
		}
	}

	return 0;
}


int st = 0;
int seh_handler(LPEXCEPTION_POINTERS pExceptionInfo)
{
	DWORD ExceptionCode = pExceptionInfo->ExceptionRecord->ExceptionCode;
	DWORD PreviousEip = pExceptionInfo->ContextRecord->Eip;
	DWORD NewEip = pExceptionInfo->ContextRecord->Eip;

	int* key = 0;
	unsigned char byte_key = 0;
	unsigned char* shellcode_ptr = 0;
	unsigned char* exec_ptr = 0;
	unsigned char* key_ptr = 0;
	DWORD offset = 0;
	DWORD size = 0;

	if ((ExceptionCode != STATUS_GUARD_PAGE_VIOLATION) &&
		(ExceptionCode != STATUS_BREAKPOINT) &&
		(ExceptionCode != STATUS_ILLEGAL_INSTRUCTION)) {
		return EXCEPTION_EXECUTE_HANDLER;
	}

	if ((st == 0) && (ExceptionCode == STATUS_GUARD_PAGE_VIOLATION))
	{
		goto modify_shellcode;
	}
	else if ((st == 1) && (ExceptionCode == STATUS_BREAKPOINT))
	{
		goto modify_shellcode;
	}
	else if ((st == 2) && (ExceptionCode == STATUS_BREAKPOINT))
	{
		goto modify_shellcode;
	}
	else if ((st == 3) && (ExceptionCode == STATUS_ILLEGAL_INSTRUCTION))
	{
		goto modify_shellcode;
	}
	else
	{
		goto return_to_handler;
	}

modify_shellcode:
	key = (int*)key_list[st];
	shellcode_ptr = (unsigned char*)seh_shellcode_list[st];
	key_ptr = (unsigned char*)&key;
	byte_key = *(key_ptr + 0) ^ *(key_ptr + 1) ^ *(key_ptr + 2) ^ *(key_ptr + 3);
	offset = seh_shellcode_offset[st];
	size = seh_shellcode_size[st];


	for (int i = 0; i < size; i++) {
		shellcode_ptr[i] ^= byte_key;
	}

	if ((st > 0) && (st < 4)) 
	{
		NewEip = PreviousEip & 0xfffffff0;
		memmove((void*)NewEip, (void*)(NewEip + (DWORD)seh_shellcode_offset[st - 1]), (DWORD)seh_shellcode_size[st - 1] - (DWORD)seh_shellcode_offset[st - 1]);
	}

return_to_handler:
	st++;
	return EXCEPTION_EXECUTE_HANDLER;
}


int main()
{
	LPWSTR* szArglist;
	wchar_t* endString;
	int nArgs;
	int i;
	int num;

	unsigned char* ptr;
	unsigned char* ptr2;
	DWORD oldProtection;
	DWORD ntdll_base = 0;


	printf("[+] Put 4 correct passcodes in command line arguments and you will get the flag!\n");
	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (NULL == szArglist)
	{
		printf("CommandLineToArgvW failed \n");
		return -1;
	}
	if (nArgs != 0x5)
	{
		printf("Too few arguments!\n");
		return -1;
	}
	for (i = 0; i < nArgs - 1; i++) {
		num = wcstoul(szArglist[i + 1], &endString, 16);
		printf("KEY%d: %lx\n", i, num);
		key_list[i] = num;
	}

	// Free memory allocated for CommandLineToArgvW arguments.
	LocalFree(szArglist);


	__try {
		// alloc memory to store shellcode
		exec = VirtualAlloc(0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READONLY | PAGE_GUARD);
		if (exec == 0) {
			printf("VirtualAlloc failed\n");
			exit(-1);
		}
		memset(exec, 0, 0x1000);
	}
	__except (seh_handler(GetExceptionInformation())) {
		__try {
			VirtualProtect(exec, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtection);
			memset(exec, 0, 0x1000);
			memcpy(exec, get_ntdll_base, sizeof(get_ntdll_base));
			ntdll_base = ((DWORD(*)())exec)();
		}
		__except (seh_handler(GetExceptionInformation())) {
			__try {
				ntdll_base = ((DWORD(*)())exec)();
				memcpy(exec, RtlAddVectoredExceptionHandler_shellcode, sizeof(RtlAddVectoredExceptionHandler_shellcode));
				((void(*)(DWORD))exec)((DWORD)ExceptionHandler);
			}
			__except (seh_handler(GetExceptionInformation())) {
				__try {
					((void(*)(DWORD))exec)((DWORD)ExceptionHandler);
					ScanForInstructions(ntdll_base);

					memcpy(exec, illegal_instruction_shellcode, sizeof(illegal_instruction_shellcode));
					((void(*)())exec)();
				}
				__except (seh_handler(GetExceptionInformation())) {
					printf("???\n");
				}
			}
		}
	}

	printf("See Ya!\n");

	return 0;
}