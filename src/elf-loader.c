// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>
#include <stdint.h>
#include <sys/random.h>

void push64(void **sp, Elf64_Addr v)
{
	*sp = (void *)((char *)(*sp) - 8);
	*(Elf64_Addr *)(*sp) = v;
}

void *map_elf(const char *filename)
{
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	void *elf_contents = map_elf(filename);
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_contents; // header elf 64-bit de la inceputul fisierului
	Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_contents + ehdr->e_phoff); // inceput program headers

	size_t page_size = (size_t)sysconf(_SC_PAGESIZE); // dimensiunea paginii de memorie

	// task1

	if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
	    ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3) {
		fprintf(stderr, "Not a valid ELF file\n"); // verific ELF
		exit(3);
	}

	// accept doar ELF 64-bit
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}

	// accept doar executabile si ET_DYN (pentru task5)
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		exit(2);

	// task5
	Elf64_Addr base_addr = 0; // pentru ET_EXEC ramane 0

	if (ehdr->e_type == ET_DYN) {
		Elf64_Addr min_addr = (Elf64_Addr)-1; // cel mai mic p_vaddr din PT_LOAD
		Elf64_Addr max_addr = 0; // cel mai mare capăt (p_vaddr + p_memsz)

		// calculez intervalul total de adrese acoperit de segmentele PT_LOAD
		for (int i = 0; i < ehdr->e_phnum; i++) {
			Elf64_Phdr *ph = &phdr[i];

			if (ph->p_type != PT_LOAD)
				continue;

			Elf64_Addr s = ph->p_vaddr;
			Elf64_Addr e = s + ph->p_memsz;

			if (s < min_addr)
				min_addr = s;
			if (e > max_addr)
				max_addr = e;
		}

		// ET_DYN fara PT_LOAD nu are sens
		if (min_addr == (Elf64_Addr)-1)
			exit(2);

		Elf64_Addr map_start = (Elf64_Addr)((min_addr / page_size) * page_size); // adresa de inceput a paginii care contine min_addr (aliniere in jos)

		size_t total_size = (size_t)(max_addr - map_start); // lungimea totala si rotunjesc in sus la pagina

		if (total_size % page_size != 0)
			total_size = ((total_size / page_size) + 1) * page_size;

		// rezerv memorie pentru intreg intervalul [min_addr, max_addr)
		void *probe = mmap(NULL, total_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (probe == MAP_FAILED) {
			perror("mmap");
			exit(2);
		}

		base_addr = (Elf64_Addr)(unsigned long)probe - map_start; // unde am rezervat-unde ar fi vrut ELF-ul sa inceapa
	}

	// task2 si task3

	for (int i = 0; i < ehdr->e_phnum; i++) {
		Elf64_Phdr *ph = &phdr[i]; // pointer la program header-ul curent

		if (ph->p_type != PT_LOAD)
			continue; // se ignora segmenetele non-load

		// adresa virtuala dorita dupa realocare
		Elf64_Addr vaddr = ph->p_vaddr + base_addr;

		// inceput segment aliniat in jos la pagina
		Elf64_Addr seg_start = (Elf64_Addr)((vaddr / page_size) * page_size);

		size_t offset_in_page = (size_t)(vaddr - seg_start); // cat sa sarim de la inceputul paginii pana la segment
		size_t map_needed = offset_in_page + ph->p_memsz; // tot ce trebuie in memorie

		// lungime mapata rotunjita in sus la multiplu de pagina
		size_t map_len = map_needed;

		if (map_len % page_size != 0)
			map_len = ((map_len / page_size) + 1) * page_size;

		// mapez memorie anonima la adresa calculata (MAP_FIXED)
		void *mapped = mmap((void *)seg_start, map_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

		if (mapped == MAP_FAILED) {
			perror("mmap");
			exit(2);
		}

		// copiez continutul segementului din fisier daca exista
		if (ph->p_filesz > 0)
			memcpy((char *)mapped + offset_in_page, (char *)elf_contents + ph->p_offset, (size_t)ph->p_filesz);

		// umplu cu 0 restul fisierului
		if (ph->p_memsz > ph->p_filesz)
			memset((char *)mapped + offset_in_page + ph->p_filesz, 0, (size_t)(ph->p_memsz - ph->p_filesz));

		// calculez permisiunile finale
		int prot = 0;

		if (ph->p_flags & PF_R)
			prot |= PROT_READ;
		if (ph->p_flags & PF_W)
			prot |= PROT_WRITE;
		if (ph->p_flags & PF_X)
			prot |= PROT_EXEC;

		// aplic permisiunile corecte
		if (mprotect((void *)seg_start, map_len, prot) != 0) {
			perror("mprotect");
			exit(2);
		}
	}

	// task 4 si 5 (pentru stiva si auxv cu base_addr)

	size_t stack_size = 8 * 1024 * 1024; // 8MB stack pentru programul incarcat

	void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);

	if (stack == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	// rsp porneste de la varful stack-ului aliniat la 16 bytes
	unsigned long sp_val = (unsigned long)stack + stack_size;

	sp_val = (sp_val / 16) * 16;
	void *sp = (void *)sp_val;



	int env_count = 0; // pentru numararea variabilelor de mediu

	while (envp && envp[env_count])
		env_count++;

	// AT_RANDOM: pentru comportament kernelului
	sp = (void *)((char *)sp - 16);
	unsigned char *at_rand_area = (unsigned char *)sp;

	ssize_t gr = getrandom(at_rand_area, 16, 0); // pun 16 bytes random pe stack si tin pointerul in auxv

	if (gr != 16)
		exit(2);
	Elf64_Addr at_random_ptr = (Elf64_Addr)(unsigned long)at_rand_area;

	// calculez adresa in memorie a vectorului de program headers
	Elf64_Addr at_phdr = 0; // adresa finala
	Elf64_Off ph_tbl_off = ehdr->e_phoff; // offsetul tabelei de program headers
	Elf64_Xword ph_tbl_len = (Elf64_Xword)ehdr->e_phnum * ehdr->e_phentsize; // dimensiunea totala a program table header

	for (int i = 0; i < ehdr->e_phnum && !at_phdr; i++) {
		Elf64_Phdr *ph = &phdr[i]; // program header curent

		// doar segmentele incarcate
		if (ph->p_type != PT_LOAD)
			continue;

		Elf64_Off fstart = ph->p_offset; // inceputul segmentului in fisier
		Elf64_Off fend = ph->p_offset + ph->p_filesz; // sfarsitul segmentului din fisier

		// verific daca intreaga tabela se ala in interiorul acestui segment PT_LOAD
		if (ph_tbl_off >= fstart && (ph_tbl_off + ph_tbl_len) <= fend)
			at_phdr = ph->p_vaddr + (ph_tbl_off - fstart); // se calculeaza adresa virtuala corespunzatoare PHT in memorie
	}

	// daca nu am gasit in PT_LOAD caut
	if (!at_phdr) {
		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type == PT_PHDR) {
				at_phdr = phdr[i].p_vaddr;
				break;
			}
		}
	}

	if (at_phdr)
		at_phdr += base_addr; // ajustez cu base_addr pentru ET_DYN

	// entry point efectiv (realocat)
	Elf64_Addr at_entry = ehdr->e_entry + base_addr;
	void (*entry)(void) = (void (*)(void))(unsigned long)at_entry;

	// auxv ordonat invers pe stack si terminat cu AT_NULL
	push64(&sp, 0); // valoare pentru AT_NULL
	push64(&sp, AT_NULL); // marcheaza sfarsitul auxv
	push64(&sp, at_random_ptr); // pointer la cei 16 butes random
	push64(&sp, AT_RANDOM); // intrare AT_RANDOM
	push64(&sp, (Elf64_Addr)page_size); // dimensiunea paginii
	push64(&sp, AT_PAGESZ);
	push64(&sp, at_entry); // adresa entry pointului ELF
	push64(&sp, AT_ENTRY);
	push64(&sp, (Elf64_Addr)ehdr->e_phnum); // numarul de program headers
	push64(&sp, AT_PHNUM);
	push64(&sp, (Elf64_Addr)sizeof(Elf64_Phdr)); // dimensiunea unui program header
	push64(&sp, AT_PHENT);
	if (at_phdr) {
		push64(&sp, at_phdr); // adresa in memorie a program header table
		push64(&sp, AT_PHDR);
	}
	push64(&sp, (Elf64_Addr)geteuid()); // effictive UID
	push64(&sp, AT_EUID);
	push64(&sp, (Elf64_Addr)getuid()); // real UID
	push64(&sp, AT_UID);
	push64(&sp, (Elf64_Addr)getegid()); // effective GID
	push64(&sp, AT_EGID);
	push64(&sp, (Elf64_Addr)getgid()); // real GID
	push64(&sp, AT_GID);

	push64(&sp, 0); // NULL dupa envp

	// envp in ordine inversa
	for (int i = env_count - 1; i >= 0; i--)
		push64(&sp, (Elf64_Addr)(unsigned long)envp[i]);

	// NULL dupa argv
	push64(&sp, 0);

	// primul argument: calea ELF-ului
	for (int i = argc - 1; i >= 0; i--)
		push64(&sp, (Elf64_Addr)(unsigned long)argv[i]);

	// argc
	push64(&sp, (Elf64_Addr)argc);

	__asm__ __volatile__(
		"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
