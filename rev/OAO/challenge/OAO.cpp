#include <sys/types.h>
#include <sys/stat.h>
#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <iostream>

using std::string;

static void	extract(const char *filename, int do_extract, int flags);
static int	copy_data(struct archive *, struct archive *);
static void	usage(void);
static void	warn(string);
static void	fail(string, int);
static int verbose = 0;

static int
copy_data(struct archive *ar, struct archive *aw)
{
	int r;
	const void *buff;
	size_t size;
	int64_t offset;

	for (;;) {
		r = archive_read_data_block(ar, &buff, &size, &offset);
		if (r == ARCHIVE_EOF)
			return (ARCHIVE_OK);
		if (r != ARCHIVE_OK)
			return (r);
		r = archive_write_data_block(aw, buff, size, offset);
		if (r != ARCHIVE_OK) {
			warn("write data");
			//    archive_error_string(aw));
			return (r);
		}
	}
}

static void
extract(const char *filename, int do_extract, int flags)
{
	struct archive *a;
	struct archive *ext;
	struct archive_entry *entry;
	int r;

	a = archive_read_new();
	ext = archive_write_disk_new();
	archive_write_disk_set_options(ext, flags);

	archive_read_support_format_all(a);

	if ((r = archive_read_open_filename(a, filename, 10240)))
		fail("open file", r);
	for (;;) {
		r = archive_read_next_header(a, &entry);
		if (r == ARCHIVE_EOF)
			break;
		if (r != ARCHIVE_OK)
			fail("read next header", 1);
		if (verbose && do_extract)
			std::cout << "x ";
		if (verbose || !do_extract)
			std::cout << archive_entry_pathname(entry);
		if (do_extract) {
			r = archive_write_header(ext, entry);
			if (r != ARCHIVE_OK)
				warn("write header");
				    //archive_error_string(ext));
			else {
				copy_data(a, ext);
				r = archive_write_finish_entry(ext);
				if (r != ARCHIVE_OK)
					fail("write finish entry", 1);
					    //archive_error_string(ext), 1);
			}

		}
		if (verbose || !do_extract)
			std::cout << std::endl;
	}

	archive_read_close(a);
	archive_read_free(a);
	
	archive_write_close(ext);
  	archive_write_free(ext);
	exit(0);
}

int
main(int argc, const char **argv)
{
	const char *filename = NULL;
	int compress, flags, mode, opt;
	
	mode = 'x';
	verbose = 0;
	compress = '\0';
	flags = ARCHIVE_EXTRACT_TIME;

	while (*++argv != NULL && **argv == '-') {
		const char *p = *argv + 1;

		while ((opt = *p++) != '\0') {
			switch (opt) {
				case 'f':
					if (*p != '\0')
						filename = p;
					else
						filename = *++argv;
					p += strlen(p);
					break;
				case 'p':
					flags |= ARCHIVE_EXTRACT_PERM;
					flags |= ARCHIVE_EXTRACT_ACL;
					flags |= ARCHIVE_EXTRACT_FFLAGS;
					break;
				case 't':
					mode = opt;
					break;
				case 'v':
					verbose++;
					break;
				case 'x':
					mode = opt;
					break;
				default:
					usage();
			}
		}
	}

	if(filename == NULL || strcmp(filename, "-") == 0)
		usage();

	switch (mode) {
		case 't':
			extract(filename, 0, flags);
			break;
		case 'x':
			extract(filename, 1, flags);
			break;
	}

	return (0);
}


static void
warn(string m)
{
	std::cerr << "failed: " << m << std::endl;
}

static void
fail(string m, int r)
{
	std::cerr << "failed: " << m << std::endl;
	exit(r);
}

static void
usage(void)
{
	std::cerr <<  "Usage: unOAO [-tvx] [-f file]\n";
	exit(1);
}