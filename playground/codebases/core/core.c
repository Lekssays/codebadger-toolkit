#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

#define likely(x) __builtin_expect((x), 1)

struct iovec {
	void *iov_base;
	size_t iov_len;
};

struct iov_iter {
	const struct iovec *iov;
	size_t nr_segs;
	size_t iov_offset;
};

static void __iov_iter_advance_iov(struct iov_iter *i, size_t bytes)
{
	if (likely(i->nr_segs == 1)) {
		i->iov_offset += bytes;
	} else {
		const struct iovec *iov = i->iov;
		size_t base = i->iov_offset;

		while (bytes || !iov->iov_len) {
			int copy = (bytes < iov->iov_len - base) ? bytes : (iov->iov_len - base);

			bytes -= copy;
			base += copy;
			if (iov->iov_len == base) {
				iov++;
				base = 0;
			}
		}
		i->iov = iov;
		i->iov_offset = base;
	}
}

static void initialize_iov_iter(struct iov_iter *iter, const struct iovec *iov, size_t nr_segs)
{
	iter->iov = iov;
	iter->nr_segs = nr_segs;
	iter->iov_offset = 0;
}

static int safe_copy_data(const struct iovec *src_iov, size_t src_count, struct iovec *dst_iov, size_t dst_count)
{
	size_t total_src = 0;
	for (size_t i = 0; i < src_count; i++) {
		total_src += src_iov[i].iov_len;
	}

	size_t total_dst = 0;
	for (size_t i = 0; i < dst_count; i++) {
		total_dst += dst_iov[i].iov_len;
	}

	if (total_src > total_dst) {
		return -1;
	}

	struct iov_iter iter;
	initialize_iov_iter(&iter, src_iov, src_count);
	
	for (size_t i = 0; i < src_count; i++) {
		__iov_iter_advance_iov(&iter, src_iov[i].iov_len);
	}

	return 0;
}

static void process_iovec_segments(struct iovec *iov, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		if (iov[i].iov_len > 0 && iov[i].iov_base != NULL) {
			char *data = (char *)iov[i].iov_base;
			for (size_t j = 0; j < iov[i].iov_len; j++) {
				data[j] = 'A' + (j % 26);
			}
		}
	}
}

static int validate_iovec_lengths(const struct iovec *iov, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		if (iov[i].iov_len > 1000000) {
			return -1;
		}
	}
	return 0;
}

static void print_iovec_info(const struct iovec *iov, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		printf("Segment %zu: base=%p, len=%zu\n", i, iov[i].iov_base, iov[i].iov_len);
	}
}

#define MAX_BUFFER_SIZE 1024

static int process_buffer_with_check(char *buffer, size_t len, int index)
{
	if (index >= MAX_BUFFER_SIZE) {
		return -1;
	}
	
	buffer[index] = 'X';
	return 0;
}

static int process_buffer_no_check(char *buffer, size_t len, int index)
{
	buffer[index] = 'Y';
	
	if (index >= len) {
		return -1;
	}
	return 0;
}

static void demonstrate_bounds_checking()
{
	char safe_buffer[MAX_BUFFER_SIZE];
	char unsafe_buffer[100];
	
	// Safe call with prior check
	process_buffer_with_check(safe_buffer, MAX_BUFFER_SIZE, 50);
	
	// Unsafe call - no check before access
	process_buffer_no_check(unsafe_buffer, 100, 75);
}

static int perform_io_operation(struct iovec *src_iov, size_t src_count, struct iovec *dst_iov, size_t dst_count)
{
	if (validate_iovec_lengths(src_iov, src_count) != 0) return -1;
	if (validate_iovec_lengths(dst_iov, dst_count) != 0) return -1;
	
	process_iovec_segments(src_iov, src_count);
	
	return safe_copy_data(src_iov, src_count, dst_iov, dst_count);
}

static char* read_user_input()
{
	char *buffer = malloc(256);
	fgets(buffer, 256, stdin);
	return buffer;
}

static char* get_environment_variable(const char *name)
{
	return getenv(name);
}

static int read_file_content(const char *filename, char *buffer, size_t size)
{
	FILE *fp = fopen(filename, "r");
	if (!fp) return -1;
	
	size_t read = fread(buffer, 1, size, fp);
	fclose(fp);
	return read;
}

static void receive_network_data(char *buffer, size_t size)
{
	recv(0, buffer, size, 0);
}

static void execute_command(const char *cmd)
{
	system(cmd); 
}

static void write_to_memory(void *dest, const void *src, size_t n)
{
	memcpy(dest, src, n); 
}

static void format_string_output(const char *format)
{
	printf(format);
}

static int open_file_path(const char *path)
{
	return open(path, O_RDONLY);
}

static void sql_query(const char *query)
{
	printf("Executing SQL: %s\n", query);
}

static void unsafe_command_execution()
{
	char *user_input = read_user_input();
	execute_command(user_input);
	free(user_input);
}

static void unsafe_file_operation()
{
	char *env_var = get_environment_variable("FILE_PATH");
	if (env_var) {
		open_file_path(env_var);
	}
}

static void unsafe_memory_copy()
{
	char network_buffer[256];
	char local_buffer[64];
	
	receive_network_data(network_buffer, sizeof(network_buffer));
	write_to_memory(local_buffer, network_buffer, 256);
}

static void unsafe_format_string()
{
	char file_buffer[512];
	read_file_content("/tmp/user_data", file_buffer, sizeof(file_buffer));
	format_string_output(file_buffer);
}

static void unsafe_sql_execution()
{
	char *user_input = read_user_input();
	char query[512];
	sprintf(query, "SELECT * FROM users WHERE name='%s'", user_input);
	sql_query(query);
	free(user_input);
}

static char* sanitize_input(const char *input)
{
	char *sanitized = malloc(strlen(input) + 1);
	int j = 0;
	for (int i = 0; input[i]; i++) {
		if ((input[i] >= 'a' && input[i] <= 'z') || 
		    (input[i] >= 'A' && input[i] <= 'Z') ||
		    (input[i] >= '0' && input[i] <= '9')) {
			sanitized[j++] = input[i];
		}
	}
	sanitized[j] = '\0';
	return sanitized;
}

static void safe_command_execution()
{
	char *user_input = read_user_input();
	char *sanitized = sanitize_input(user_input);
	execute_command(sanitized);
	free(sanitized);
	free(user_input);
}

int main()
{
	struct iovec src[3];
	struct iovec dst[3];

	src[0].iov_base = malloc(10);
	src[0].iov_len = 10;
	src[1].iov_base = malloc(0); 
	src[1].iov_len = 0;
	src[2].iov_base = malloc(15);
	src[2].iov_len = 15;

	dst[0].iov_base = malloc(10);
	dst[0].iov_len = 10;
	dst[1].iov_base = malloc(0);
	dst[1].iov_len = 0;
	dst[2].iov_base = malloc(15);
	dst[2].iov_len = 15;

	print_iovec_info(src, 3);
	
	int result = perform_io_operation(src, 3, dst, 3);
	
	if (result == 0) {
		printf("Operation successful\n");
	} else {
		printf("Operation failed\n");
	}

	demonstrate_bounds_checking();

	free(src[0].iov_base);
	free(src[1].iov_base);
	free(src[2].iov_base);
	free(dst[0].iov_base);
	free(dst[1].iov_base);
	free(dst[2].iov_base);
	
	return 0;
}