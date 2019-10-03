#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>


#define BUFSTR_LEN 32
#define STD_POLL_INTERVAL 1
#define STD_SYSTEM_WAIT_INTERVAL 1
#define MAX_PROC_NUM 128
#define MAX_PROC_NAME 64
#define MAX_CMD_LINE 1024
#define LOG_STR_LEN 256


typedef struct Args
{
    char config_file[PATH_MAX];
    char log_file[PATH_MAX];
    unsigned int poll_interval;
    unsigned int system_wait_interval;
} Args_t;

typedef struct ProcAttrs
{
    pid_t pid;
    char proc_name[MAX_PROC_NAME];
    char logging; // Boolean.
    char need_restart; // Boolean.
    char cmd_line[MAX_CMD_LINE];
} ProcAttrs_t;


static FILE *config_file = NULL;
static FILE *log_file = NULL;
static const char *opt_string = "c:l:i:w:";
static ProcAttrs_t proc_attrs[MAX_PROC_NUM];
static unsigned int proc_attrs_size = 0;
static Args_t args;
static char log_str[LOG_STR_LEN];


void parse_args(int argc, char *argv[], Args_t *args);
void daemon_stop(int sig_num);
pid_t get_pid_by_name(const char *proc_name);
int get_cmd_line(pid_t pid, char *cmd_line);
int parse_config(void);
void main_loop(void);
void print_to_log(const char *line);


int main(int argc, char *argv[])
{
    signal(SIGINT, daemon_stop);
    signal(SIGTERM, daemon_stop);

    parse_args(argc, argv, &args);

    // Open configuration and logging files.
    log_file = fopen(args.log_file, "w");
    if (log_file == NULL) {
        return -1;
    }
    config_file = fopen(args.config_file, "r");
    if (config_file == NULL) {
        print_to_log("Can't open configuration file\n");
        fclose(log_file);
        return -1;
    }

    if (parse_config() == -1) {
        return -1;
    }

    main_loop();

    return 0;
}


void parse_args(int argc, char *argv[], Args_t *args)
{
    int opt = 0;
    args->poll_interval = STD_POLL_INTERVAL;
    args->system_wait_interval = STD_SYSTEM_WAIT_INTERVAL;
    while ((opt = getopt(argc, argv, opt_string)) != -1) {
        switch (opt) {
        case 'c':
            memmove(args->config_file, optarg, strlen(optarg) + 1);
            break;

        case 'l':
            memmove(args->log_file, optarg, strlen(optarg) + 1);
            break;
        
        case 'i':
            sscanf(optarg, "%u", &args->poll_interval);
            break;
        
        case 'w':
            sscanf(optarg, "%u", &args->system_wait_interval);
            break;
        }
    }
}

void daemon_stop(int sig_num)
{
    fclose(config_file);
    fclose(log_file);
    exit(0);
}

pid_t get_pid_by_name(const char *proc_name)
{
    pid_t pid = -1;
    char path_to_pid[PATH_MAX];
    snprintf(path_to_pid, PATH_MAX, "/var/run/%s.pid", proc_name);
    FILE *pid_file = fopen(path_to_pid, "r");
    if (pid_file == NULL) {
        snprintf(log_str,
                 LOG_STR_LEN,
                 "Can't open PID file for %s\n",
                 proc_name);
        print_to_log(log_str);
        goto err;
    }

    char pid_str[16];
    if (fgets(pid_str, sizeof(pid_str), pid_file)) {
        sscanf(pid_str, "%d", &pid);
    
    } else if (ferror(pid_file)) {
        print_to_log("Error occurred while parsing *.pid file\n");
        goto err;
    }

err:
    if (pid_file) {
        fclose(pid_file);
    }
    return pid;
}

int get_cmd_line(pid_t pid, char *cmd_line)
{
    int result = -1;

    char path_to_line[PATH_MAX];
    snprintf(path_to_line, PATH_MAX, "/proc/%d/cmdline", pid);
    FILE *line_file = fopen(path_to_line, "rb");
    if (line_file == NULL) {
        snprintf(log_str,
                 LOG_STR_LEN,
                 "Can't open cmdline file for PID %d, "
                 "ignoring current process\n", pid);
        print_to_log(log_str);
        goto err;
    }

    size_t bytes_num = fread(cmd_line, 1, MAX_CMD_LINE, line_file);
    for (int i = 0; i < MAX_CMD_LINE - 1; i++) {
        if (cmd_line[i] == '\0' && cmd_line[i + 1] != '\0') {
            cmd_line[i] = ' ';
        
        } else if (cmd_line[i] == '\0' && cmd_line[i + 1] == '\0') {
            break;
        }
    }

    if (bytes_num < MAX_CMD_LINE && ferror(line_file)) {
        snprintf(log_str,
                 LOG_STR_LEN,
                 "Error occurred while reading /proc/%d/cmdline\n", pid);
        print_to_log(log_str);
        goto err;
    }

    result = 0;
    
err:
    if (line_file) {
        fclose(line_file);
    }
    return result;
}

int parse_config(void)
{
    char first_flag;
    char second_flag;
    char bufstr[BUFSTR_LEN];
    int i = 0;
    while (!feof(config_file)) {
        first_flag = second_flag = '\0';

        if (!fgets(bufstr, sizeof(bufstr), config_file)) {
            if (ferror(config_file)) {
                print_to_log(
                        "Error occurred while reading configuration file\n");
                return -1;
            }
            continue;
        }
        
        sscanf(bufstr,
               "%63s %c %c",
               proc_attrs[i].proc_name,
               &first_flag,
               &second_flag);

        proc_attrs[i].pid = get_pid_by_name(proc_attrs[i].proc_name);
        if (proc_attrs[i].pid < 0) {
            snprintf(log_str,
                     LOG_STR_LEN,
                     "Error: Can't find PID by process name for %s, "
                     "ignoring current process\n",
                     proc_attrs[i].proc_name);
            print_to_log(log_str);
            continue;
        }

        switch (first_flag) {
        case 'L':
            proc_attrs[i].logging = 1;
            break;

        case 'R':
            proc_attrs[i].need_restart = 1;
            if (get_cmd_line(proc_attrs[i].pid,
                             proc_attrs[i].cmd_line) == -1) {
                continue;
            }
            break;

        default:
            bufstr[strlen(bufstr) - 1] = '\0';
            snprintf(log_str,
                     LOG_STR_LEN,
                     "Line \"%s\" - wrong flags, "
                     "ignoring current process\n",
                     bufstr);
            print_to_log(log_str);
            continue;
        }

        if (proc_attrs[i].logging || proc_attrs[i].need_restart) {
            switch (second_flag) {
            case 'L':
                proc_attrs[i].logging = 1;
                break;

            case 'R':
                proc_attrs[i].need_restart = 1;
                if (get_cmd_line(proc_attrs[i].pid,
                                 proc_attrs[i].cmd_line) == -1) {
                    continue;
                }
                break;

            case '\0':
                break;

            default:
                bufstr[strlen(bufstr) - 1] = '\0';
                snprintf(log_str,
                         LOG_STR_LEN,
                         "Line \"%s\" - wrong flags, "
                         "ignoring current process\n",
                         bufstr);
                print_to_log(log_str);
                continue;
            }
        }
        
        i += 1;
    }

    proc_attrs_size = i;
    return 0;
}

void main_loop(void)
{
    while (1) {
        for (int i = 0; i < proc_attrs_size; i++) {
            if (proc_attrs[i].pid == -1) {
                continue; // Skip deleted process.
            }

            if (kill(proc_attrs[i].pid, 0) == -1) {
                if (proc_attrs[i].logging) {
                    snprintf(log_str,
                             LOG_STR_LEN,
                             "Process \"%s\" terminated\n",
                             proc_attrs[i].proc_name);
                    print_to_log(log_str);
                }

                if (proc_attrs[i].need_restart) {
                    if (system(proc_attrs[i].cmd_line) != 0) {
                        snprintf(log_str,
                                 LOG_STR_LEN,
                                 "Error occurred while \"%s\" start\n",
                                 proc_attrs[i].proc_name);
                        print_to_log(log_str);

                        proc_attrs[i].pid = -1; // Mark process as deleted.
                    
                    } else {
                        sleep(args.system_wait_interval);
                        proc_attrs[i].pid =
                                get_pid_by_name(proc_attrs[i].proc_name);
                    }
                
                } else {
                    proc_attrs[i].pid = -1; // Mark process as deleted.
                }
            }
        }

        sleep(args.poll_interval);
    }
}

void print_to_log(const char *line)
{
    fprintf(log_file, "%s", line);
    fflush(log_file);
}
