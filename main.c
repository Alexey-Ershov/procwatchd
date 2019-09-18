#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/inotify.h>


#define MAX_EVENTS 1024 /*Максимальное кличество событий для обработки за один раз*/
#define EVENT_SIZE  ( sizeof (struct inotify_event) ) /*размер структуры события*/
#define BUF_LEN     ( MAX_EVENTS * ( EVENT_SIZE + PATH_MAX )) /*буфер для хранения данных о событиях*/


typedef struct args
{
    char config_file[PATH_MAX];
    char log_file[PATH_MAX];
} Args_t;

int open_inotify_fd(void);
void parse_args(int argc, char *argv[], Args_t *args);
void daemon_stop(int sig_num);

static FILE *config_file = NULL;
static FILE *log_file = NULL;
static const char *opt_string = "c:l:";
static int fd = 0;
static int wd = 0;


int main(int argc, char *argv[])
{
    Args_t args;
    parse_args(argc, argv, &args);

    // Open configuration and logging files.
    config_file = fopen(args.config_file, "w");
    if (config_file == NULL) {
        fprintf(stderr, "Can't open configuration file\n");
        return -1;
    }
    log_file = fopen(args.log_file, "w");
    if (log_file == NULL) {
        fprintf(stderr, "Can't open logging file\n");
        return -1;
    }

    signal(SIGINT, daemon_stop);
    signal(SIGTERM, daemon_stop);
    
    // Inotify work start.
    fd = inotify_init();
    if (fd < 0) {
        fprintf(log_file, "inotify_init() = %s\n", strerror(errno));
    }

    wd = inotify_add_watch(fd, "/home/alex/test", IN_CREATE | IN_MODIFY | IN_DELETE);
    if (wd == -1) {
        printf("Couldn't add watch to %s\n", "/home/alex/test");
    }

    while (1) {
        int i = 0;
        char buffer[BUF_LEN];
        int length = read(fd, buffer, BUF_LEN);

        if (length < 0) {
            perror( "read" );
        }

        while (i < length) {
            struct inotify_event *event = (struct inotify_event *) &buffer[i];
            
            if (event->len) {
                if (event->mask & IN_CREATE) {
                    if (event->mask & IN_ISDIR) {
                        printf("The directory %s was Created.\n", event->name);       
                    
                    } else {
                        printf("The file %s was Created with WD %d\n", event->name, event->wd);       
                    }
                }

                if (event->mask & IN_MODIFY) {
                    if (event->mask & IN_ISDIR) {
                        printf( "The directory %s was modified.\n", event->name );       
                    
                    } else {
                        printf( "The file %s was modified with WD %d\n", event->name, event->wd );       
                    }
                }
              
                if (event->mask & IN_DELETE) {
                    if (event->mask & IN_ISDIR) {
                        printf( "The directory %s was deleted.\n", event->name );       
                    
                    } else {
                        printf( "The file %s was deleted with WD %d\n", event->name, event->wd );       
                    }
                }
                
                i += EVENT_SIZE + event->len;
            }
        }
    }

    return 0;
}


void parse_args(int argc, char *argv[], Args_t *args)
{
    int opt = 0;
    while ((opt = getopt(argc, argv, opt_string)) != -1) {
        switch (opt) {
        case 'c':
            memmove(args->config_file, optarg, strlen(optarg) + 1);
            break;
        case 'l':
            memmove(args->log_file, optarg, strlen(optarg) + 1);
            break;
        }
    }
}

void daemon_stop(int sig_num)
{
    printf("Daemon stop <\n");

    inotify_rm_watch(fd, wd);
    close(fd);
    fclose(config_file);
    fclose(log_file);

    printf("Daemon stop >\n");

    exit(0);
}
