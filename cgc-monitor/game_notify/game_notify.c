#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/inotify.h>
/*
Watch a directory from new games, optionally starting by watching
an existng game directory.  Each time a new game appears, a
game_listener process is created to process its config file.
If old game_listeners are killed when new games appear, but they
are given a chance to complete their processing.
*/

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

int gl_pid = 0;
int is_proxy = 0;
char *proxy_dest=NULL;
void usage(){
    printf("game_notify <game_list_dir> [<init_game> | proxy <monitor>]\n");
    printf("\tWhere game_list_dir is where to listen for new games\n");
    printf("\tand init_game is an optional inital game directory to process.\n");
    printf("\tThe optional 'proxy' argument causes directories & files to be copied\n");
    printf("\tto the given monitor server (using the same file hierarchy)\n");
    exit(0);
}
/*
Create a game_listener process to handle any config files
found in a given game directory, and to watch for new config
files that may appear there.
*/
int create_game_listener(char *game_list_dir, char *gname){
   int status;
   int result = 0;
   if(gl_pid != 0){
      /* already a listener, kill it and wait for it to finish. */
      kill(gl_pid, SIGUSR1);
      int done = 0;
      while(!done){
         printf("wait for child to exit\n");
         fflush(stdout);
         sleep(1);
         waitpid(gl_pid, &status, 0);
         if(WIFEXITED(status)){
            gl_pid = 0;
            printf("child is now dead\n");
            done=1;
         }
      }
          
   }     
   char *game_listener = "game_listener";
   char *cargv [5];
   char game_path[1024];
   int dlen, glen;
   dlen = strlen(game_list_dir);
   glen = strlen(gname);
   if((dlen+glen) > sizeof(game_path)){
       fprintf(stderr, "game_list_dir, gname too long %s\n", game_list_dir);
       exit(1);
   }
   sprintf(game_path,"%s/%s", game_list_dir, gname);
   printf("in create_game_listener\n");
   cargv[0] = "game_listener";
   cargv[1] = game_path;
   if(is_proxy){
      cargv[2] = "proxy";
      cargv[3] = proxy_dest;
      cargv[4] = NULL;
   }else{
      cargv[2] = NULL;
   }
   gl_pid = fork();
   if(gl_pid == 0){
      /* in child */
      pid_t child_pid = getpid();
      printf("about to exec, pid is %d\n", child_pid);
      //VERIFY(execv, "/usr/bin/cb-server", cargv);
      execv("/usr/bin/game_listener",cargv);
      fprintf(stderr, "exec failed %s\n", strerror(errno));
      exit(1); /* only if execv fails */
   }else{
      printf("created listener, pid %d\n", gl_pid);
   }
   fflush(stdout);
   return result;
}
int proxyDir(char *game_list_dir, char *gname){
   char cmd[2048];
   int result;
   sprintf(cmd, "ssh cgcwf@%s mkdir -p -m 777 %s/%s", proxy_dest, game_list_dir, gname);
   fprintf(stdout, "in  proxyDir for command %s\n", cmd);
   result = system(cmd);
   if(result != 0){
      fprintf(stderr, "failed proxy command %s error %d\n", cmd, result);
      exit(1);
   }
}
int main(int argc, char **argv)
{
  int length, i = 0;
  int fd;
  int wd;
  char buffer[EVENT_BUF_LEN];
  static struct timeval the_time;
  if(argc < 2){
     fprintf(stderr, "not enough arguments\n");
     usage();
  }  
  char *game_list = argv[1];
  //char *init_game = NULL;
  int init_game_arg = 0;
  gettimeofday(&the_time, NULL);
  printf("[%u.%06u] game_notify Start, game_list %s num_args is %d\n", (unsigned)the_time.tv_sec, (unsigned)the_time.tv_usec, game_list, argc);
  fflush(stdout);
  if(argc >= 3){
     if(argc >= 3 && !strncmp(argv[3], "proxy", 5)){
         /* initial game to monitor */
         fprintf(stderr, "Run as proxy, with initial game of %s\n", argv[2]);
         init_game_arg = 2;
         is_proxy = 1;
         proxy_dest = argv[4];
     }else if(argc == 4){
        if(!strncmp(argv[2], "proxy", 5)){
           fprintf(stderr, "Run as proxy, no initial game, will wait for new one\n");
           is_proxy = 1;
           proxy_dest = argv[3];
        }else{
           fprintf(stderr, "four arguments, thrid not proxy\n");
           usage();
        }
     }else{
        fprintf(stderr, "more than 4 args\n");
        usage();
     }
  }

  /*creating the INOTIFY instance*/
  fd = inotify_init();

  /*checking for error*/
  if ( fd < 0 ) {
    perror( "inotify_init" );
  }

  wd = inotify_add_watch( fd, game_list, IN_CREATE );
  int result = 0;
  if(init_game_arg > 0){
     /* Initial game directory given, handle its content */
     if(is_proxy == 0){
        int i = init_game_arg;
        printf("Create listeners for existing games, start with %s, count %d through %d\n", argv[i], i, argc);
        while(i < argc){
           result = create_game_listener(game_list, argv[i]);
           sleep(5);
           i++;
        }
     }else{
        printf("Create listener for first proxied directory\n");
        proxyDir(game_list, argv[init_game_arg]);
        result = create_game_listener(game_list, argv[init_game_arg]);
     }
  }
  while(result == 0){
     /* blocking read */
     gettimeofday(&the_time, NULL);
     printf("[%u.%06u] game_notify do blocking read\n", (unsigned)the_time.tv_sec, (unsigned)the_time.tv_usec);
     length = read( fd, buffer, EVENT_BUF_LEN ); 
   
     /*checking for error*/
     if ( length < 0 ) {
       perror( "read" );
     }  
   
     gettimeofday(&the_time, NULL);
     printf("[%u.%06u] game_notify read %d items\n", (unsigned)the_time.tv_sec, (unsigned)the_time.tv_usec, length);
     /*
     Read each event, looking for directory creation 
     */
     i=0;
     while ( i < length ) {     
        struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];     
        if ( event->len ) {
            if ( event->mask & IN_CREATE ) {
              if ( event->mask & IN_ISDIR ) {
                printf( "game_notify new directory %s created, create a game_listener.\n", event->name );
                if(is_proxy){
                   proxyDir(game_list, event->name);
                }   
                result = create_game_listener(game_list, event->name);
              }else {
                printf( "game_notify new file %s created, ignore.\n", event->name );
              }
            }
        }
        i += EVENT_SIZE + event->len;
     }
     fflush(stdout);
  }
   inotify_rm_watch( fd, wd );

  /*closing the INOTIFY instance*/
   close( fd );

}
