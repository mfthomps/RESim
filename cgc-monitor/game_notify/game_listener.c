/* Watch for new  configuration file entries in the game directory */
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <linux/inotify.h>

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

int is_proxy = 0;
char *proxy_dest=NULL;
int die_now = 0; /* caught signal, die after processing current data */
int die_lock = 1; /* if set, signal hander does not exit, it sets die_now */
void usage(){
    printf("game_listener game_dir\n");
    exit(0);
}
void signal_handler(){
   printf("game_listener in signal_handler, set die_now so it exits die_lock is %d.\n",die_lock );
   if(die_lock){
       die_now = 1;
   }else{
       printf("game_listener got signal with die_lock unset, exit\n");
       exit(0);
   }
}
    
int proxyFile(char *game_dir, char *config_file){
   char cmd[2048];
   int result;
   sprintf(cmd, "scp -p %s/%s cgcwf@%s:%s/%s.tmp", game_dir, config_file, proxy_dest, game_dir, config_file);
   result = system(cmd);
   if(result != 0){
      fprintf(stderr, "failed proxy command %s\n", cmd);
   }
   sprintf(cmd, "ssh cgcwf@%s mv %s/%s.tmp %s/%s", proxy_dest, game_dir, config_file, game_dir, config_file);
   result = system(cmd);
   if(result != 0){
      fprintf(stderr, "failed proxy command %s\n", cmd);
   }
   return result;
}
int processConfigList(char **cargv, int wait_for_sets){
   /*
   Process list of config files and wait for the processing to complete.
   */
   int status;
   int i;
   printf("game_listener processConfigList\n");
   int child_pid = fork();
   if(child_pid == 0){
      /* in child */
      pid_t my_pid = getpid();
      printf("game_listener about to exec, pid is %d\n", my_pid);
      execv("/usr/bin/cfeFlow",cargv);
      fprintf(stderr, "exec failed %s\n", strerror(errno));
      exit(1); /* only if execv fails */
   }else{
      printf("game_listener created cfeFlow, pid %d\n", child_pid);
      fflush(stdout);
      waitpid(child_pid, &status, 0);
      printf("game_listener cfeFlow has finished.\n");
   }
}
char *mybase(char *str){
   char *last_slash = strrchr(str,'/');
   if(last_slash != NULL){
       return last_slash+1;
   }else{
       return NULL;
   }
}
/*
Create/clear the database for a new game
*/
int prepDataStores(char *gname){
   int status;
   int result = 0;
   char *continue_cfe = "/usr/bin/continueCFE";
   char *cargv [5];
   printf("in prepDataStores\n");
   cargv[0] = "bash";
   cargv[1] = "continueCFE";
   cargv[2] = gname;
   /* don't process content, will be done by game_listener */
   cargv[3] = "wait";
   cargv[4] = NULL;
   int pid = fork();
   if(pid == 0){
      /* in child */
      pid_t child_pid = getpid();
      printf("about to exec, pid is %d\n", child_pid);
      //VERIFY(execv, "/usr/bin/cb-server", cargv);
      execv("/bin/bash",cargv);
      fprintf(stderr, "exec failed %s\n", strerror(errno));
      exit(1); /* only if execv fails */
   }else{
      printf("created continueCFE, pid %d\n", pid);
      waitpid(pid, &status, 0);
      printf("back from continueCFE, pid %d\n", pid);
   }
   return result;
}
void checkDir(char *game_dir, int fname_index, char **cargv, int skip_json){
   /*
   look for files that existed before we got here
   hack to skip json files for proxying until second pass to ensure other files are moved first.
   */
   char *cfg_list_file = "cfg_list_file";
   FILE *fd = fopen(cfg_list_file, "w");
   int result = 0;
   DIR *d;
   struct dirent *dir;
   cargv[fname_index] = cfg_list_file;
   cargv[fname_index+1] = NULL;
   int cfg_count = 0;
   d = opendir(game_dir);
   if(d){
      while((dir = readdir(d)) != NULL){
         if(strchr(dir->d_name,'.')==dir->d_name){
            continue;
         }
         if(is_proxy){
            if(!strstr(dir->d_name, "luigi-tmp")){
               if((skip_json && !strstr(dir->d_name, ".json")) || (!skip_json && strstr(dir->d_name, ".json"))){
                  result = proxyFile(game_dir, dir->d_name);
                  if(result != 0){
                     break;
                  }
               }
            }
         }else{
            if(strstr(dir->d_name, ".json")){
               fprintf(fd, "%s\n", dir->d_name);
               cfg_count ++;
            }
         }
      }
      fflush(fd);
      fclose(fd);
      if(!is_proxy && (cfg_count > 0)){
         /* tell cfeFlow to wait until the sets are done before letting us move to next game. */
         cargv[2] = "-wait_list";
         processConfigList(cargv, 1);
         cargv[2] = "-list";
      }
      closedir(d);
   } 
}
int main(int argc, char **argv)
{
  int length, i = 0;
  int fd;
  int wd;
  char buffer[EVENT_BUF_LEN];
  char *cargv [8];
  static struct timeval the_time;
  char *cfg_list_file = "cfg_list_file";
  FILE *cfg_fd = NULL;

  signal(SIGUSR1, signal_handler);
  if(argc < 2){
     usage();
  }  
  char *game_dir = argv[1];
  char *game_name = mybase(game_dir);

  /* set up initial arguments for exec of cfeFlow */
  cargv[0] = "cfeFlow";
  cargv[1] = game_name;
  cargv[2] = "-list";
  cargv[3] = cfg_list_file;
  cargv[4] = NULL;;
  gettimeofday(&the_time, NULL);
  printf("[%u.%06u] Start game_listener game_dir %s\n", (unsigned)the_time.tv_sec, (unsigned)the_time.tv_usec, game_dir);
  fflush(stdout);

  if(argc >= 3){
     if(argc == 4){
        if(!strncmp(argv[2], "proxy", 5)){
           is_proxy = 1;
           proxy_dest = argv[3];
           printf("running as proxy to %s\n", proxy_dest);
        }else{
           usage();
        }
     }else{
        usage();
     }
  }
  if(!is_proxy){
     prepDataStores(game_name);
  }
  /*creating the INOTIFY instance*/
  fd = inotify_init();

  /*checking for error*/
  if ( fd < 0 ) {
    perror( "inotify_init" );
  }

  /*
  adding the game directory into watch list, looking for moves
  */
  wd = inotify_add_watch( fd, game_dir, IN_MOVED_TO );
  int fname_index = 3;
  checkDir(game_dir, fname_index, cargv, 1);
  if(is_proxy){
     /* second time through gets the json files, first did the bins */
     checkDir(game_dir, fname_index, cargv, 0);
  }
  gettimeofday(&the_time, NULL);
  printf("[%u.%06u] Game_listener done checking dir\n", (unsigned)the_time.tv_sec, (unsigned)the_time.tv_usec);
  fflush(stdout);
  int result = 0;
  /* until an error or killed */
  i = 0;
  while(result == 0){
     gettimeofday(&the_time, NULL);
     /* blocking read */
     if(die_now){
         printf("[%u.%06u] game_listener found die_now, exit\n", (unsigned)the_time.tv_sec, (unsigned)the_time.tv_usec);
         exit(0);
     }else{
         die_lock = 0;
     }
     printf("[%u.%06u] game_listener do block read \n", (unsigned)the_time.tv_sec, (unsigned)the_time.tv_usec);
     length = read( fd, buffer, EVENT_BUF_LEN ); 
     /* must have read an event, handle it before dieing.  race conditions? */ 
     die_lock = 1;
     /*checking for error*/
     if ( length < 0 ) {
       perror( "read" );
     }  
   
     printf("read %d items\n",  length); 
     /* Go through the events, looking for a move */
     i=0;
     int cfg_count = 0;
     cfg_fd = fopen(cfg_list_file, "w");
     while ( i < length ) {     
        struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];     
        if ( event->len ) {
            if ( event->mask & IN_MOVED_TO ) {
              if ( event->mask & IN_ISDIR ) {
                printf( "New directory %s moved, ignore.\n", event->name );
              }else {
                 gettimeofday(&the_time, NULL);
                 printf( "[%u.%06u] game_listener New file %s move i is %d.\n", (unsigned)the_time.tv_sec, (unsigned)the_time.tv_usec, event->name, i );
                 if(is_proxy){
                    result = proxyFile(game_dir, event->name);
                    if(result != 0){
                       break;
                    }
                 }else if(strstr(event->name, ".json")){
                    fprintf(cfg_fd, "%s\n", event->name);
                    cfg_count++;
                 }
              }
            }
        }
        i += EVENT_SIZE + event->len;
     }
     fflush(cfg_fd);
     fclose(cfg_fd);
     fflush(stdout);
     if(!is_proxy && (cfg_count > 0)){
        processConfigList(cargv, 0);
     }
  }
  inotify_rm_watch( fd, wd );

  /*closing the INOTIFY instance*/
   close( fd );

}
