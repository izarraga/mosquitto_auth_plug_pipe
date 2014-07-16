/*
    mosquitto auth pipe plugin

    with this plugin you can authenticate throw an unix pipe

    idea and code taken from jabberd2 proyect.
 
    gcc -I../src -fPIC -shared auth_plug_pipe.c -o auth_plug_pipe.so
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>

#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <errno.h>


#define PIPE_EXEC "/root/mqtt/mosquitto_auth_pipe/mqttpipe.pl"
/*
#define DEBUG 1
*/

/** internal structure, holds our data */
typedef struct moddata_st {
    char    *exec;
    pid_t   child;
    int     in, out;
} *moddata_t;

moddata_t data;



static void pipe_signal(int signum)
{
    wait(NULL);
    /* !!! attempt to restart the pipe, or shutdown c2s */
}


static int pipe_write(int fd, const char *msgfmt, ...)
{
    va_list args;
    char buf[1024];
    int ret;

    va_start(args, msgfmt);
    vsnprintf(buf, 1024, msgfmt, args);
    va_end(args);

#ifdef DEBUG    
    fprintf(stderr, "[auth_plug_pipe] writing to pipe: %s\n", buf);
#endif

    ret = write(fd, buf, strlen(buf));
    if(ret < 0)
    {
        fprintf(stderr, "[auth_plug_pipe] pipe: write to pipe failed: %s\n", strerror(errno));
    }

    return ret;
}


static int pipe_read(int fd, char *buf, int buflen)
{
    int ret;
    char *c;

    ret = read(fd, buf, buflen);
    if(ret == 0)
        fprintf(stderr, "[auth_plug_pipe] pipe: got EOF from pipe\n");
    if(ret < 0)
        fprintf(stderr, "[auth_plug_pipe] pipe: read from pipe failed: %s\n", strerror(errno));
    if(ret <= 0)
        return ret;

    buf[ret] = '\0';
    c = strchr(buf, '\n');
    if(c != NULL)
        *c = '\0';

#ifdef DEBUG
    fprintf(stderr, "[auth_plug_pipe] read from pipe: %s\n", buf);
#endif

    return ret;
}


static int pipe_check_password(moddata_t data, const char *username,  const char *password)
{
    char buf[1024];

    if(pipe_write(data->out, "CHECK-PASSWORD %s %s\n", username, password) < 0)
        return 1;

    if(pipe_read(data->in, buf, 1023) <= 0)
        return 1;

    if(buf[0] != 'O' || buf[1] != 'K')
        return 1;

    return 0;
}


int mosquitto_auth_plugin_version(void)
{

    fprintf(stderr, "[auth_plug_pipe] _____START_____\n");
    fprintf(stderr, "[auth_plug_pipe] mosquitto_auth_plugin_version()\n");

	return MOSQ_AUTH_PLUGIN_VERSION;
}


int mosquitto_auth_plugin_init(void **userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
    fprintf(stderr, "[auth_plug_pipe] mosquitto_auth_plugin_init()\n");

    int to[2], from[2], ret;
    char buf[1024], *tok, *c;

    data = (moddata_t) calloc(1, sizeof(struct moddata_st));

    data->exec = PIPE_EXEC;
    fprintf(stderr, "[auth_plug_pipe] PIPE_WITH: %s\n",data->exec);

    if(pipe(to) < 0)
    {
        fprintf(stderr, "[auth_plug_pipe] pipe: failed to create pipe\n");
        free(data);
        return 1;
    }

    if(pipe(from) <0)
    {
        fprintf(stderr, "[auth_plug_pipe] pipe:failed to create pipe\n");
        close(to[0]);
        close(to[1]);
        free(data);
        return 1;
    }

    signal(SIGCHLD, pipe_signal);

    fprintf(stderr, "[auth_plug_pipe] attempting to fork\n");

    data->child = fork();

    if(data->child < 0)
    {
        fprintf(stderr, "[auth_plug_pipe] no fork\n");
        close(to[0]);
        close(to[1]);
        close(from[0]);
        close(from[1]);
        return 1;
    }

    /* child */
    if(data->child == 0)
    {
        fprintf(stderr, "[auth_plug_pipe] executing.....\n");

        close(STDIN_FILENO);
        close(STDOUT_FILENO);

        dup2(to[0], STDIN_FILENO);
        dup2(from[1], STDOUT_FILENO);

        close(to[0]);
        close(to[1]);
        close(from[0]);
        close(from[1]);

        execl(data->exec, data->exec, NULL);

        fprintf(stderr, "[auth_plug_pipe] child: failed to execute %s", data->exec);

        exit(1);
    }

    /* parent */
    close(to[0]);
    close(from[1]);

    data->in = from[0];
    data->out = to[1];

    ret = pipe_read(data->in, buf, 1023);

    if(ret <= 0)
    {
        close(data->in);
        close(data->out);
        free(data);
        return 1;
    }

    c = buf;
    while(c != NULL)
    {
        tok = c;

        c = strchr(c, ' ');
        if(c != NULL)
        {
            *c = '\0';
            c++;
        }

        /* first token must be OK */
        if(tok == buf)
        {
            if(strcmp(tok, "OK") == 0)
            {
                continue;
            }

            kill(data->child, SIGTERM);
            close(data->in);
            close(data->out);
            free(data);
            return 1;
        }

        fprintf(stderr, "[auth_plug_pipe] tok: %s\n", tok);

    }

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_auth_plugin_cleanup(void *userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
    fprintf(stderr, "[auth_plug_pipe] mosquitto_auth_plugin_cleanup()\n");

    free(data);

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_auth_security_init(void *userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
    fprintf(stderr, "[auth_plug_pipe] mosquitto_auth_security_init()\n");
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_auth_security_cleanup(void *userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
    fprintf(stderr, "[auth_plug_pipe] mosquitto_auth_security_cleanup()\n");
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_auth_unpwd_check(void *userdata, const char *username, const char *password)
{
#ifdef DEBUG
    fprintf(stderr, "[auth_plug_pipe] mosquitto_auth_unpwd_check()\n");
#endif
	if (!username || !*username || !password || !*password)
		return MOSQ_ERR_AUTH;

    int retu;

    retu = pipe_check_password(data, username, password);

    if(retu == 0)
        return MOSQ_ERR_SUCCESS;

	return  MOSQ_ERR_AUTH;
}


int mosquitto_auth_acl_check(void *userdata, const char *clientid, const char *username, const char *topic, int access)
{
#ifdef DEBUG
    fprintf(stderr, "[auth_plug_pipe] mosquitto_auth_acl_check()\n");
#endif
    int authorized = 1;
	return (authorized) ?  MOSQ_ERR_SUCCESS : MOSQ_ERR_ACL_DENIED;
}


int mosquitto_auth_psk_key_get(void *userdata, const char *hint, const char *identity, char *key, int max_key_len)
{
    fprintf(stderr, "[auth_plug_pipe] mosquitto_auth_psk_key_get()\n");
	return MOSQ_ERR_AUTH;
}

