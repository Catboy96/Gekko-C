/**********************************************************************************************************************
    file:           gekko.c
    description:    Gekko main executable
    author:         (C) 2021 PlayerCatboy (Ralf Ren).
    date:           Jul.17, 2021
**********************************************************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <stdbool.h>

#include "gekko.h"
#include "jsmn.h"
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <libssh2_publickey.h>

#ifdef DARWIN
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#ifdef WINDOWS
#include <winsock.h>
#endif

#ifdef LINUX
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
/**********************************************************************************************************************
    global variables
**********************************************************************************************************************/
static int          sock            = -1;
char               *grips_path      = NULL;
LIBSSH2_SESSION    *session         = NULL;
LIBSSH2_CHANNEL    *channel         = NULL;
/**********************************************************************************************************************
    useful macros
**********************************************************************************************************************/
#define gko_error_return(prompt)                \
if (ret != GEKKO_OK) {                          \
    fprintf(stderr, prompt " (%d).\n", ret);    \
    return GEKKO_ERROR;                         \
}
/**********************************************************************************************************************
    description:    windows specific strndup implementation
    arguments:      str:    string
                    chars:  max string length to duplicate
    return:         duplicate string
**********************************************************************************************************************/
#ifdef WINDOWS
static char *strndup(const char *str, size_t chars)
{
    char   *buffer;
    int     n;

    buffer = (char *)malloc(chars + 1);
    memset(buffer, 0, chars + 1);
    if (buffer) {
        for (n = 0; ((n < chars) && (str[n] != 0)); n++) {
            buffer[n] = str[n];
        }

        buffer[n] = 0;
    }

    return buffer;
}
#endif
/**********************************************************************************************************************
    description:    Check if file exists
    arguments:      path:   file path
    return:         boolean
**********************************************************************************************************************/
static bool gko_file_exists(const char *path)
{
    if (!path) return false;

    return (access(path, F_OK) == GEKKO_OK) ? true : false;
}
/**********************************************************************************************************************
    description:    Check if directory exists
    arguments:      path:   directory path
    return:         boolean
**********************************************************************************************************************/
static bool gko_dir_exists(const char *path)
{
    DIR *dir;

    if (!path) return false;

    if (access(path, F_OK) != -1) {
        if ((dir = opendir(path)) != NULL) {
            closedir(dir);
        } else {
            return false;
        }
    } else {
        return false;
    }

    return true;
}
/**********************************************************************************************************************
    description:    Create instance
    arguments:      grip:   grip instance
    return:         error code
**********************************************************************************************************************/
static int gko_instance_create(GRIP *grip)
{
    struct sockaddr_in  sin;
    int                 ret             = GEKKO_ERROR;
    int                 auth_method     = 0;
    const char         *fingerprint     = NULL;
    char               *user_auth_list  = NULL;

#ifdef GEKKO_DEBUG
    int                 i;
#endif

    ret = libssh2_init(0);
    gko_error_return("libssh2 initialization failed");

    sock = socket(AF_INET, SOCK_STREAM, 0);
    gko_error_return("Socket creation failed");

    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(grip->port);
    sin.sin_addr.s_addr = inet_addr(grip->host);    // TODO: support IP and hostname
    ret = connect(sock, (struct sockaddr*)&sin, sizeof(struct sockaddr_in));
    gko_error_return("Socket connection failed");

    session = libssh2_session_init();
    ret = libssh2_session_handshake(session, sock);
    gko_error_return("Cannot establish SSH session");

    // check if fingerprint matches the saved ones
    fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);

#ifdef GEKKO_DEBUG
    printf("The fingerprint is: ");
    for (i = 0; i < 20; i++) {
        printf("%02x", (uint8_t)fingerprint[i]);
    }
    printf("\n");
#endif

    // TODO: check if fingerprint matches the saved ones

    // check what authentication methods are available
    user_auth_list = libssh2_userauth_list(session, grip->user, strlen(grip->user));

#ifdef GEKKO_DEBUG
    printf("Authentication methods: %s\n", user_auth_list);
#endif

    if (strstr(user_auth_list, "password")) {
        auth_method |= AUTH_METHOD_PASSWORD;
    }
    if (strstr(user_auth_list, "keyboard-interactive")) {
        auth_method |= AUTH_METHOD_KEYBOARD_INTERACTIVE;
    }
    if (strstr(user_auth_list, "publickey")) {
        auth_method |= AUTH_METHOD_PUBLIC_KEY;
    }

    if (auth_method & AUTH_METHOD_PASSWORD) {
        ret = libssh2_userauth_password(session, grip->user, grip->pass);
        gko_error_return("Authentication failed: password");
        printf("Authentication succeeded: password\n");

    } else if (auth_method & AUTH_METHOD_KEYBOARD_INTERACTIVE) {
        // TODO
    } else if (auth_method & AUTH_METHOD_PUBLIC_KEY) {
        // TODO
    } else {
        fprintf(stderr, "No supported authentication methods found.\n");
        goto __error_no_auth;
    }

    return GEKKO_OK;

__error_no_auth:
    libssh2_session_disconnect(session, "Super Gekko Camouflage");
    libssh2_session_free(session);
    close(sock);

    return GEKKO_ERROR;
}
/**********************************************************************************************************************
    description:    Destroy instance
    arguments:      -
    return:         -
**********************************************************************************************************************/
static void gko_instance_destroy(void)
{
    libssh2_session_disconnect(session, "Super Gekko Camouflage");
    libssh2_session_free(session);
    close(sock);
}
/**********************************************************************************************************************
    description:    Read configuration file
    arguments:      path:   configuration file path
    return:         error code
**********************************************************************************************************************/
static int gko_read_config(const char *path)
{
    char           *json            = NULL;
    char           *value           = NULL;
    char           *temp            = NULL;
    FILE           *file            = NULL;
    size_t          file_length     = 0;
    size_t          file_read       = 0;
    int             count           = 0;
    int             i               = 0;
    jsmn_parser     p;
    jsmntok_t       t[TOKEN_MAX];

    if (!path) return GEKKO_ERROR;

    file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "Cannot open file %s.\n", path);
        return GEKKO_ERROR;
    }

    fseek(file, 0, SEEK_END);
    file_length = ftell(file);
    fseek(file, 0, SEEK_SET);

    json = (char *)malloc(file_length);
    memset(json, 0, file_length);
    if (!json) {
        fprintf(stderr, "Insufficient memory.\n");
        return GEKKO_ERROR;
    }

    file_read = fread(json, 1, file_length, file);
    fclose(file);

    if (file_read != file_length) {
        fprintf(stderr, "Failed to parse JSON %s (%d).\n", path, count);
        free(json);
        return GEKKO_ERROR;
    }

    jsmn_init(&p);
    count = jsmn_parse(&p, json, strlen(json), t, sizeof(t) / sizeof(t[0]));
    if (count < 0) {
        fprintf(stderr, "Failed to parse JSON %s (%d).\n", path, count);
        return GEKKO_ERROR;
    }

    if (count < 1 || t[0].type != JSMN_OBJECT) {
        fprintf(stderr, "Invalid json file %s (%d).\n", path, count);
        free(json);
        return GEKKO_ERROR;
    }

    for (i = 1; i < count; i++) {
        if (jsoneq(json, &t[i], "debug") == GEKKO_OK) {
            value = strndup(json + t[i + 1].start, t[i + 1].end - t[i + 1].start);
            printf("debug = %s\n", value);
            i++;

        } else if (jsoneq(json, &t[i], "grip_directory") == GEKKO_OK) {
            value = strndup(json + t[i + 1].start, t[i + 1].end - t[i + 1].start);
            printf("grip_directory = %s\n", value);

            temp = value;
            while (*temp++ != '\0') {
#ifdef WINDOWS
                if (*temp == '/') *temp = '\\';
#else
                if (*temp == '\\') *temp = '/';
#endif
            }

            grips_path = (char *)malloc(PATH_MAX);
            if (!grips_path) {
                fprintf(stderr, "Insufficient memory.\n");
                return GEKKO_ERROR;
            }

            if (value[0] == '~') {
#ifdef WINDOWS
                snprintf(grips_path, PATH_MAX, "%s%s%s", getenv("HOMEDRIVE"),
                         getenv("HOMEPATH"), &value[1]);
#else
                snprintf(grips_path, PATH_MAX, "%s%s", getenv("HOME"), &value[1]);
#endif
            }

            i++;
        }
    }

    free(value);
    free(json);

    if (!grips_path) {
        fprintf(stderr, "Grips directory is not specified.\n");
        return GEKKO_ERROR;
    }

    if (!gko_dir_exists(grips_path)) {
        free(grips_path);
        fprintf(stderr, "Grips directory does not exist.\n");
        return GEKKO_ERROR;
    }

    return GEKKO_OK;
}
/**********************************************************************************************************************
    description:    Read configuration file
    arguments:      name:   grip name
                    grip:   grip instance to store
    return:         error code
**********************************************************************************************************************/
static int gko_read_grip(const char *name, GRIP *grip)
{
    if (!name) return GEKKO_ERROR;

    return GEKKO_OK;
}
/**********************************************************************************************************************
    description:    Print general help
    arguments:      -
    return:         -
**********************************************************************************************************************/
static void gko_help_main(void)
{
    printf("Usage: gekko command [options]\n\n");

    printf("Commands:\n");
    printf("\tcamo\t\tspecify file or directory to ignore\n");
    printf("\tgrip\t\tadd a grip to remote host\n");
    printf("\trun\t\tstart synchronization\n\n");

    printf("Common usage:\n");
    printf("- Add path to ignore:\n");
    printf("\tgekko camo no_upload.txt\n");
    printf("- Remove path to ignore:\n");
    printf("\tgekko camo -r no_upload.txt\n\n");

    printf("- List all grips:\n");
    printf("\tgekko grip\n");
    printf("- Add / Modify a grip:\n");
    printf("\tgekko grip myserver sftp://catboy@myserver.com:22\n");
    printf("- Remove a grip:\n");
    printf("\tgekko grip -r myserver\n\n");

    printf("- Start synchronization:\n");
    printf("\tgekko run myserver /home/catboy/upload/ [-p password] [-k keyfile]\n");
    printf("- Check changes to apply:\n");
    printf("\tgekko run -s myserver [-p password] [-k keyfile]\n\n");
}
/**********************************************************************************************************************
    description:    Entry function of Gekko
    arguments:      argc:   Count of command line arguments
                    argv:   Values of command line arguments
    return:         error code
**********************************************************************************************************************/
int main(int argc, char *argv[])
{
    int     ret                 = GEKKO_ERROR;
    int     error               = GEKKO_OK;
    char    config[PATH_MAX]    = {0};
    GRIP   *grip                = NULL;

#ifdef WINDOWS
    snprintf(config, PATH_MAX, "%s%s%s", getenv("HOMEDRIVE"),
             getenv("HOMEPATH"), GEKKO_DEFAULT_CONFIG);
#else
    snprintf(config, PATH_MAX, "%s%s", getenv("HOME"), GEKKO_DEFAULT_CONFIG);
#endif

    printf("Use default configuration file: %s\n", config);

    if (!gko_file_exists(config)) {
        fprintf(stderr, "Cannot access file (%d).\n", ret);
        return GEKKO_ERROR;
    }

    ret = gko_read_config(config);
    if (ret != GEKKO_OK) {
        fprintf(stderr, "Cannot read configuration file (%d).\n", ret);
        return GEKKO_ERROR;
    }

    grip = (GRIP *)malloc(sizeof(GRIP));
    memset(grip, 0, sizeof(GRIP));
    if (!grip) {
        fprintf(stderr, "Insufficient memory.\n");
        error = GEKKO_ERROR;
        goto __error_malloc;
    }

    ret = gko_read_grip("aliyun", grip);
    if (ret != GEKKO_OK) {
        fprintf(stderr, "Cannot read grip (%d).\n", ret);
        error = GEKKO_ERROR;
        goto __error_read_grip;
    }

    return GEKKO_OK;

    ret = gko_instance_create(grip);
    gko_error_return("Cannot create SSH instance");

    gko_instance_destroy();
    printf("Connection closed.");

__error_read_grip:
    free(grip);

__error_malloc:
    free(grips_path);

    if (error) {
        return GEKKO_ERROR;
    } else {
        return GEKKO_OK;
    }
}
/**********************************************************************************************************************
    end
**********************************************************************************************************************/
