/**********************************************************************************************************************
    file:           gekko.h
    description:    Common definition of Gekko
    author:         (C) 2021 PlayerCatboy (Ralf Ren).
    date:           Jul.17, 2021
**********************************************************************************************************************/
#ifndef __GEKKO_H
#define __GEKKO_H
/**********************************************************************************************************************
    common definitions
**********************************************************************************************************************/
#ifndef PATH_MAX
#define PATH_MAX        (512)
#endif
#ifndef TOKEN_MAX
#define TOKEN_MAX       (32)
#endif
/**********************************************************************************************************************
    gekko defaults
**********************************************************************************************************************/
#define GEKKO_DEFAULT_CONFIG            "/.gekko/gekko.json"
/**********************************************************************************************************************
    gekko return type
**********************************************************************************************************************/
typedef enum {
    GEKKO_OK        = 0,
    GEKKO_ERROR     = 1,
} GEKKO_RETURN;
/**********************************************************************************************************************
    ssh authentication methods
**********************************************************************************************************************/
typedef enum {
    AUTH_METHOD_PASSWORD               = (1 << 0),
    AUTH_METHOD_KEYBOARD_INTERACTIVE   = (1 << 1),
    AUTH_METHOD_PUBLIC_KEY             = (1 << 2),
} AUTH_METHOD;
/**********************************************************************************************************************
    gekko grip type
**********************************************************************************************************************/
typedef struct {
    char           *host;
    uint16_t        port;
    AUTH_METHOD     auth;
    char           *user;
    char           *pass;
    char           *key;
} GRIP;

#endif  // __GEKKO_H
/**********************************************************************************************************************
    end
**********************************************************************************************************************/