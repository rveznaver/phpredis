/* -*- Mode: C; tab-width: 4 -*- */
/*
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2009 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Original author: Alfonso Jimenez <yo@alfonsojimenez.com>             |
  | Maintainer: Nicolas Favre-Felix <n.favre-felix@owlient.eu>           |
  | Maintainer: Nasreddine Bouafif <n.bouafif@owlient.eu>                |
  | Maintainer: Michael Grunder <michael.grunder@gmail.com>              |
  +----------------------------------------------------------------------+
*/

#include "common.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef PHP_SESSION
#include "ext/standard/info.h"
#include "php_redis.h"
#include "redis_session.h"
#include <zend_exceptions.h>

#include "library.h"
#include "cluster_library.h"

#include "php.h"
#include "php_ini.h"
#include "php_variables.h"
#include "SAPI.h"
#include "ext/standard/url.h"

#define REDIS_SESSION_PREFIX "PHPREDIS_SESSION:"
#define CLUSTER_SESSION_PREFIX "PHPREDIS_CLUSTER_SESSION:"

/* Session lock LUA as well as its SHA1 hash */
#define LOCK_RELEASE_LUA_STR "if redis.call(\"get\",KEYS[1]) == ARGV[1] then return redis.call(\"del\",KEYS[1]) else return 0 end"
#define LOCK_RELEASE_LUA_LEN (sizeof(LOCK_RELEASE_LUA_STR) - 1)
#define LOCK_RELEASE_SHA_STR "b70c2384248f88e6b75b9f89241a180f856ad852"
#define LOCK_RELEASE_SHA_LEN (sizeof(LOCK_RELEASE_SHA_STR) - 1)

/* Atomic acquire-and-read Lua script for the cluster session handler.
 *   KEYS[1] - session data key
 *   KEYS[2] - lock key, hash tagged to the same slot
 *   ARGV[1] - lock secret
 *   ARGV[2] - lock TTL in milliseconds
 *   ARGV[3] - session TTL in seconds (a positive value issues GETEX EX <ttl> for early_refresh)
 *
 * Returns {locked ? 1 : 0, data}; reads data unconditionally to honour lock_failure_readonly. */
#define LOCK_RW_LUA_STR "local d;if tonumber(ARGV[3])>0 then d=redis.call('GETEX',KEYS[1],'EX',ARGV[3]) else d=redis.call('GET',KEYS[1]) end;local l;if tonumber(ARGV[2])>0 then l=redis.call('SET',KEYS[2],ARGV[1],'NX','PX',ARGV[2]) else l=redis.call('SET',KEYS[2],ARGV[1],'NX') end;return {l and 1 or 0,d or ''}"
#define LOCK_RW_SHA_STR "87c7c94521579faf92d4f7cae910d3546923c8d8"

typedef struct evalCmd {
    char *kw;
    char *str;
    size_t len;
} evalCmd;

/* Cluster lock-release EVALSHA->EVAL fallback (same script/SHA as LOCK_RELEASE_*) */
static evalCmd lua_cmd[2] = {
    {"EVALSHA", ZEND_STRL(LOCK_RELEASE_SHA_STR)},
    {"EVAL", ZEND_STRL(LOCK_RELEASE_LUA_STR)}
};

/* Cluster atomic acquire-and-read EVALSHA->EVAL fallback */
static evalCmd lua_rw_cmd[2] = {
    {"EVALSHA", ZEND_STRL(LOCK_RW_SHA_STR)},
    {"EVAL", ZEND_STRL(LOCK_RW_LUA_STR)}
};

typedef enum lockDelCmd {
    LOCK_DEL_EVAL,
    LOCK_DEL_DELEX,
    LOCK_DEL_DELIFEQ,
} lockDelCmd;

typedef enum releaseResult {
    DEL_SUCCESS,
    DEL_FAILURE,
    DEL_NO_CMD,
} delResult;

/* Check if a response is the Redis +OK status response */
#define IS_REDIS_OK(r, len) (r != NULL && len == 3 && !memcmp(r, "+OK", 3))
#define NEGATIVE_LOCK_RESPONSE 1

#define CLUSTER_DEFAULT_PREFIX() \
    zend_string_init(CLUSTER_SESSION_PREFIX, sizeof(CLUSTER_SESSION_PREFIX) - 1, 0)

ps_module ps_mod_redis = {
    PS_MOD_UPDATE_TIMESTAMP(redis)
};

ps_module ps_mod_redis_cluster = {
    PS_MOD_UPDATE_TIMESTAMP(rediscluster)
};

typedef struct {
    zend_bool is_locked;
    zend_string *session_key;
    zend_string *lock_key;
    zend_string *lock_secret;
} redis_session_lock_status;

typedef struct redis_pool_member_ {

    RedisSock *redis_sock;
    int weight;
    struct redis_pool_member_ *next;

} redis_pool_member;

typedef struct {

    int totalWeight;
    int count;

    redis_pool_member *head;
    redis_session_lock_status lock_status;

} redis_pool;

// static char *session_conf_string(HashTable *ht, const char *key, size_t keylen) {
// }

PHP_REDIS_API void
redis_pool_add(redis_pool *pool, RedisSock *redis_sock, int weight)
{
    redis_pool_member *rpm = ecalloc(1, sizeof(redis_pool_member));
    rpm->redis_sock = redis_sock;
    rpm->weight = weight;

    rpm->next = pool->head;
    pool->head = rpm;

    pool->totalWeight += weight;
}

PHP_REDIS_API void
redis_pool_free(redis_pool *pool) {

    redis_pool_member *rpm, *next;

    if (pool == NULL)
        return;

    rpm = pool->head;
    while (rpm) {
        next = rpm->next;
        redis_sock_disconnect(rpm->redis_sock, 0, 1);
        redis_free_socket(rpm->redis_sock);
        efree(rpm);
        rpm = next;
    }

    /* Cleanup after our lock */
    if (pool->lock_status.session_key) zend_string_release(pool->lock_status.session_key);
    if (pool->lock_status.lock_secret) zend_string_release(pool->lock_status.lock_secret);
    if (pool->lock_status.lock_key) zend_string_release(pool->lock_status.lock_key);

    /* Cleanup pool itself */
    efree(pool);
}

/* Retrieve session.gc_maxlifetime from php.ini protecting against an integer overflow */
static int session_gc_maxlifetime(void) {
    zend_long value = INI_INT("session.gc_maxlifetime");
    if (value > INT_MAX) {
        php_error_docref(NULL, E_NOTICE, "session.gc_maxlifetime overflows INT_MAX, truncating.");
        return INT_MAX;
    } else if (value <= 0) {
        php_error_docref(NULL, E_NOTICE, "session.gc_maxlifetime is <= 0, defaulting to 1440 seconds");
        return 1440;
    }

    return value;
}

/* Retrieve redis.session.compression from php.ini */
static int session_compression_type(void) {
    const char *compression = INI_STR("redis.session.compression");
    if(compression == NULL || *compression == '\0' || strncasecmp(compression, "none", sizeof("none") - 1) == 0) {
        return REDIS_COMPRESSION_NONE;
    }

#ifdef HAVE_REDIS_LZF
    if(strncasecmp(compression, "lzf", sizeof("lzf") - 1) == 0) {
        return REDIS_COMPRESSION_LZF;
    }
#endif
#ifdef HAVE_REDIS_ZSTD
    if(strncasecmp(compression, "zstd", sizeof("zstd") - 1) == 0) {
        return REDIS_COMPRESSION_ZSTD;
    }
#endif
#ifdef HAVE_REDIS_LZ4
    if(strncasecmp(compression, "lz4", sizeof("lz4") - 1) == 0) {
        return REDIS_COMPRESSION_LZ4;
    }
#endif

    // E_NOTICE when outside of valid values
    php_error_docref(NULL, E_NOTICE, "redis.session.compression is outside of valid values, disabling");

    return REDIS_COMPRESSION_NONE;
}

/* Helper to compress session data */
static int
session_compress_data(RedisSock *redis_sock, char *data, size_t len,
                      char **compressed_data, size_t *compressed_len)
{
    if (redis_sock->compression) {
        if(redis_compress(redis_sock, compressed_data, compressed_len, data, len)) {
            return 1;
        }
    }

    *compressed_data = data;
    *compressed_len = len;

    return 0;
}

/* Helper to uncompress session data */
static int
session_uncompress_data(RedisSock *redis_sock, char *data, size_t len,
                                   char **decompressed_data, size_t *decompressed_len) {
    if (redis_sock->compression) {
        if(redis_uncompress(redis_sock, decompressed_data, decompressed_len, data, len)) {
            return 1;
        }
    }

    *decompressed_data = data;
    *decompressed_len = len;

    return 0;
}

/* Send a command to Redis.  Returns byte count written to socket (-1 on failure) */
static int redis_simple_cmd(RedisSock *redis_sock, char *cmd, int cmdlen,
                              char **reply, int *replylen)
{
    *reply = NULL;
    int len_written = redis_sock_write(redis_sock, cmd, cmdlen);

    if (len_written >= 0) {
        *reply = redis_sock_read(redis_sock, replylen);
    }

    return len_written;
}

PHP_REDIS_API redis_pool_member *
redis_pool_get_sock(redis_pool *pool, const char *key) {

    unsigned int pos, i;
    memcpy(&pos, key, sizeof(pos));
    pos %= pool->totalWeight;

    redis_pool_member *rpm = pool->head;

    for(i = 0; i < pool->totalWeight;) {
        if (pos >= i && pos < i + rpm->weight) {
            if (redis_sock_server_open(rpm->redis_sock) == 0) {
                return rpm;
            }
        }
        i += rpm->weight;
        rpm = rpm->next;
    }

    return NULL;
}

/* Helper to set our session lock key */
static int set_session_lock_key(RedisSock *redis_sock, char *cmd, int cmd_len
                               )
{
    char *reply;
    int sent_len, reply_len;

    sent_len = redis_simple_cmd(redis_sock, cmd, cmd_len, &reply, &reply_len);
    if (reply) {
        if (IS_REDIS_OK(reply, reply_len)) {
            efree(reply);
            return SUCCESS;
        }

        efree(reply);
    }

    /* Return FAILURE in case of network problems */
    return sent_len >= 0 ? NEGATIVE_LOCK_RESPONSE : FAILURE;
}

static int lock_acquire(RedisSock *redis_sock, redis_session_lock_status *lock_status
                       )
{
    char *cmd, hostname[HOST_NAME_MAX] = {0}, suffix[] = "_LOCK";
    int cmd_len, lock_wait_time, retries, i, set_lock_key_result, expiry;

    /* Short circuit if we are already locked or not using session locks */
    if (lock_status->is_locked || !INI_INT("redis.session.locking_enabled"))
        return SUCCESS;

    /* How long to wait between attempts to acquire lock */
    lock_wait_time = INI_INT("redis.session.lock_wait_time");
    if (lock_wait_time == 0) {
        lock_wait_time = 20000;
    }

    /* Maximum number of times to retry (-1 means infinite) */
    retries = INI_INT("redis.session.lock_retries");
    if (retries == 0) {
        retries = 100;
    }

    /* How long should the lock live (in seconds) */
    expiry = INI_INT("redis.session.lock_expire");
    if (expiry == 0) {
        expiry = INI_INT("max_execution_time");
    }

    /* Generate our qualified lock key */
    if (lock_status->lock_key) zend_string_release(lock_status->lock_key);
    lock_status->lock_key = zend_string_alloc(ZSTR_LEN(lock_status->session_key) + sizeof(suffix) - 1, 0);
    memcpy(ZSTR_VAL(lock_status->lock_key), ZSTR_VAL(lock_status->session_key), ZSTR_LEN(lock_status->session_key));
    memcpy(ZSTR_VAL(lock_status->lock_key) + ZSTR_LEN(lock_status->session_key), suffix, sizeof(suffix) - 1);

    /* Calculate lock secret */
    gethostname(hostname, HOST_NAME_MAX);
    if (lock_status->lock_secret) zend_string_release(lock_status->lock_secret);
    lock_status->lock_secret = strpprintf(0, "%s|%ld", hostname, (long)getpid());

    if (expiry > 0) {
        cmd_len = REDIS_SPPRINTF(&cmd, "SET", "SSssd", lock_status->lock_key,
                                 lock_status->lock_secret, "NX", 2, "PX", 2,
                                 expiry * 1000);
    } else {
        cmd_len = REDIS_SPPRINTF(&cmd, "SET", "SSs", lock_status->lock_key,
                                 lock_status->lock_secret, "NX", 2);
    }

    /* Attempt to get our lock */
    for (i = 0; retries == -1 || i <= retries; i++) {
        set_lock_key_result = set_session_lock_key(redis_sock, cmd, cmd_len);

        if (set_lock_key_result == SUCCESS) {
            lock_status->is_locked = 1;
            break;
        } else if (set_lock_key_result == FAILURE) {
            /* In case of network problems, break the loop and report to userland */
            lock_status->is_locked = 0;
            break;
        }

        /* Sleep unless we're done making attempts */
        if (retries == -1 || i < retries) {
            usleep(lock_wait_time);
        }
    }

    /* Cleanup SET command */
    efree(cmd);

    /* Success if we're locked */
    return lock_status->is_locked ? SUCCESS : FAILURE;
}

#define IS_LOCK_SECRET(reply, len, secret) (len == ZSTR_LEN(secret) && !redis_strncmp(reply, ZSTR_VAL(secret), len))
static int write_allowed(RedisSock *redis_sock, redis_session_lock_status *lock_status)
{
    if (!INI_INT("redis.session.locking_enabled")) {
        return 1;
    }
    /* If locked and redis.session.lock_expire is not set => TTL=max_execution_time
       Therefore it is guaranteed that the current process is still holding the lock */

    if (lock_status->is_locked && INI_INT("redis.session.lock_expire") != 0) {
        char *cmd, *reply = NULL;
        int replylen, cmdlen;
        /* Command to get our lock key value and compare secrets */
        cmdlen = REDIS_SPPRINTF(&cmd, "GET", "S", lock_status->lock_key);

        /* Attempt to refresh the lock */
        redis_simple_cmd(redis_sock, cmd, cmdlen, &reply, &replylen);
        /* Cleanup */
        efree(cmd);

        if (reply == NULL) {
            lock_status->is_locked = 0;
        } else {
            lock_status->is_locked = IS_LOCK_SECRET(reply, replylen, lock_status->lock_secret);
            efree(reply);
        }

        /* Issue a warning if we're not locked.  We don't attempt to refresh the lock
         * if we aren't flagged as locked, so if we're not flagged here something
         * failed */
        if (!lock_status->is_locked) {
            php_error_docref(NULL, E_WARNING, "Session lock expired");
        }
    }

    return lock_status->is_locked;
}

/* Release any session lock we hold and cleanup allocated lock data.  This function
 * first attempts to use EVALSHA and then falls back to EVAL if EVALSHA fails.  This
 * will cause Redis to cache the script, so subsequent calls should then succeed
 * using EVALSHA. */
static void lock_release(RedisSock *redis_sock, redis_session_lock_status *lock_status)
{
    char *cmd, *reply;
    int i, cmdlen, replylen;

    /* Keywords, command, and length fallbacks */
    const char *kwd[] = {"EVALSHA", "EVAL"};
    const char *lua[] = {LOCK_RELEASE_SHA_STR, LOCK_RELEASE_LUA_STR};
    int len[] = {LOCK_RELEASE_SHA_LEN, LOCK_RELEASE_LUA_LEN};

    /* We first want to try EVALSHA and then fall back to EVAL */
    for (i = 0; lock_status->is_locked && i < sizeof(kwd)/sizeof(*kwd); i++) {
        /* Construct our command */
        cmdlen = REDIS_SPPRINTF(&cmd, (char*)kwd[i], "sdSS", lua[i], len[i], 1,
            lock_status->lock_key, lock_status->lock_secret);

        /* Send it off */
        redis_simple_cmd(redis_sock, cmd, cmdlen, &reply, &replylen);

        /* Release lock and cleanup reply if we got one */
        if (reply != NULL) {
            lock_status->is_locked = 0;
            efree(reply);
        }

        /* Cleanup command */
        efree(cmd);
    }

    /* Something has failed if we are still locked */
    if (lock_status->is_locked) {
        php_error_docref(NULL, E_WARNING, "Failed to release session lock");
    }
}

#define REDIS_URL_STR(umem) ZSTR_VAL(umem)

/* {{{ PS_OPEN_FUNC
 */
PS_OPEN_FUNC(redis)
{
    php_url *url;
    zval params, context, *zv;
    int i, j, path_len;

    redis_pool *pool = ecalloc(1, sizeof(*pool));

    for (i = 0, j = 0, path_len = strlen(save_path); i < path_len; i = j + 1) {
        /* find beginning of url */
        while ( i< path_len && (isspace(save_path[i]) || save_path[i] == ','))
            i++;

        /* find end of url */
        j = i;
        while (j<path_len && !isspace(save_path[j]) && save_path[j] != ',')
            j++;

        if (i < j) {
            int weight = 1;
            double timeout = 86400.0, read_timeout = 0.0;
            int persistent = 0, db = -1;
            zend_long retry_interval = 0;
            zend_string *persistent_id = NULL, *prefix = NULL;
            zend_string *user = NULL, *pass = NULL;

            /* translate unix: into file: */
            if (!redis_strncmp(save_path+i, ZEND_STRL("unix:"))) {
                int len = j-i;
                char *path = estrndup(save_path+i, len);
                memcpy(path, "file:", sizeof("file:")-1);
                url = php_url_parse_ex(path, len);
                efree(path);
            } else {
                url = php_url_parse_ex(save_path+i, j-i);
            }

            if (!url) {
                char *path = estrndup(save_path+i, j-i);
                php_error_docref(NULL, E_WARNING,
                    "Failed to parse session.save_path (error at offset %d, url was '%s')", i, path);
                efree(path);

                goto fail;
            }

            ZVAL_NULL(&context);
            /* parse parameters */
            if (url->query != NULL) {
                HashTable *ht;
                char *query;
                array_init(&params);

                if (url->fragment) {
                    spprintf(&query, 0, "%s#%s", REDIS_URL_STR(url->query), REDIS_URL_STR(url->fragment));
                } else {
                    query = estrdup(REDIS_URL_STR(url->query));
                }

                sapi_module.treat_data(PARSE_STRING, query, &params);
                ht = Z_ARRVAL(params);

                REDIS_CONF_INT_STATIC(ht, "weight", &weight);
                REDIS_CONF_BOOL_STATIC(ht, "persistent", &persistent);
                REDIS_CONF_INT_STATIC(ht, "database", &db);
                REDIS_CONF_DOUBLE_STATIC(ht, "timeout", &timeout);
                REDIS_CONF_DOUBLE_STATIC(ht, "read_timeout", &read_timeout);
                REDIS_CONF_LONG_STATIC(ht, "retry_interval", &retry_interval);
                REDIS_CONF_STRING_STATIC(ht, "persistent_id", &persistent_id);
                REDIS_CONF_STRING_STATIC(ht, "prefix", &prefix);
                REDIS_CONF_AUTH_STATIC(ht, "auth", &user, &pass);

                if ((zv = REDIS_HASH_STR_FIND_TYPE_STATIC(ht, "stream", IS_ARRAY)) != NULL) {
                    ZVAL_ZVAL(&context, zv, 1, 0);
                }

                zval_dtor(&params);
            }

            if ((url->path == NULL && url->host == NULL) || weight <= 0 || timeout <= 0) {
                char *path = estrndup(save_path+i, j-i);
                php_error_docref(NULL, E_WARNING,
                    "Failed to parse session.save_path (error at offset %d, url was '%s')", i, path);
                efree(path);

                php_url_free(url);
                if (persistent_id) zend_string_release(persistent_id);
                if (prefix) zend_string_release(prefix);
                if (user) zend_string_release(user);
                if (pass) zend_string_release(pass);

                goto fail;
            }

            RedisSock *redis_sock;
            char *addr, *scheme;
            size_t addrlen;
            int port, addr_free = 0;

            scheme = url->scheme ? REDIS_URL_STR(url->scheme) : "tcp";
            if (url->host) {
                port = url->port;
                addrlen = spprintf(&addr, 0, "%s://%s", scheme, REDIS_URL_STR(url->host));
                addr_free = 1;
            } else { /* unix */
                port = 0;
                addr = REDIS_URL_STR(url->path);
                addrlen = strlen(addr);
            }

            redis_sock = redis_sock_create(addr, addrlen, port, timeout, read_timeout,
                                           persistent, persistent_id ? ZSTR_VAL(persistent_id) : NULL,
                                           retry_interval);

            if (db >= 0) { /* default is -1 which leaves the choice to redis. */
                redis_sock->dbNumber = db;
            }

            redis_sock->compression = session_compression_type();
            redis_sock->compression_level = INI_INT("redis.session.compression_level");

            if (Z_TYPE(context) == IS_ARRAY) {
                redis_sock_set_stream_context(redis_sock, &context);
            }

            redis_pool_add(pool, redis_sock, weight);
            redis_sock->prefix = prefix;
            redis_sock_set_auth(redis_sock, user, pass);

            if (addr_free) efree(addr);
            if (persistent_id) zend_string_release(persistent_id);
            if (user) zend_string_release(user);
            if (pass) zend_string_release(pass);
            php_url_free(url);
        }
    }

    if (pool->head) {
        PS_SET_MOD_DATA(pool);
        return SUCCESS;
    }

fail:
    redis_pool_free(pool);
    PS_SET_MOD_DATA(NULL);
    return FAILURE;
}
/* }}} */

/* {{{ PS_CLOSE_FUNC
 */
PS_CLOSE_FUNC(redis)
{
    redis_pool *pool = PS_GET_MOD_DATA();

    if (pool) {
        if (pool->lock_status.session_key) {
            redis_pool_member *rpm = redis_pool_get_sock(pool, ZSTR_VAL(pool->lock_status.session_key));

            RedisSock *redis_sock = rpm ? rpm->redis_sock : NULL;
            if (redis_sock) {
                lock_release(redis_sock, &pool->lock_status);
            }
        }

        redis_pool_free(pool);
        PS_SET_MOD_DATA(NULL);
    }

    return SUCCESS;
}
/* }}} */

static zend_string *
redis_session_key(RedisSock *redis_sock, const char *key, int key_len)
{
    zend_string *session;
    char default_prefix[] = REDIS_SESSION_PREFIX;
    char *prefix = default_prefix;
    size_t prefix_len = sizeof(default_prefix)-1;

    if (redis_sock->prefix) {
        prefix = ZSTR_VAL(redis_sock->prefix);
        prefix_len = ZSTR_LEN(redis_sock->prefix);
    }

    /* build session key */
    session = zend_string_alloc(key_len + prefix_len, 0);
    memcpy(ZSTR_VAL(session), prefix, prefix_len);
    memcpy(ZSTR_VAL(session) + prefix_len, key, key_len);

    return session;
}

/* {{{ PS_CREATE_SID_FUNC
 */
PS_CREATE_SID_FUNC(redis)
{
    int retries = 3;
    redis_pool *pool = PS_GET_MOD_DATA();

    if (!pool) {
        return php_session_create_id(NULL);
    }

    while (retries-- > 0) {
        zend_string* sid = php_session_create_id((void **) &pool);
        redis_pool_member *rpm = redis_pool_get_sock(pool, ZSTR_VAL(sid));

        RedisSock *redis_sock = rpm ? rpm->redis_sock : NULL;

        if (!redis_sock) {
            php_error_docref(NULL, E_NOTICE, "Redis connection not available");
            zend_string_release(sid);
            return php_session_create_id(NULL);
        }

        if (pool->lock_status.session_key) zend_string_release(pool->lock_status.session_key);
        pool->lock_status.session_key = redis_session_key(redis_sock, ZSTR_VAL(sid), ZSTR_LEN(sid));

        if (lock_acquire(redis_sock, &pool->lock_status) == SUCCESS) {
            return sid;
        }

        zend_string_release(pool->lock_status.session_key);
        zend_string_release(sid);

        sid = NULL;
    }

    php_error_docref(NULL, E_WARNING,
        "Acquiring session lock failed while creating session_id");

    return NULL;
}
/* }}} */

/* {{{ PS_VALIDATE_SID_FUNC
 */
PS_VALIDATE_SID_FUNC(redis)
{
    char *cmd, *response;
    int cmd_len, response_len;

    const char *skey = ZSTR_VAL(key);
    size_t skeylen = ZSTR_LEN(key);

    if (!skeylen) return FAILURE;

    redis_pool *pool = PS_GET_MOD_DATA();
    redis_pool_member *rpm = redis_pool_get_sock(pool, skey);
    RedisSock *redis_sock = rpm ? rpm->redis_sock : NULL;
    if (!redis_sock) {
        php_error_docref(NULL, E_WARNING, "Redis connection not available");
        return FAILURE;
    }

    /* send EXISTS command */
    zend_string *session = redis_session_key(redis_sock, skey, skeylen);
    cmd_len = REDIS_SPPRINTF(&cmd, "EXISTS", "S", session);
    zend_string_release(session);
    if (redis_sock_write(redis_sock, cmd, cmd_len) < 0 || (response = redis_sock_read(redis_sock, &response_len)) == NULL) {
        php_error_docref(NULL, E_WARNING, "Error communicating with Redis server");
        efree(cmd);
        return FAILURE;
    }

    efree(cmd);

    if (response_len == 2 && response[0] == ':' && response[1] == '1') {
        efree(response);
        return SUCCESS;
    } else {
        efree(response);
        return FAILURE;
    }
}
/* }}} */

/* {{{ PS_UPDATE_TIMESTAMP_FUNC
 */
PS_UPDATE_TIMESTAMP_FUNC(redis)
{
    char *cmd, *response;
    int cmd_len, response_len;

    const char *skey = ZSTR_VAL(key);
    size_t skeylen = ZSTR_LEN(key);

    if (!skeylen) return FAILURE;

    /* No need to update the session timestamp if we've already done so */
    if (INI_INT("redis.session.early_refresh")) {
        return SUCCESS;
    }

    redis_pool *pool = PS_GET_MOD_DATA();
    redis_pool_member *rpm = redis_pool_get_sock(pool, skey);
    RedisSock *redis_sock = rpm ? rpm->redis_sock : NULL;
    if (!redis_sock) {
        php_error_docref(NULL, E_WARNING, "Redis connection not available");
        return FAILURE;
    }

    /* send EXPIRE command */
    zend_string *session = redis_session_key(redis_sock, skey, skeylen);
    cmd_len = REDIS_SPPRINTF(&cmd, "EXPIRE", "Sd", session, session_gc_maxlifetime());
    zend_string_release(session);

    if (redis_sock_write(redis_sock, cmd, cmd_len) < 0 || (response = redis_sock_read(redis_sock, &response_len)) == NULL) {
        php_error_docref(NULL, E_WARNING, "Error communicating with Redis server");
        efree(cmd);
        return FAILURE;
    }

    efree(cmd);

    if (response_len == 2 && response[0] == ':') {
        efree(response);
        return SUCCESS;
    } else {
        efree(response);
        return FAILURE;
    }
}
/* }}} */

/* {{{ PS_READ_FUNC
 */
PS_READ_FUNC(redis)
{
    char *resp, *cmd, *compressed_buf;
    int resp_len, cmd_len, compressed_free;
    const char *skey = ZSTR_VAL(key);
    size_t skeylen = ZSTR_LEN(key), compressed_len;

    if (!skeylen) return FAILURE;

    redis_pool *pool = PS_GET_MOD_DATA();
    redis_pool_member *rpm = redis_pool_get_sock(pool, skey);
    RedisSock *redis_sock = rpm ? rpm->redis_sock : NULL;
    if (!redis_sock) {
        php_error_docref(NULL, E_WARNING, "Redis connection not available");
        return FAILURE;
    }

    /* send GET command */
    if (pool->lock_status.session_key) zend_string_release(pool->lock_status.session_key);
    pool->lock_status.session_key = redis_session_key(redis_sock, skey, skeylen);

    /* Update the session ttl if early refresh is enabled */
    if (INI_INT("redis.session.early_refresh")) {
        cmd_len = REDIS_SPPRINTF(&cmd, "GETEX", "Ssd", pool->lock_status.session_key,
                                 "EX", 2, session_gc_maxlifetime());
    } else {
        cmd_len = REDIS_SPPRINTF(&cmd, "GET", "S", pool->lock_status.session_key);
    }

    if (lock_acquire(redis_sock, &pool->lock_status) != SUCCESS) {
        if (INI_INT("redis.session.lock_failure_readonly")) {
            // opt-in legacy behavior: readonly session
            php_error_docref(NULL, E_WARNING, "Failed to acquire session lock, session will be read only");
        } else {
            php_error_docref(NULL, E_WARNING, "Failed to acquire session lock");
            efree(cmd);
            return FAILURE;
        }
    }

    if (redis_sock_write(redis_sock, cmd, cmd_len) < 0) {
        php_error_docref(NULL, E_WARNING, "Error communicating with Redis server");
        efree(cmd);
        return FAILURE;
    }

    efree(cmd);

    /* Read response from Redis.  If we get a NULL response from redis_sock_read
     * this can indicate an error, OR a "NULL bulk" reply (empty session data)
     * in which case we can reply with success. */
    if ((resp = redis_sock_read(redis_sock, &resp_len)) == NULL && resp_len != -1) {
        php_error_docref(NULL, E_WARNING, "Error communicating with Redis server");
        return FAILURE;
    }

    if (resp_len < 0) {
        *val = ZSTR_EMPTY_ALLOC();
    } else {
        compressed_free = session_uncompress_data(redis_sock, resp, resp_len, &compressed_buf, &compressed_len);
        *val = zend_string_init(compressed_buf, compressed_len, 0);
        if (compressed_free) {
            efree(compressed_buf); // Free the buffer allocated by redis_uncompress
        }
    }

    efree(resp);

    return SUCCESS;
}
/* }}} */

/* {{{ PS_WRITE_FUNC
 */
PS_WRITE_FUNC(redis)
{
    char *cmd, *response;
    int cmd_len, response_len, compressed_free;
    const char *skey = ZSTR_VAL(key);
    size_t skeylen = ZSTR_LEN(key), svallen = ZSTR_LEN(val);
    char *sval;

    if (!skeylen) return FAILURE;

    redis_pool *pool = PS_GET_MOD_DATA();
    redis_pool_member *rpm = redis_pool_get_sock(pool, skey);
    RedisSock *redis_sock = rpm ? rpm->redis_sock : NULL;
    if (!redis_sock) {
        php_error_docref(NULL, E_WARNING, "Redis connection not available");
        return FAILURE;
    }

    /* send SET command */
    zend_string *session = redis_session_key(redis_sock, skey, skeylen);

    compressed_free = session_compress_data(redis_sock, ZSTR_VAL(val), ZSTR_LEN(val),
                                            &sval, &svallen);

    cmd_len = REDIS_SPPRINTF(&cmd, "SETEX", "Sds", session, session_gc_maxlifetime(), sval, svallen);
    zend_string_release(session);
    if (compressed_free) {
        efree(sval);
    }

    if (!write_allowed(redis_sock, &pool->lock_status)) {
        php_error_docref(NULL, E_WARNING, "Unable to write session: session lock not held");
        efree(cmd);
        return FAILURE;
    }

    if (redis_sock_write(redis_sock, cmd, cmd_len ) < 0 || (response = redis_sock_read(redis_sock, &response_len)) == NULL) {
        php_error_docref(NULL, E_WARNING, "Error communicating with Redis server");
        efree(cmd);
        return FAILURE;
    }

    efree(cmd);

    if (IS_REDIS_OK(response, response_len)) {
        efree(response);
        return SUCCESS;
    } else {
        php_error_docref(NULL, E_WARNING, "Error writing session data to Redis: %s", response);
        efree(response);
        return FAILURE;
    }
}
/* }}} */

/* {{{ PS_DESTROY_FUNC
 */
PS_DESTROY_FUNC(redis)
{
    char *cmd, *response;
    int cmd_len, response_len;
    const char *skey = ZSTR_VAL(key);
    size_t skeylen = ZSTR_LEN(key);

    redis_pool *pool = PS_GET_MOD_DATA();
    redis_pool_member *rpm = redis_pool_get_sock(pool, skey);
    RedisSock *redis_sock = rpm ? rpm->redis_sock : NULL;
    if (!redis_sock) {
        php_error_docref(NULL, E_WARNING, "Redis connection not available");
        return FAILURE;
    }

    /* Release lock */
    lock_release(redis_sock, &pool->lock_status);

    /* send DEL command */
    zend_string *session = redis_session_key(redis_sock, skey, skeylen);
    cmd_len = REDIS_SPPRINTF(&cmd, "DEL", "S", session);
    zend_string_release(session);
    if (redis_sock_write(redis_sock, cmd, cmd_len) < 0 || (response = redis_sock_read(redis_sock, &response_len)) == NULL) {
        php_error_docref(NULL, E_WARNING, "Error communicating with Redis server");
        efree(cmd);
        return FAILURE;
    }

    efree(cmd);

    if (response_len == 2 && response[0] == ':' && (response[1] == '0' || response[1] == '1')) {
        efree(response);
        return SUCCESS;
    } else {
        efree(response);
        return FAILURE;
    }
}
/* }}} */

/* {{{ PS_GC_FUNC
 */
PS_GC_FUNC(redis)
{
    return SUCCESS;
}
/* }}} */

/**
 * Redis Cluster session handler functions
 */

/* Prefix a session key */

/* ---- Cluster session locking (backported from cluster_session_lock) ---- */

/* Select the lock-key form based on the full (prefixed) session key.
 * Mirrors Redis's keyHashSlot() first-{tag} rule so the derived lock key
 * co-locates with the session key:
 *   EXISTING_TAG : non-empty first "{tag}" -> lock = <sk>_LOCK
 *   WRAP         : no braces at all        -> lock = {<sk>}_LOCK
 *   INVALID      : any other brace shape   -> reject */
typedef enum {
    LOCK_KEY_INVALID = 0,
    LOCK_KEY_EXISTING_TAG,
    LOCK_KEY_WRAP,
} cluster_lock_key_form;

static cluster_lock_key_form select_cluster_lock_key_form(const char *sk, size_t slen)
{
    int s = -1;
    size_t i;

    for (i = 0; i < slen; i++) {
        if (sk[i] == '{') {
            if (s < 0) s = (int)i;
        } else if (sk[i] == '}') {
            if (s >= 0) {
                return (i == (size_t)s + 1) ? LOCK_KEY_INVALID : LOCK_KEY_EXISTING_TAG;
            }
            if (s == -1) s = -2;
        }
    }
    return (s == -1) ? LOCK_KEY_WRAP : LOCK_KEY_INVALID;
}

/* Create a lock key that hashes to the SAME slot as the session key, so the
 * atomic acquire-and-read Lua script never trips CROSSSLOT.  Returns
 * SUCCESS / FAILURE; on FAILURE the caller (PS_READ) emits a diagnostic
 * warning and fails the request. */
static int generate_cluster_lock_key(redis_session_lock_status *status)
{
    const char *sk = ZSTR_VAL(status->session_key);
    size_t slen = ZSTR_LEN(status->session_key);
    size_t klen;
    cluster_lock_key_form form;
    zend_string *out;
    char *p;
    const char *prefix = "", *suffix = "";
    size_t prefix_len = 0, suffix_len = 0;

    /* Always (re)derive so lock_key stays in sync with the current session_key. */
    if (status->lock_key) {
        zend_string_release(status->lock_key);
        status->lock_key = NULL;
    }

    form = select_cluster_lock_key_form(sk, slen);

    if (form == LOCK_KEY_EXISTING_TAG) {
        suffix = "_LOCK";
        suffix_len = sizeof("_LOCK") - 1;
    } else if (form == LOCK_KEY_WRAP) {
        prefix = "{";
        prefix_len = 1;
        suffix = "}_LOCK";
        suffix_len = sizeof("}_LOCK") - 1;
    } else {
        return FAILURE;
    }

    klen = prefix_len + slen + suffix_len;
    out = zend_string_alloc(klen, 0);
    p = ZSTR_VAL(out);
    memcpy(p, prefix, prefix_len);                     /* optional '{'          */
    memcpy(p + prefix_len, sk, slen);                  /* the session key bytes */
    memcpy(p + prefix_len + slen, suffix, suffix_len); /* "_LOCK" or "}_LOCK"   */
    p[klen] = '\0';                                    /* terminating NUL       */

    status->lock_key = out;
    return SUCCESS;
}

/* Process-stable lock secret (hostname|pid), matching the standalone handler. */
static void generate_lock_secret(redis_session_lock_status *status) {
    char hostname[HOST_NAME_MAX] = {0};

    gethostname(hostname, HOST_NAME_MAX);
    if (status->lock_secret) zend_string_release(status->lock_secret);
    status->lock_secret = strpprintf(0, "%s|%ld", hostname, (long)getpid());
}

/* Map redis.session.lock_release_cmd to a release primitive. */
static lockDelCmd lock_release_cmd(void) {
    const char *cmd = INI_STR("redis.session.lock_release_cmd");

    if (cmd == NULL) {
        return LOCK_DEL_EVAL;
    } else if (strcasecmp(cmd, "DELEX") == 0) {
        return LOCK_DEL_DELEX;
    } else if (strcasecmp(cmd, "DELIFEQ") == 0) {
        return LOCK_DEL_DELIFEQ;
    }

    return LOCK_DEL_EVAL;
}

typedef struct {
    redisCluster *cluster;
    redis_session_lock_status lock_status;
} redis_cluster_session;

static redis_cluster_session *cluster_session_alloc(redisCluster *c) {
    redis_cluster_session *rcs = ecalloc(1, sizeof(*rcs));
    rcs->cluster = c;
    return rcs;
}

static void cluster_session_free(redis_cluster_session *rcs) {
    if (rcs == NULL) return;

    if (rcs->lock_status.session_key) zend_string_release(rcs->lock_status.session_key);
    if (rcs->lock_status.lock_secret) zend_string_release(rcs->lock_status.lock_secret);
    if (rcs->lock_status.lock_key)    zend_string_release(rcs->lock_status.lock_key);

    if (rcs->cluster) cluster_free(rcs->cluster, 1);
    efree(rcs);
}

/* Send a single command at the given slot. Returns SUCCESS (+OK = locked),
 * NEGATIVE_LOCK_RESPONSE (nil = busy), or FAILURE (transport error). */
static int cluster_set_session_lock_key(redisCluster *c, char *cmd, int cmdlen, short slot) {
    clusterReply *reply;
    int result;

    /* Must go to the slot master, not a replica */
    c->readonly = 0;
    if (cluster_send_command(c, slot, cmd, cmdlen) < 0 || c->err) {
        return FAILURE;
    }

    /* status_strings=1: +OK reply has len>0, nil bulk has len<=0. */
    reply = cluster_read_resp(c, 1);
    if (!reply || c->err) {
        if (reply) cluster_free_reply(reply, 1);
        return FAILURE;
    }

    result = (reply->len > 0) ? SUCCESS : NEGATIVE_LOCK_RESPONSE;
    cluster_free_reply(reply, 1);
    return result;
}

/* Cluster equivalent of lock_acquire(). Idempotent on lock_status: re-entry
 * is safe because generate_cluster_lock_key() and generate_lock_secret() are
 * deterministic on session_key and process identity respectively. */
static int cluster_lock_acquire(redisCluster *c, redis_session_lock_status *lock_status)
{
    zend_long wait_time, expiry, retries, attempt = 0;
    int result;
    char *cmd; int cmdlen;
    short slot;

    if (lock_status->is_locked || !INI_INT("redis.session.locking_enabled"))
        return SUCCESS;

    wait_time = INI_INT("redis.session.lock_wait_time");
    if (wait_time == 0) wait_time = 20000;

    retries = INI_INT("redis.session.lock_retries");
    if (retries == 0) retries = 100;

    expiry = INI_INT("redis.session.lock_expire");
    if (expiry == 0) expiry = INI_INT("max_execution_time");

    /* Defensive re-derive in case we're ever called outside PS_READ */
    if (generate_cluster_lock_key(lock_status) != SUCCESS) {
        return FAILURE;
    }
    if (!lock_status->lock_secret) {
        generate_lock_secret(lock_status);
    }

    if (expiry > 0) {
        cmdlen = redis_spprintf(NULL, NULL, &cmd, "SET", "SSssd",
                            lock_status->lock_key, lock_status->lock_secret,
                            ZEND_STRL("NX"), ZEND_STRL("PX"), expiry * 1000);
    } else {
        cmdlen = redis_spprintf(NULL, NULL, &cmd, "SET", "SSs",
                            lock_status->lock_key, lock_status->lock_secret,
                            ZEND_STRL("NX"));
    }
    slot = cluster_hash_key_zstr(lock_status->lock_key);

    /* Attempt to get our lock */
    for (;;) {
        result = cluster_set_session_lock_key(c, cmd, cmdlen, slot);

        if (result == SUCCESS) {
            lock_status->is_locked = 1;
            break;
        } else if (result == FAILURE) {
            /* Network failure */
            break;
        }

        /* Lock is busy */

        if (retries >= 0 && attempt++ >= retries) {
            break;
        }

        usleep(wait_time);
    }

    /* Cleanup SET command */
    efree(cmd);

    /* Success if we're locked */
    return lock_status->is_locked ? SUCCESS : FAILURE;
}

/* Cluster equivalent of write_allowed(). GETs the lock key and verifies the
 * value still matches our secret; warns and clears is_locked if not. */
static int cluster_write_allowed(redisCluster *c, redis_session_lock_status *lock_status)
{
    if (!INI_INT("redis.session.locking_enabled")) {
        return 1;
    }
    /* If locked and redis.session.lock_expire is not set => TTL=max_execution_time
       Therefore it is guaranteed that the current process is still holding the lock */

    if (lock_status->is_locked && INI_INT("redis.session.lock_expire") != 0) {
        char *cmd; int cmdlen;
        short slot;
        clusterReply *reply = NULL;

        /* Command to get our lock key value and compare secrets */
        cmdlen = redis_spprintf(NULL, NULL, &cmd, "GET", "S", lock_status->lock_key);
        slot = cluster_hash_key_zstr(lock_status->lock_key);

        /* Must go to the slot master, not a replica */
        c->readonly = 0;

        /* Attempt to refresh the lock */
        if (cluster_send_command(c, slot, cmd, cmdlen) >= 0 && !c->err) {
            reply = cluster_read_resp(c, 0);
            if (c->err && reply) {
                cluster_free_reply(reply, 1);
                reply = NULL;
            }
        }
        /* Cleanup */
        efree(cmd);

        if (reply == NULL) {
            lock_status->is_locked = 0;
        } else {
            lock_status->is_locked = IS_LOCK_SECRET(reply->str, reply->len, lock_status->lock_secret);
            cluster_free_reply(reply, 1);
        }

        /* Issue a warning if we're not locked.  We don't attempt to refresh the lock
         * if we aren't flagged as locked, so if we're not flagged here something
         * failed */
        if (!lock_status->is_locked) {
            php_error_docref(NULL, E_WARNING, "Session lock expired");
        }
    }

    return lock_status->is_locked;
}

static delResult
cluster_get_del_result(redisCluster *c, clusterReply *reply)
{
    zend_bool nocmd = 0;

    #define NOCMD_PFX "ERR unknown command"

    if (reply == NULL || c->err) {
        if (c->err) {
            php_error_docref(NULL, E_WARNING, "%s", ZSTR_VAL(c->err));
            nocmd = ZSTR_LEN(c->err) >= sizeof(NOCMD_PFX) - 1 && !redis_strncmp(ZSTR_VAL(c->err), NOCMD_PFX, sizeof(NOCMD_PFX) - 1);
            zend_string_release(c->err);
            c->err = NULL;
        }
        return nocmd ? DEL_NO_CMD : DEL_FAILURE;
    } else if (reply->integer == 1) {
        return DEL_SUCCESS;
    } else {
        return DEL_FAILURE;
    }

    #undef NOCMD_PFX
}

/* Send a release command (DELEX or DELIFEQ) and parse the reply. */
static delResult cluster_send_release_cmd(redisCluster *c, short slot, char *cmd, int cmdlen)
{
    clusterReply *reply;
    delResult result;

    /* Scrub stale c->err so cluster_get_del_result classifies this call's
     * error (in particular "ERR unknown command" → DEL_NO_CMD so the
     * caller can fall back to LUA), not whatever the previous call left. */
    if (c->err) {
        zend_string_release(c->err);
        c->err = NULL;
    }

    c->readonly = 0;
    if (cluster_send_command(c, slot, cmd, cmdlen) < 0) {
        return DEL_FAILURE;
    }

    reply = cluster_read_resp(c, 0);
    result = cluster_get_del_result(c, reply);
    if (reply) cluster_free_reply(reply, 1);

    return result;
}

static delResult
cluster_lock_release_delex(redisCluster *c, redis_session_lock_status *status)
{
    char *cmd; int cmdlen;
    short slot;
    delResult result;

    cmdlen = redis_spprintf(NULL, NULL, &cmd, "DELEX", "SsS", status->lock_key,
                        ZEND_STRL("IFEQ"), status->lock_secret);
    slot = cluster_hash_key_zstr(status->lock_key);

    result = cluster_send_release_cmd(c, slot, cmd, cmdlen);

    efree(cmd);

    return result;
}

static delResult
cluster_lock_release_delifeq(redisCluster *c, redis_session_lock_status *status)
{
    char *cmd; int cmdlen;
    short slot;
    delResult result;

    cmdlen = redis_spprintf(NULL, NULL, &cmd, "DELIFEQ", "SS", status->lock_key,
                        status->lock_secret);
    slot = cluster_hash_key_zstr(status->lock_key);

    result = cluster_send_release_cmd(c, slot, cmd, cmdlen);

    efree(cmd);

    return result;
}

/* Release any session lock we hold and cleanup allocated lock data.  This
 * function first attempts to use EVALSHA and then falls back to EVAL if
 * EVALSHA fails.  This will cause Redis to cache the script, so subsequent
 * calls should then succeed using EVALSHA. */
static void
cluster_lock_release_lua(redisCluster *c, redis_session_lock_status *status)
{
    int i;
    char *cmd; int cmdlen;
    short slot;
    clusterReply *reply;

    slot = cluster_hash_key_zstr(status->lock_key);

    /* We first want to try EVALSHA and then fall back to EVAL */
    for (i = 0; status->is_locked && i < (int)(sizeof(lua_cmd) / sizeof(*lua_cmd)); i++) {
        cmdlen = redis_spprintf(NULL, NULL, &cmd, lua_cmd[i].kw, "sdSS",
                            lua_cmd[i].str, lua_cmd[i].len, 1,
                            status->lock_key, status->lock_secret);

        c->readonly = 0;
        if (cluster_send_command(c, slot, cmd, cmdlen) < 0) {
            efree(cmd);
            continue;
        }
        efree(cmd);

        reply = cluster_read_resp(c, 0);
        if (reply && !c->err) {
            status->is_locked = 0;
        }
        if (reply) cluster_free_reply(reply, 1);
    }

    /* Something has failed if we are still locked */
    if (status->is_locked) {
        php_error_docref(NULL, E_WARNING, "Failed to release session lock");
    }
}

static void
cluster_lock_release(redisCluster *c, redis_session_lock_status *status)
{
    delResult res = DEL_NO_CMD;

    if (status->lock_key == NULL)
        return;

    switch (lock_release_cmd()) {
        case LOCK_DEL_DELEX:
            res = cluster_lock_release_delex(c, status);
            break;
        case LOCK_DEL_DELIFEQ:
            res = cluster_lock_release_delifeq(c, status);
            break;
        case LOCK_DEL_EVAL:
            break; /* fallthrough */
    }

    /* If res == DEL_NO_CMD LUA is selected or the new command didn't exist */
    if (res == DEL_NO_CMD)
        cluster_lock_release_lua(c, status);
}

/* Plain session data read for PS_READ. Used when locking is disabled and
 * after a successful retry-acquire (the pre-lock read is discarded since
 * another writer may have mutated the data before we got the lock).
 *
 * Returns SUCCESS on transport success and writes the data into *out_data
 * (zero-length zend_string when the session key is missing). */
static int cluster_read_session_data(redisCluster *c,
                                     zend_string *session_key,
                                     zend_long session_ttl_seconds,
                                     zend_string **out_data)
{
    char *cmd; int cmdlen;
    short slot;
    clusterReply *reply;

    slot = cluster_hash_key_zstr(session_key);

    /* Must go to the slot master, not a replica */
    if (session_ttl_seconds > 0) {
        cmdlen = redis_spprintf(NULL, NULL, &cmd, "GETEX", "Ssd", session_key,
                            ZEND_STRL("EX"), session_ttl_seconds);
    } else {
        cmdlen = redis_spprintf(NULL, NULL, &cmd, "GET", "S", session_key);
    }
    c->readonly = 0;

    if (cluster_send_command(c, slot, cmd, cmdlen) < 0 || c->err) {
        efree(cmd);
        return FAILURE;
    }
    efree(cmd);

    reply = cluster_read_resp(c, 0);
    if (!reply || c->err) {
        if (reply) cluster_free_reply(reply, 1);
        return FAILURE;
    }

    if (reply->str == NULL) {
        *out_data = ZSTR_EMPTY_ALLOC();
    } else {
        *out_data = zend_string_init(reply->str, reply->len, 0);
    }

    cluster_free_reply(reply, 1);
    return SUCCESS;
}

/* Atomic acquire-and-read for PS_READ via EVAL/EVALSHA against
 * KEYS=[session_data, lock_key]. SUCCESS means the EVAL completed; the
 * caller inspects lock_status->is_locked and reads *out_data (zero-length
 * when the key is missing). Tries EVALSHA first, falls back to EVAL on
 * NOSCRIPT (which also warms the script cache for subsequent EVALSHA hits). */
static int cluster_lock_acquire_and_read(redisCluster *c,
                                         redis_session_lock_status *lock_status,
                                         zend_string *session_key,
                                         zend_long session_ttl_seconds,
                                         zend_string **out_data)
{
    zend_long expiry;
    zend_long lock_ms;
    char *cmd; int cmdlen;
    int i;
    short slot;
    clusterReply *reply;
    int got_response = 0;

    expiry = INI_INT("redis.session.lock_expire");
    if (expiry == 0) expiry = INI_INT("max_execution_time");
    lock_ms = expiry > 0 ? expiry * 1000 : 0;

    /* Caller must have generated the lock key (slot/co-location decided
     * up front). Lock secret is process-stable; (re)generate if missing. */
    if (!lock_status->lock_key) {
        return FAILURE;
    }
    if (!lock_status->lock_secret) {
        generate_lock_secret(lock_status);
    }

    /* Both keys hash to the same slot (caller-confirmed). */
    slot = cluster_hash_key_zstr(lock_status->lock_key);

    /* We first want to try EVALSHA and then fall back to EVAL */
    for (i = 0; i < (int)(sizeof(lua_rw_cmd) / sizeof(*lua_rw_cmd)); i++) {
        /* Clear prior NOSCRIPT error so the EVAL fallback can run */
        if (c->err) {
            zend_string_release(c->err);
            c->err = NULL;
        }

        /* EVAL[SHA] <script> 2 <session_key> <lock_key> <secret> <lock_ms> <session_ttl> */
        cmdlen = redis_spprintf(NULL, NULL, &cmd, lua_rw_cmd[i].kw, "sdSSSdd",
                            lua_rw_cmd[i].str, lua_rw_cmd[i].len,
                            2,
                            session_key, lock_status->lock_key,
                            lock_status->lock_secret,
                            lock_ms,
                            session_ttl_seconds);

        c->readonly = 0;
        if (cluster_send_command(c, slot, cmd, cmdlen) < 0) {
            efree(cmd);
            /* Transport failure — EVAL fallback can't help */
            return FAILURE;
        }
        efree(cmd);

        reply = cluster_read_resp(c, 0);
        if (reply && reply->type == TYPE_MULTIBULK && reply->elements >= 2) {
            clusterReply *r_locked = reply->element[0];
            clusterReply *r_data   = reply->element[1];
            zend_long locked_int = 0;

            /* Lua returns RESP integer per spec; accept bulk "1"/"0" too so
             * a RESP3 proxy can't force a wasted retry after we hold the lock */
            if (r_locked) {
                if (r_locked->type == TYPE_INT) {
                    locked_int = r_locked->integer;
                } else if (r_locked->type == TYPE_BULK && r_locked->str
                           && r_locked->len > 0)
                {
                    locked_int = strtol(r_locked->str, NULL, 10);
                }
            }

            if (locked_int == 1) {
                lock_status->is_locked = 1;
            }

            if (r_data && r_data->str) {
                *out_data = zend_string_init(r_data->str, r_data->len, 0);
            } else {
                *out_data = ZSTR_EMPTY_ALLOC();
            }

            cluster_free_reply(reply, 1);
            got_response = 1;
            break;
        }

        if (reply) cluster_free_reply(reply, 1);

        /* NOSCRIPT or unrecognised reply — let EVAL try next iteration */
    }

    /* Drop residual error so the caller's retry/write paths don't inherit it */
    if (c->err) {
        zend_string_release(c->err);
        c->err = NULL;
    }

    return got_response ? SUCCESS : FAILURE;
}


static char *cluster_session_key(redisCluster *c, const char *key, int keylen,
                                 int *skeylen, short *slot) {
    char *skey;

    *skeylen = keylen + ZSTR_LEN(c->flags->prefix);
    skey = emalloc(*skeylen);
    memcpy(skey, ZSTR_VAL(c->flags->prefix), ZSTR_LEN(c->flags->prefix));
    memcpy(skey + ZSTR_LEN(c->flags->prefix), key, keylen);

    *slot = cluster_hash_key(skey, *skeylen);

    return skey;
}

PS_OPEN_FUNC(rediscluster) {
    redisCluster *c;
    zval z_conf, *zv, *context;
    HashTable *ht_conf, *ht_seeds;
    double timeout = 0, read_timeout = 0;
    int persistent = 0, failover = REDIS_FAILOVER_NONE;
    zend_string *prefix = NULL, *user = NULL, *pass = NULL, *failstr = NULL;

    /* Parse configuration for session handler */
    array_init(&z_conf);
    sapi_module.treat_data(PARSE_STRING, estrdup(save_path), &z_conf);

    /* We need seeds */
    zv = REDIS_HASH_STR_FIND_TYPE_STATIC(Z_ARRVAL(z_conf), "seed", IS_ARRAY);
    if (zv == NULL) {
        zval_dtor(&z_conf);
        return FAILURE;
    }

    /* Grab a copy of our config hash table and keep seeds array */
    ht_conf = Z_ARRVAL(z_conf);
    ht_seeds = Z_ARRVAL_P(zv);

    /* Optional configuration settings */
    REDIS_CONF_DOUBLE_STATIC(ht_conf, "timeout", &timeout);
    REDIS_CONF_DOUBLE_STATIC(ht_conf, "read_timeout", &read_timeout);
    REDIS_CONF_BOOL_STATIC(ht_conf, "persistent", &persistent);

    /* Sanity check on our timeouts */
    if (timeout < 0 || read_timeout < 0) {
        php_error_docref(NULL, E_WARNING,
            "Can't set negative timeout values in session configuration");
        zval_dtor(&z_conf);
        return FAILURE;
    }

    REDIS_CONF_STRING_STATIC(ht_conf, "prefix", &prefix);
    REDIS_CONF_AUTH_STATIC(ht_conf, "auth", &user, &pass);
    REDIS_CONF_STRING_STATIC(ht_conf, "failover", &failstr);

    /* Need to massage failover string if we have it */
    if (failstr) {
        if (zend_string_equals_literal_ci(failstr, "error")) {
            failover = REDIS_FAILOVER_ERROR;
        } else if (zend_string_equals_literal_ci(failstr, "distribute")) {
            failover = REDIS_FAILOVER_DISTRIBUTE;
        }
    }

    redisCachedCluster *cc;
    zend_string **seeds, *hash = NULL;
    uint32_t nseeds;

    #define CLUSTER_SESSION_CLEANUP() \
        if (hash) zend_string_release(hash); \
        if (failstr) zend_string_release(failstr); \
        if (prefix) zend_string_release(prefix); \
        if (user) zend_string_release(user); \
        if (pass) zend_string_release(pass); \
        free_seed_array(seeds, nseeds); \
        zval_dtor(&z_conf); \

    /* Extract at least one valid seed or abort */
    seeds = cluster_validate_args(timeout, read_timeout, ht_seeds, &nseeds, NULL);
    if (seeds == NULL) {
        php_error_docref(NULL, E_WARNING, "No valid seeds detected");
        CLUSTER_SESSION_CLEANUP();
        return FAILURE;
    }

    c = cluster_create(timeout, read_timeout, failover, persistent);

    if (prefix) {
        c->flags->prefix = zend_string_copy(prefix);
    } else {
        c->flags->prefix = CLUSTER_DEFAULT_PREFIX();
    }

    c->flags->compression = session_compression_type();
    c->flags->compression_level = INI_INT("redis.session.compression_level");

    redis_sock_set_auth(c->flags, user, pass);

    if ((context = REDIS_HASH_STR_FIND_TYPE_STATIC(ht_conf, "stream", IS_ARRAY)) != NULL) {
        redis_sock_set_stream_context(c->flags, context);
    }

    /* First attempt to load from cache */
    if (CLUSTER_CACHING_ENABLED()) {
        hash = cluster_hash_seeds(seeds, nseeds);
        if ((cc = cluster_cache_load(hash))) {
            cluster_init_cache(c, cc);
            goto success;
        }
    }

    /* Initialize seed array, and attempt to map keyspace */
    cluster_init_seeds(c, seeds, nseeds);
    if (cluster_map_keyspace(c) != SUCCESS)
        goto failure;

    /* Now cache our cluster if caching is enabled */
    if (hash)
        cluster_cache_store(hash, c->nodes);

success:
    CLUSTER_SESSION_CLEANUP();
    PS_SET_MOD_DATA(cluster_session_alloc(c));
    return SUCCESS;

failure:
    CLUSTER_SESSION_CLEANUP();
    cluster_free(c, 1);
    return FAILURE;
}

/* {{{ PS_CREATE_SID_FUNC
 */
PS_CREATE_SID_FUNC(rediscluster)
{
    redis_cluster_session *rcs = PS_GET_MOD_DATA();
    redisCluster *c = rcs ? rcs->cluster : NULL;
    clusterReply *reply;
    char *cmd, *skey;
    zend_string *sid;
    int cmdlen, skeylen;
    int retries = 3;
    short slot;

    if (!c) {
        return php_session_create_id(NULL);
    }

    if (INI_INT("session.use_strict_mode") == 0) {
        return php_session_create_id((void **) &c);
    }

    while (retries-- > 0) {
        sid = php_session_create_id((void **) &c);

        /* Create session key if it doesn't already exist */
        skey = cluster_session_key(c, ZSTR_VAL(sid), ZSTR_LEN(sid), &skeylen, &slot);
        cmdlen = redis_spprintf(NULL, NULL, &cmd, "SET", "ssssd", skey,
                        skeylen, "", 0, "NX", 2, "EX", 2, session_gc_maxlifetime());

        efree(skey);

        /* Attempt to kick off our command */
        c->readonly = 0;
        if (cluster_send_command(c,slot,cmd,cmdlen) < 0 || c->err) {
            php_error_docref(NULL, E_NOTICE, "Redis connection not available");
            efree(cmd);
            zend_string_release(sid);
            return php_session_create_id(NULL);;
        }

        efree(cmd);

        /* Attempt to read reply */
        reply = cluster_read_resp(c, 1);

        if (!reply || c->err) {
            php_error_docref(NULL, E_NOTICE, "Unable to read redis response");
        } else if (reply->len > 0) {
            cluster_free_reply(reply, 1);
            break;
        } else {
            php_error_docref(NULL, E_NOTICE, "Redis sid collision on %s, retrying %d time(s)", sid->val, retries);
        }

        if (reply) {
            cluster_free_reply(reply, 1);
        }

        zend_string_release(sid);
        sid = NULL;
    }

    return sid;
}
/* }}} */

/* {{{ PS_VALIDATE_SID_FUNC
 */
PS_VALIDATE_SID_FUNC(rediscluster)
{
    redis_cluster_session *rcs = PS_GET_MOD_DATA();
    redisCluster *c = rcs ? rcs->cluster : NULL;
    clusterReply *reply;
    char *cmd, *skey;
    int cmdlen, skeylen;
    int res = FAILURE;
    short slot;

    /* Check key is valid and whether it already exists */
    if (php_session_valid_key(ZSTR_VAL(key)) == FAILURE) {
        php_error_docref(NULL, E_NOTICE, "Invalid session key: %s", ZSTR_VAL(key));
        return FAILURE;
    }

    skey = cluster_session_key(c, ZSTR_VAL(key), ZSTR_LEN(key), &skeylen, &slot);
    cmdlen = redis_spprintf(NULL, NULL, &cmd, "EXISTS", "s", skey, skeylen);
    efree(skey);

    /* We send to master, to ensure consistency */
    c->readonly = 0;
    if (cluster_send_command(c,slot,cmd,cmdlen) < 0 || c->err) {
        php_error_docref(NULL, E_NOTICE, "Redis connection not available");
        efree(cmd);
        return FAILURE;
    }

    efree(cmd);

    /* Attempt to read reply */
    reply = cluster_read_resp(c, 0);

    if (!reply || c->err) {
        php_error_docref(NULL, E_NOTICE, "Unable to read redis response");
        res = FAILURE;
    } else if (reply->integer == 1) {
        res = SUCCESS;
    }

     /* Clean up */
    if (reply) {
        cluster_free_reply(reply, 1);
    }

    return res;
}
/* }}} */

/* {{{ PS_UPDATE_TIMESTAMP_FUNC
 */
PS_UPDATE_TIMESTAMP_FUNC(rediscluster) {
    redis_cluster_session *rcs = PS_GET_MOD_DATA();
    redisCluster *c = rcs ? rcs->cluster : NULL;
    clusterReply *reply;
    char *cmd, *skey;
    int cmdlen, skeylen;
    short slot;

    /* No need to update the session timestamp if we've already done so */
    if (INI_INT("redis.session.early_refresh")) {
        return SUCCESS;
    }

    /* Set up command and slot info */
    skey = cluster_session_key(c, ZSTR_VAL(key), ZSTR_LEN(key), &skeylen, &slot);
    cmdlen = redis_spprintf(NULL, NULL, &cmd, "EXPIRE", "sd", skey,
                            skeylen, session_gc_maxlifetime());
    efree(skey);

    /* Attempt to send EXPIRE command */
    c->readonly = 0;
    if (cluster_send_command(c,slot,cmd,cmdlen) < 0 || c->err) {
        php_error_docref(NULL, E_NOTICE, "Redis unable to update session expiry");
        efree(cmd);
        return FAILURE;
    }

    /* Clean up our command */
    efree(cmd);

    /* Attempt to read reply */
    reply = cluster_read_resp(c, 0);
    if (!reply || c->err) {
        if (reply) cluster_free_reply(reply, 1);
        return FAILURE;
    }

    /* Clean up */
    cluster_free_reply(reply, 1);

    return SUCCESS;
}
/* }}} */

/* {{{ PS_READ_FUNC
 */
PS_READ_FUNC(rediscluster) {
    redis_cluster_session *rcs = PS_GET_MOD_DATA();
    redisCluster *c = rcs ? rcs->cluster : NULL;
    clusterReply *reply;
    char *cmd, *skey, *compressed_buf;
    int cmdlen, skeylen, free_flag, compressed_free;
    size_t compressed_len;
    short slot;
    zend_string *raw_data = NULL;

    if (!c) return FAILURE;

    /* Set up our command and slot information */
    skey = cluster_session_key(c, ZSTR_VAL(key), ZSTR_LEN(key), &skeylen, &slot);

    /* Locking enabled: atomic SET-NX + GET/GETEX via Lua on the slot owner
     * (lock_key co-located with session_key via hash tag). On lock contention
     * retry with plain SET NX and re-fetch under the lock on success.
     * Prefixes that can't produce a co-located lock key fail with a diagnostic. */
    if (INI_INT("redis.session.locking_enabled")) {
        zend_long ttl = INI_INT("redis.session.early_refresh")
                          ? session_gc_maxlifetime() : 0;
        int rv;

        /* Store the prefixed session key (as zend_string) in lock_status */
        if (rcs->lock_status.session_key) {
            zend_string_release(rcs->lock_status.session_key);
        }
        rcs->lock_status.session_key = zend_string_init(skey, skeylen, 0);
        efree(skey);

        /* Co-located lock key required by the atomic Lua; malformed brace
         * usage in the prefix is a hard failure. */
        if (generate_cluster_lock_key(&rcs->lock_status) != SUCCESS) {
            php_error_docref(NULL, E_WARNING,
                "Cluster session prefix must contain no braces or a non-empty {hash-tag}");
            return FAILURE;
        }

        rv = cluster_lock_acquire_and_read(c, &rcs->lock_status,
                                           rcs->lock_status.session_key,
                                           ttl, &raw_data);
        if (rv != SUCCESS) {
            return FAILURE;
        }

        if (!rcs->lock_status.is_locked) {
            /* Lua didn't get the lock — the read is potentially stale and
             * MUST NOT be reused on retry-success (lost-update race). */
            int retry_rv = cluster_lock_acquire(c, &rcs->lock_status);

            if (retry_rv == SUCCESS) {
                if (raw_data) {
                    zend_string_release(raw_data);
                    raw_data = NULL;
                }
                if (cluster_read_session_data(c, rcs->lock_status.session_key,
                                              ttl, &raw_data) != SUCCESS) {
                    return FAILURE;
                }
            } else if (INI_INT("redis.session.lock_failure_readonly")) {
                php_error_docref(NULL, E_WARNING,
                    "Failed to acquire session lock, session will be read only");
            } else {
                php_error_docref(NULL, E_WARNING, "Failed to acquire session lock");
                if (raw_data) zend_string_release(raw_data);
                return FAILURE;
            }
        }

        /* Decompress and hand off */
        if (raw_data == NULL) {
            *val = ZSTR_EMPTY_ALLOC();
        } else if (ZSTR_LEN(raw_data) == 0) {
            *val = raw_data;            /* hand ownership to caller */
        } else {
            compressed_free = session_uncompress_data(c->flags,
                ZSTR_VAL(raw_data), ZSTR_LEN(raw_data),
                &compressed_buf, &compressed_len);
            *val = zend_string_init(compressed_buf, compressed_len, 0);
            if (compressed_free) {
                efree(compressed_buf);
            }
            zend_string_release(raw_data);
        }
        return SUCCESS;
    }

    /* Locking disabled: plain GET (or GETEX with early_refresh) — unchanged. */
    /* Update the session ttl if early refresh is enabled */
    if (INI_INT("redis.session.early_refresh")) {
        cmdlen = redis_spprintf(NULL, NULL, &cmd, "GETEX", "ssd", skey,
                                skeylen, "EX", 2, session_gc_maxlifetime());
        c->readonly = 0;
    } else {
        cmdlen = redis_spprintf(NULL, NULL, &cmd, "GET", "s", skey, skeylen);
        c->readonly = 1;
    }

    efree(skey);

    /* Attempt to kick off our command */
    if (cluster_send_command(c,slot,cmd,cmdlen) < 0 || c->err) {
        efree(cmd);
        return FAILURE;
    }

    /* Clean up command */
    efree(cmd);

    /* Attempt to read reply */
    reply = cluster_read_resp(c, 0);
    if (!reply || c->err) {
        if (reply) cluster_free_reply(reply, 1);
        return FAILURE;
    }

    /* Push reply value to caller */
    if (reply->str == NULL) {
        *val = ZSTR_EMPTY_ALLOC();
    } else {
        compressed_free = session_uncompress_data(c->flags, reply->str, reply->len, &compressed_buf, &compressed_len);
        *val = zend_string_init(compressed_buf, compressed_len, 0);
        if (compressed_free) {
            efree(compressed_buf); // Free the buffer allocated by redis_uncompress
        }
    }

    free_flag = 1;

    /* Clean up */
    cluster_free_reply(reply, free_flag);

    /* Success! */
    return SUCCESS;
}

/* {{{ PS_WRITE_FUNC
 */
PS_WRITE_FUNC(rediscluster) {
    redis_cluster_session *rcs = PS_GET_MOD_DATA();
    redisCluster *c = rcs ? rcs->cluster : NULL;
    clusterReply *reply;
    char *cmd, *skey, *sval;
    int cmdlen, skeylen, compressed_free;
    size_t svallen;
    short slot;

    if (!c) return FAILURE;

    /* If locking is enabled but our lock is no longer held (expired or
     * stolen), refuse to write — same semantics as the standalone handler. */
    if (!cluster_write_allowed(c, &rcs->lock_status)) {
        return FAILURE;
    }

    compressed_free = session_compress_data(c->flags, ZSTR_VAL(val), ZSTR_LEN(val),
                                            &sval, &svallen);

    /* Set up command and slot info */
    skey = cluster_session_key(c, ZSTR_VAL(key), ZSTR_LEN(key), &skeylen, &slot);
    cmdlen = redis_spprintf(NULL, NULL, &cmd, "SETEX", "sds", skey,
                            skeylen, session_gc_maxlifetime(),
                            sval, svallen);
    efree(skey);
    if (compressed_free) {
        efree(sval);
    }

    /* Attempt to send command */
    c->readonly = 0;
    if (cluster_send_command(c,slot,cmd,cmdlen) < 0 || c->err) {
        efree(cmd);
        return FAILURE;
    }

    /* Clean up our command */
    efree(cmd);

    /* Attempt to read reply */
    reply = cluster_read_resp(c, 0);
    if (!reply || c->err) {
        if (reply) cluster_free_reply(reply, 1);
        return FAILURE;
    }

    /* Clean up*/
    cluster_free_reply(reply, 1);

    return SUCCESS;
}

/* {{{ PS_DESTROY_FUNC(rediscluster)
 */
PS_DESTROY_FUNC(rediscluster) {
    redis_cluster_session *rcs = PS_GET_MOD_DATA();
    redisCluster *c = rcs ? rcs->cluster : NULL;
    clusterReply *reply;
    char *cmd, *skey;
    int cmdlen, skeylen;
    short slot;

    if (!c) return FAILURE;

    /* Set up command and slot info */
    skey = cluster_session_key(c, ZSTR_VAL(key), ZSTR_LEN(key), &skeylen, &slot);

    cmdlen = redis_spprintf(NULL, NULL, &cmd, "DEL", "s", skey, skeylen);
    efree(skey);

    /* Attempt to send command */
    if (cluster_send_command(c,slot,cmd,cmdlen) < 0 || c->err) {
        efree(cmd);
        return FAILURE;
    }

    /* Clean up our command */
    efree(cmd);

    /* Attempt to read reply */
    reply = cluster_read_resp(c, 0);
    if (!reply || c->err) {
        if (reply) cluster_free_reply(reply, 1);
        return FAILURE;
    }

    /* Clean up our reply */
    cluster_free_reply(reply, 1);

    /* Release the lock if we hold one */
    cluster_lock_release(c, &rcs->lock_status);

    return SUCCESS;
}

/* {{{ PS_CLOSE_FUNC
 */
PS_CLOSE_FUNC(rediscluster)
{
    redis_cluster_session *rcs = PS_GET_MOD_DATA();
    if (rcs) {
        if (rcs->cluster) {
            cluster_lock_release(rcs->cluster, &rcs->lock_status);
        }
        cluster_session_free(rcs);
        PS_SET_MOD_DATA(NULL);
    }
    return SUCCESS;
}

/* {{{ PS_GC_FUNC
 */
PS_GC_FUNC(rediscluster) {
    return SUCCESS;
}

#endif

/* vim: set tabstop=4 expandtab: */
