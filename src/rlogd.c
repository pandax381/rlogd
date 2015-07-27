/*
 * Copyright (c) 2014,2015 KLab Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <regex.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <ev.h>
#include <pcre.h>
#include "common.h"
#include "rlogd.h"

#define DEFAULT_CONFIG_FILE (SYSCONFDIR "/rlogd.conf")
#define DEFAULT_PID_FILE (LOCALSTATEDIR "/run/rlogd.pid")

int __dryrun;

typedef struct {
    char *config;
    int debug;
    int dryrun;
    int foreground;
    char *pid;
    char *_stdout;
    char *_stderr;
} option_t;

struct signal_def {
    int signum;
    struct ev_signal w;
};

static struct signal_def signals[] = {
    {.signum = SIGINT },
    {.signum = SIGTERM},
    {.signum = 0}
};

struct source {
    struct module ctx;
    char *label;
    char *prefix;
    char *suffix;
    pthread_t thread;
    TAILQ_ENTRY(source) lp;
};

struct match {
    struct module ctx;
    pcre *reg;
    pthread_t thread;
    pthread_mutex_t mutex;
    TAILQ_ENTRY(match) lp;
};

struct label {
    pcre *reg;
    TAILQ_HEAD(/**/, match) matches;
    TAILQ_ENTRY(label) lp;
};

#define MODULE_TYPE_INPUT  (1)
#define MODULE_TYPE_OUTPUT (2)

#define MODULE_DEFINE(XX)                                \
    XX(MODULE_TYPE_INPUT,  "forward", in_forward_setup)  \
    XX(MODULE_TYPE_OUTPUT, "forward", out_forward_setup) \
    XX(MODULE_TYPE_OUTPUT, "file",    out_file_setup)    \

#define MODULE_DECLARE(type, name, func) extern int func (struct module *module, const struct dir *dir);
MODULE_DEFINE(MODULE_DECLARE)
#undef  MODULE_DECLARE 

struct module_def {
    int type;
    char *name;
    int (*setup)(struct module *, const struct dir *);
};

static struct module_def modules[] = {
#define MODULE_DECLARE(type, name, func) {type, name, func},
    MODULE_DEFINE(MODULE_DECLARE)
#undef  MODULE_DECLARE
    {0, NULL, NULL}
};

#undef MODULE_DEFINE

TAILQ_HEAD(/**/, source) sources = TAILQ_HEAD_INITIALIZER(sources);
TAILQ_HEAD(/**/, match)  matches = TAILQ_HEAD_INITIALIZER(matches);
TAILQ_HEAD(/**/, label)  labels  = TAILQ_HEAD_INITIALIZER(labels);

void
push_entries (struct module *module, const char *tag, size_t tag_len, struct entry *entries, size_t len) {
    struct source *source;
    char buf[1024];
    size_t n = 0;
    struct label *label;
    struct match *match;

    source = container_of(module, struct source, ctx);
    if (!source) {
        return;
    }
    if (source->prefix) {
        strcpy(buf, source->prefix);
        n += strlen(source->prefix);
        buf[n++] = '.';
    }
    strncpy(buf + n, tag, tag_len);
    n += tag_len;
    if (source->suffix) {
        buf[n++] = '.';
        strcpy(buf + n, source->suffix);
    } else {
        buf[n] = '\0';
    }
    if (source->label) {
        TAILQ_FOREACH(label, &labels, lp) {
            if (pcre_exec(label->reg, NULL, source->label, strlen(source->label), 0, 0, 0, 0) >= 0) {
                TAILQ_FOREACH(match, &label->matches, lp) {
                    if (pcre_exec(match->reg, NULL, buf, strlen(buf), 0, 0, 0, 0) >= 0) {
                        pthread_mutex_lock(&match->mutex);
                        match->ctx.emit(match->ctx.arg, buf, n, entries, len);
                        pthread_mutex_unlock(&match->mutex);
                        return;
                    }
                }
                warning_print("'%.*s' is not match", (int)tag_len, tag);
                return;
            }
        }
        warning_print("label '%s' is not found", source->label);
        return;
    }
    TAILQ_FOREACH(match, &matches, lp) {
        if (pcre_exec(match->reg, NULL, buf, strlen(buf), 0, 0, 0, 0) >= 0) {
            pthread_mutex_lock(&match->mutex);
            match->ctx.emit(match->ctx.arg, buf, n, entries, len);
            pthread_mutex_unlock(&match->mutex);
            return;
        }
    }
    warning_print("'%.*s' is not match", (int)tag_len, tag);
}

void
cancel_modules (void) {
    struct source *source;
    struct match *match;
    struct label *label;

    while ((source = TAILQ_FIRST(&sources)) != NULL) {
        source->ctx.cancel(source->ctx.arg);
        pthread_join(source->thread, NULL);
        TAILQ_REMOVE(&sources, source, lp);
        free(source);
    }
    while ((match = TAILQ_FIRST(&matches)) != NULL) {
        match->ctx.cancel(match->ctx.arg);
        pthread_join(match->thread, NULL);
        TAILQ_REMOVE(&matches, match, lp);
        pcre_free(match->reg);
        free(match);
    }
    while ((label = TAILQ_FIRST(&labels)) != NULL) {
        while ((match = TAILQ_FIRST(&label->matches)) != NULL) {
            match->ctx.cancel(match->ctx.arg);
            pthread_join(match->thread, NULL);
            TAILQ_REMOVE(&matches, match, lp);
            pcre_free(match->reg);
            free(match);
        }
        TAILQ_REMOVE(&labels, label, lp);
        pcre_free(label->reg);
        free(label);
    }
}

void
run_modules (void) {
    struct label *label;
    struct match *match;
    struct source *source;

    TAILQ_FOREACH(label, &labels, lp) {
        TAILQ_FOREACH(match, &label->matches, lp) {
            pthread_create(&match->thread, NULL, match->ctx.run, match->ctx.arg);
        }
    }
    TAILQ_FOREACH(match, &matches, lp) {
        pthread_create(&match->thread, NULL, match->ctx.run, match->ctx.arg);
    }
    TAILQ_FOREACH(source, &sources, lp) {
        pthread_create(&source->thread, NULL, source->ctx.run, source->ctx.arg);
    }
}

static void
revoke_modules (void) {
    struct source *source;
    struct match *match;
    struct label *label;

    while ((source = TAILQ_FIRST(&sources)) != NULL) {
        source->ctx.revoke(source->ctx.arg);
        TAILQ_REMOVE(&sources, source, lp);
        free(source);
    }
    while ((match = TAILQ_FIRST(&matches)) != NULL) {
        match->ctx.revoke(match->ctx.arg);
        TAILQ_REMOVE(&matches, match, lp);
        pcre_free(match->reg);
        free(match);
    }
    while ((label = TAILQ_FIRST(&labels)) != NULL) {
        while ((match = TAILQ_FIRST(&label->matches)) != NULL) {
            match->ctx.revoke(match->ctx.arg);
            TAILQ_REMOVE(&matches, match, lp);
            pcre_free(match->reg);
            free(match);
        }
        TAILQ_REMOVE(&labels, label, lp);
        pcre_free(label->reg);
        free(label);
    }
}

static struct module_def *
module_lookup (int type, const char *name) {
    struct module_def *m;

    for (m = modules; m->type; m++) {
        if (m->type == type && strcmp(m->name, name) == 0) {
            return m;
        }
    }
    return NULL;
}

static struct source *
setup_source (struct dir *dir) {
    char *type;
    struct module_def *module;
    struct source *source;

    type = config_dir_get_param_value(dir, "type");
    if (!type) {
        error_print("module type is required, line %zu", dir->line);
        return NULL;
    }
    module = module_lookup(MODULE_TYPE_INPUT, type);
    if (!module) {
        error_print("module not found [in_%s]", type);
        return NULL;
    }
    source = (struct source *)malloc(sizeof(struct source));
    if (!source) {
        error_print("malloc error");
        return NULL;
    }
    if (module->setup(&source->ctx, dir) == -1) {
        error_print("module setup error [in_%s]", type);
        free(source);
        return NULL;
    }
    source->label  = config_dir_get_param_value(dir, "label");
    source->prefix = config_dir_get_param_value(dir, "add_prefix");
    source->suffix = config_dir_get_param_value(dir, "add_suffix");
    return source;
}

static char *
convert_regex_pattern (char *dst, size_t size, const char *src, size_t len) {
    size_t n = 0, off = 0;
    int esc = 0, dot = 0;

    dst[off++] = '\\';
    dst[off++] = 'A';
    while (n < len) {
        if (esc) {
            switch (src[n]) {
            case '[':
            case ']':
            case '{':
            case '}':
            case '(':
            case ')':
            case '|':
            case '-':
            case '*':
            case '.':
            case '\\':
            case '?':
            case '+':
            case '^':
            case '$':
            case '#':
            case ' ':
            case '\t':
            case '\f':
            case '\v':
            case '\n':
            case '\r':
                dst[off++] = '\\';
            default:
                dst[off++] = src[n];
            }
            esc = 0;
            n++;
            continue;
        }
        if (src[n] == '*' && src[n + 1] == '*') {
            if (dot) {
                dst[off++] = '(';
                dst[off++] = '?';
                dst[off++] = '!';
                dst[off++] = '[';
                dst[off++] = '^';
                dst[off++] = '\\';
                dst[off++] = '.';
                dst[off++] = ']';
                dst[off++] = ')';
                dot = 0;
            }
            if (src[n + 2] == '.') {
                dst[off++] = '(';
                dst[off++] = '?';
                dst[off++] = ':';
                dst[off++] = '.';
                dst[off++] = '*';
                dst[off++] = '\\';
                dst[off++] = '.';
                dst[off++] = '|';
                dst[off++] = '\\';
                dst[off++] = 'A';
                dst[off++] = ')';
                n += 3;
            } else {
                dst[off++] = '.';
                dst[off++] = '*';
                n += 2;
            }
            continue;
        }
        if (dot) {
            dst[off++] = '\\';
            dst[off++] = '.';
            dot = 0;
        }
        if (src[n] == '\\') {
            esc = 1;
        } else if (src[n] == '.') {
            dot = 1;
        } else if (src[n] == '*') {
            dst[off++] = '[';
            dst[off++] = '^';
            dst[off++] = '\\';
            dst[off++] = '.';
            dst[off++] = ']';
            dst[off++] = '*';
        } else if (src[n] == '{') {
            dst[off++] = '(';
        } else if (src[n] == '}') {
            dst[off++] = ')';
        } else if (src[n] == ',') {
            dst[off++] = '|';
        } else if (!(isalnum(src[n]) || src[n] == '_')) {
            dst[off++] = '\\';
        } else {
            dst[off++] = src[n];
        }
        n++;
    }
    dst[off++] = '\\';
    dst[off++] = 'Z';
    dst[off] = '\0';
    return dst;
}

static struct match *
setup_match (struct dir *dir) {
    char *type, pattern[1024];
    struct module_def *module;
    struct match *match;
    const char *errmsg;
    int erroff;

    if (!dir->arg) {
        error_print("match pattern is required, line %zu", dir->line);
        return NULL;
    }
    type = config_dir_get_param_value(dir, "type");
    if (!type) {
        error_print("module type is required, line %zu", dir->line);
        return NULL;
    }
    module = module_lookup(MODULE_TYPE_OUTPUT, type);
    if (!module) {
        error_print("module not found [out_%s]", type);
        return NULL;
    }
    match = (struct match *)malloc(sizeof(struct match));
    if (!match) {
        error_print("malloc error");
        return NULL;
    }
    memset(&match->reg, 0, sizeof(match->reg));
    convert_regex_pattern(pattern, sizeof(pattern), dir->arg, strlen(dir->arg));
    match->reg = pcre_compile(pattern, 0, &errmsg, &erroff, NULL);
    if (!match->reg) {
        error_print("pcre_compile: %s, line %zu", errmsg, dir->line);
        free(match);
        return NULL;
    }
    if (module->setup(&match->ctx, dir) == -1) {
        error_print("module setup error [out_%s]", type);
        pcre_free(match->reg);
        free(match);
        return NULL;
    }
    pthread_mutex_init(&match->mutex, NULL);
    return match;
}

static struct label *
setup_label (struct dir *dir) {
    struct label *label;
    char pattern[1024];
    const char *errmsg;
    int erroff;
    struct dir *child;
    struct match *match;

    if (!dir->arg) {
        error_print("label pattern is required, line %zu", dir->line);
        return NULL;
    }
    label = (struct label *)malloc(sizeof(struct label));
    if (!label) {
        error_print("malloc error");
        return NULL;
    }
    TAILQ_INIT(&label->matches);
    memset(&label->reg, 0, sizeof(label->reg));
    convert_regex_pattern(pattern, sizeof(pattern), dir->arg, strlen(dir->arg));
    label->reg = pcre_compile(pattern, 0, &errmsg, &erroff, NULL);
    if (!label->reg) {
        error_print("pcre_compile: %s, line %zu", errmsg, dir->line);
        free(label);
        return NULL;
    }
    TAILQ_FOREACH(child, &dir->dirs, lp) {
        if (strcmp(child->name, "match") == 0) {
            if ((match = setup_match(child)) == NULL) {
                while ((match = TAILQ_FIRST(&label->matches)) != NULL) {
                    match->ctx.revoke(match->ctx.arg);
                    TAILQ_REMOVE(&label->matches, match, lp);
                    pcre_free(match->reg);
                    free(match);
                }
                pcre_free(label->reg);
                free(label);
                return NULL;
            }
            TAILQ_INSERT_TAIL(&label->matches, match, lp);
        }
    }
    if (TAILQ_EMPTY(&label->matches)) {
        warning_print("match directive does not exist in this label, line %zu", dir->line);
    }
    return label;
}
static int
setup_modules (struct config *config) {
    struct dir *dir;
    struct source *source;
    struct match *match;
    struct label *label;

    TAILQ_FOREACH(dir, &config->dirs, lp) {
        if (strcmp(dir->name, "source") == 0) {
            if ((source = setup_source(dir)) == NULL) {
                revoke_modules();
                return -1;
            }
            TAILQ_INSERT_TAIL(&sources, source, lp);
        }
    }
    if (TAILQ_EMPTY(&sources)) {
        warning_print("source directive does not exist");
    }
    TAILQ_FOREACH(dir, &config->dirs, lp) {
        if (strcmp(dir->name, "match") == 0) {
            if ((match = setup_match(dir)) == NULL) {
                revoke_modules();
                return -1;
            }
            TAILQ_INSERT_TAIL(&matches, match, lp);
        }
    }
    TAILQ_FOREACH(dir, &config->dirs, lp) {
        if (strcmp(dir->name, "label") == 0) {
            if ((label = setup_label(dir)) == NULL) {
                revoke_modules();
                return -1;
            }
            TAILQ_INSERT_TAIL(&labels, label, lp);
        }
    }
    return 0;
}

static void
signal_cb (struct ev_loop *loop, struct ev_signal *w, int revents) {
    (void)revents;
    warning_print("Receive Signal: signum=%d", w->signum);
    ev_break(loop, EVBREAK_ALL);
}

static int
init (option_t *option) {
    FILE *fp = NULL;
    int _stdout = -1, _stderr = -1;

    umask(0);
    sig_ignore(SIGPIPE);
    if (option->dryrun) {
        return 0;
    }
    if (option->_stdout) {
        if ((_stdout = open(option->_stdout, O_WRONLY | O_CREAT | O_APPEND, 00644)) == -1) {
            error_print("%s [%s]", strerror(errno), option->_stdout);
            goto ERROR;
        }
    }
    if (option->_stderr) {
        if ((_stderr = open(option->_stderr, O_WRONLY | O_CREAT | O_APPEND, 00644)) == -1) {
            error_print("%s [%s]", strerror(errno), option->_stderr);
            goto ERROR;
        }
    }
    if ((fp = fopen(option->pid, "w")) == NULL) {
        error_print("%s [%s]", strerror(errno), option->pid);
        goto ERROR;
    }
    if (!option->foreground) {
        if (daemonize(NULL, 0) == -1) {
            error_print("daemonize failure");
            goto ERROR;
        }
    }
    if (_stdout != -1) {
        dup2(_stdout, STDOUT_FILENO);
        close(_stdout);
    }
    if (_stderr != -1) {
        dup2(_stderr, STDERR_FILENO);
        close(_stderr);
    }
    fprintf(fp, "%d\n", getpid());
    fclose(fp);
    return 0;

ERROR:
    if (_stderr != -1) {
        close(_stderr);
    }
    if (_stdout != -1) {
        close(_stdout);
    }
    if (fp) {
        fclose(fp);
        unlink(option->pid);
    }
    return -1;
}

static void
config_dir_debug (struct dir *dir, int depth) {
    struct param *param;
    struct dir *child;

    if (dir->arg) {
        fprintf(stderr, "> %*s<%s %s>\n", INDENT(depth), "", dir->name, dir->arg);
    } else {
        fprintf(stderr, "> %*s<%s>\n", INDENT(depth), "", dir->name);
    }
    TAILQ_FOREACH(param, &dir->params, lp) {
        fprintf(stderr, "> %*s%s %s\n", INDENT(depth + 1), "", param->key, param->value);
    }
    TAILQ_FOREACH(child, &dir->dirs, lp) {
        config_dir_debug(child, depth + 1);
    }
    fprintf(stderr, "> %*s</%s>\n", INDENT(depth), "", dir->name);
}

void
config_debug (struct config *config) {
    struct dir *dir;

    fprintf(stderr, "config_debug()\n");
    TAILQ_FOREACH(dir, &config->dirs, lp) {
        config_dir_debug(dir, 0);
    }
}

char *
config_dir_get_param_value (struct dir *dir, const char *key) {
    struct param *param;

    TAILQ_FOREACH(param, &dir->params, lp) {
        if (strcmp(param->key, key) == 0) {
            return param->value;
        }
    }
    return NULL;
}

static void
config_param_free (struct param *param) {
    free(param->key);
    free(param->value);
    free(param);
}

static void
config_dir_free (struct dir *dir) {
    struct dir *child;
    struct param *param;

    while ((param = TAILQ_FIRST(&dir->params)) != NULL) {
        TAILQ_REMOVE(&dir->params, param, lp);
        config_param_free(param);
    }
    while ((child = TAILQ_FIRST(&dir->dirs)) != NULL) {
        TAILQ_REMOVE(&dir->dirs, child, lp);
        config_dir_free(child);
    }
    free(dir->name);
    free(dir->arg);
    free(dir);
}

static void
config_free (struct config *config) {
    struct dir *dir;

    while ((dir = TAILQ_FIRST(&config->dirs)) != NULL) {
        TAILQ_REMOVE(&config->dirs, dir, lp);
        config_dir_free(dir);
    }
}

static int
config_parse (struct config *dst, const char *path) {
    FILE *fp;
    char buf[1024], *p, *name, *arg;
    size_t l = 0, n;
    struct dir *parent, *dir = NULL;
    struct param *param = NULL;

    if ((fp = fopen(path, "r")) == NULL) {
        error_print("%s, file=%s", strerror(errno), PRINTSTR(path));
        return -1;
    }
    TAILQ_INIT(&dst->dirs);
    while (fgets(buf, sizeof(buf), fp) && ++l) {
        strtrim(buf);
        if (!buf[0] || buf[0] == '#') {
            continue;
        }
        n = strlen(buf);
        if (buf[0] == '<' && buf[n - 1] == '>') {
            if (buf[1] == '/') {
                name = buf + 2;
                n -= 3; /* '<' & '/' & '>'  */
                if (!dir || !n || strncmp(name, dir->name, n) != 0) {
                    error_print("invalid string, line %zu", l);
                    config_free(dst);
                    fclose(fp);
                    return -1;
                }
                dir = dir->parent;
                continue;
            }
            parent = dir;
            dir = (struct dir *)malloc(sizeof(struct dir));
            if (!dir) {
                error_print("malloc error");
                config_free(dst);
                fclose(fp);
                return -1;
            }
            dir->parent = parent;
            name = buf + 1;
            n -= 2; /* '<' & '>'  */
            p = strpbrk(name, " \t");
            dir->name = strtrim(strndup(name, p ? p - name : n));
            if (!dir->name || !dir->name[0]) {
                error_print("invalid string, line %zu", l);
                free(dir->name);
                free(dir);
                config_free(dst);
                fclose(fp);
                return -1;
            }
            if (p) {
                arg = p + 1;
                dir->arg = strtrim(strndup(arg, n - (arg - name)));
            } else {
                dir->arg = NULL;
            }
            dir->line = l;
            TAILQ_INIT(&dir->params);
            TAILQ_INIT(&dir->dirs);
            if (parent) {
                TAILQ_INSERT_TAIL(&parent->dirs, dir, lp);
            } else {
                TAILQ_INSERT_TAIL(&dst->dirs, dir, lp);
            }
            continue;
        }
        if (dir) {
            if ((p = strpbrk(buf, " \t")) == NULL) {
                error_print("invalid string, line %zu", l);
                config_free(dst);
                fclose(fp);
                return -1;
            }
            param = (struct param *)malloc(sizeof(struct param));
            if (!param) {
                error_print("malloc error");
                config_free(dst);
                fclose(fp);
                return -1;
            }
            param->key = strtrim(strndup(buf, p - buf));
            param->value = strtrim(strndup(p + 1, n - ((p + 1) - buf)));
            if (!param->key || !param->value) {
                error_print("invalid string, line %zu", l);
                free(param->key);
                free(param->value);
                free(param);
                config_free(dst);
                fclose(fp);
                return -1;
            }
            param->line = l;
            TAILQ_INSERT_TAIL(&dir->params, param, lp);
        } else {
            warning_print("unexpected string, line %zu", l);
        }
    }
    fclose(fp);
    return 0;
}

static void
usage (void) {
    printf("usage: %s [options]\n", PACKAGE_NAME);
    printf("  options:\n");
    printf("    -c, --conf=PATH  # configuration file (default: %s)\n", DEFAULT_CONFIG_FILE);
    printf("    -d, --debug      # enable debug mode\n");
    printf("    -F, --foreground # foreground (not a daemon)\n");
    printf("    -p, --pid=PATH   # PID file (default: %s)\n", DEFAULT_PID_FILE);
    printf("    -t, --test       # run syntax check for config file\n");
    printf("    -h, --help       # print this message\n");
    printf("    -v, --version    # show version\n");
}

static void
version (void) {
    printf("%s\n", PACKAGE_STRING);
}

static int
option_parse (option_t *dst, int argc, char *argv[]) {
    int o;
    const struct option long_options[] = {
        {"conf",       1, NULL, 'c'},
        {"debug",      0, NULL, 'd'},
        {"foreground", 0, NULL, 'F'},
        {"pid",        1, NULL, 'p'},
        {"test",       0, NULL, 't'},
        {"help",       0, NULL, 'h'},
        {"version",    0, NULL, 'v'},
        { NULL,        0, NULL,  0 }
    };

    dst->config = DEFAULT_CONFIG_FILE;
    dst->debug = 0;
    dst->dryrun = 0;
    dst->foreground = 0;
    dst->pid = DEFAULT_PID_FILE;
    dst->_stdout = NULL;
    dst->_stderr = NULL;
    while ((o = getopt_long_only(argc, argv, "c:dFp:thv", long_options, NULL)) != -1) {
        switch (o) {
        case 'c':
            dst->config = optarg;
            break;
        case 'd':
            dst->debug = 1;
            break;
        case 'F':
            dst->foreground = 1;
            break;
        case 'p':
            dst->pid = optarg;
            break;
        case 't':
            dst->dryrun = 1;
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case 'v':
            version();
            exit(EXIT_SUCCESS);
        default :
            usage();
            return -1;
        }
    }
    if (optind != argc) {
        usage();
        return -1;
    }
    __debug  = dst->debug;
    __dryrun = dst->dryrun;
    return 0;
}

int
main (int argc, char *argv[]) {
    option_t option;
    struct config config;
    struct ev_loop *loop;
    struct signal_def *s;

    if (option_parse(&option, argc, argv) == -1) {
        return -1;
    }
    if (config_parse(&config, option.config) == -1) {
        return -1;
    }
    if (init(&option) == -1) {
        config_free(&config);
        return -1;
    }
    if ((loop = ev_loop_new(0)) == NULL) {
        config_free(&config);
        if (!option.dryrun) {
            unlink(option.pid);
        }
        return -1;
    }
    for (s = signals; s->signum; s++) {
        ev_signal_init(&s->w, signal_cb, s->signum);
        ev_signal_start(loop, &s->w);
    }
    if (setup_modules(&config) == -1) {
        config_free(&config);
        ev_loop_destroy(loop);
        if (!option.dryrun) {
            unlink(option.pid);
        }
        return -1;
    }
    if (option.dryrun) {
        fprintf(stderr, "Syntax OK\n");
        revoke_modules();
        config_free(&config);
        ev_loop_destroy(loop);
        return 0;
    }
    run_modules();
    ev_run(loop, 0);
    ev_loop_destroy(loop);
    cancel_modules();
    config_free(&config);
    unlink(option.pid);
    return 0;
}
