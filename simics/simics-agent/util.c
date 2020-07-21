/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.

   Copyright 2012-2016 Intel Corporation */

#include "agent.h"
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>

#define TICKET_HASHTAB_LEN 256

/* Ticket descriptor list element functions */

static inline struct ticket_desc *
ticket_elem_to_desc(struct dublist_elem *elem)
{
        return (struct ticket_desc *)elem;
}

static inline struct ticket_desc *
ticket_desc_first(struct dublist *list)
{
        return ticket_elem_to_desc(list->head);
}

static inline struct ticket_desc *
ticket_desc_next(struct ticket_desc *td)
{
        return ticket_elem_to_desc(td->elem.next);
}

/* Because a struct ticket_desc is larger than 64 bytes, the address of the
   ticket shifted left 6 times (divide by 64) must be unique, and can therefore
   be used as the ticket number (hash number).
   On a 64-bit system, it is assumed to still be unique despite the truncation
   to a 32-bit value. */
static inline uint32_t
ticketstore_hash(struct ticket_desc *this)
{
        return (uint32_t)((size_t)this >> 6);
}

CASSERT(ticket_step, sizeof(struct ticket_desc) >= 64);

/* Return the ticket list for this ticket number */
static inline struct dublist *
hashtab_list(struct ticket_hashtab *htab, uint32_t ticket)
{
        assert((uint8_t)ticket < htab->len);
        return &htab->vec[(uint8_t)ticket];
}

inline int
ticketstore_init(struct ticket_hashtab *htab)
{
        htab->used = 0;
        htab->len = TICKET_HASHTAB_LEN;
        htab->vec = calloc(sizeof(struct dublist), TICKET_HASHTAB_LEN);
        if (!htab->vec)
                return errno;
        return 0;
}

inline void
ticketstore_reset(struct ticket_hashtab *htab)
{
        int i;
        for (i = 0; i < htab->len; i++) {
                struct dublist *list = hashtab_list(htab, i);
                struct ticket_desc *td = ticket_desc_first(list);
                while (td) {
                        struct ticket_desc *next = ticket_desc_next(td);
                        ticketstore_delete(htab, td);
                        td = next;
                }
        }
}

inline void
ticketstore_free(struct ticket_hashtab *htab)
{
        ticketstore_reset(htab);
        htab->len = 0;
        free(htab->vec);
        htab->vec = NULL;
}

static inline void
ticketstore_insert(struct ticket_hashtab *htab, struct ticket_desc *this)
{
        struct dublist *list = hashtab_list(htab, this->id);
        dublist_append(list, &this->elem);
        htab->used++;
}

static inline void
ticketstore_remove(struct ticket_hashtab *htab, struct ticket_desc *this)
{
        struct dublist *list = hashtab_list(htab, this->id);
        dublist_remove(list, &this->elem);
        htab->used--;
}

struct ticket_desc *
ticketstore_create(struct ticket_hashtab *htab, const char *name)
{
        size_t len = strlen(name);
        /* sizeof(*this) has space for the string terminator */
        struct ticket_desc *td = calloc(1, len + sizeof(*td));
        if (!td)
                return NULL;
        strcpy(td->name, name);
        td->id = ticketstore_hash(td);
        ticketstore_insert(htab, td);
        DBG_PRINT("(%08x, '%s')", td->id, name);
        return td;
}

void
ticketstore_delete(struct ticket_hashtab *htab, struct ticket_desc *td)
{
        assert(ticketstore_find(htab, td->id) == td);
        ticketstore_remove(htab, td);
        DBG_PRINT("(%08x, '%s')", td->id, td->name);

        if (td->io) {
                if (td->req_code == 0x1800)
                        pclose(td->io);
                else
                        fclose(td->io);
        }
        /* td->fd is closed by the fclose above, see man fdopen */
        /* Any associated ticket_child is not closed, nor any WIN32 handles */
        if (td->data)
                free(td->data);
        free(td);
}

struct ticket_desc *
ticketstore_find(struct ticket_hashtab *htab, uint32_t ticket)
{
        struct dublist *list = hashtab_list(htab, ticket);
        struct ticket_desc *td = ticket_desc_first(list);
        while (td) {
                if (td->id == ticket)
                        break;
                td = ticket_desc_next(td);
        }
        return td;
}

size_t
dynstr_printf(char **str_p, size_t at, const char *format, ...)
{
        va_list ap;
        int rc;

        char *buf = *str_p;
        /* Calculate input length, including terminator */
        size_t len = at + 1;
        va_start(ap, format);
        rc = vsnprintf(buf, 0, format, ap);
        if (rc > 0) {
                len += (size_t)rc;
        }
        va_end(ap);
        /* Allocate buffer space for the new string */
        buf = (char *)realloc(buf, len);
        if (!buf)
                return at;
        /* Insert input in string */
        va_start(ap, format);
        rc = vsprintf(buf + at, format, ap);
        if (rc > 0) {
                at += (size_t)rc;
        }
        va_end(ap);

        *str_p = buf;
        return at;
}

size_t
buf_string_printf(struct matic_buffer *buf, const char *format, ...)
{
        size_t len = buf->head.size;
        size_t left = MAX_PAYLOAD_SIZE - len;
        va_list ap;
        int rc;

        assert(left <= MAX_PAYLOAD_SIZE);
        if (!left)
                return 0;

        va_start(ap, format);
        rc = vsnprintf(buf->data + len, left, format, ap);
        if (rc > 0) {
                len += rc;
                if (rc < left)
                        left -= (size_t)rc;
                else
                        left = 0;
        }
        va_end(ap);
        if (len >= MAX_PAYLOAD_SIZE)
                buf->head.size = MAX_PAYLOAD_SIZE;
        else
                buf->head.size = len + 1;
        return len;
}

size_t
buf_string_append(struct matic_buffer *buf, const char *str)
{
        size_t len = strlen(str) + 1;
        size_t pos = buf->head.size;

        if (pos + len > MATIC_PAGE_SIZE)
                return 0;

        memcpy(buf->data + pos, str, len);
        buf->head.size += len;
        return len - 1;
}

char *
buf_string_next(char *buf, size_t *offset, size_t align)
{
        size_t offs = *offset;
        char *str = buf + offs;
        offs += strlen(str) + 1;
        if (align) {
                size_t mod = offs % align;
                if (mod)
                        offs += align - mod;
        }
        *offset += offs;
        return str;
}

char **
buf_string_array(char *buf, size_t *offset, size_t cnt)
{
        char **arr = NULL;
        size_t n;

        arr = malloc((cnt + 1) * sizeof(*arr));
        if (!arr)
                return NULL;
        for (n = 0; n < cnt; n++) {
                arr[n] = buf_string_next(buf, offset, 0);
        }
        arr[n] = NULL;
        return arr;
}

int
buf_copy_data(struct matic_buffer *buf, char **data, size_t siz)
{
        size_t len = siz + buf->head.size;
        char *ptr = realloc(*data, len);
        if (!ptr)
                return ENOMEM;
        *data = ptr;
        memcpy(ptr + siz, buf->data, (size_t)buf->head.size);
        return 0;
}

static struct ticket_entry *
buf_next_ticket(struct matic_buffer *buf, size_t *left)
{
        size_t pos = buf->head.size;
        size_t mod = pos % 8;
        if (mod) {
                pos += 8 - mod;
                buf->head.size += pos;
        }
        if (pos + sizeof(struct ticket_entry) > MATIC_PAGE_SIZE)
                return NULL;
        if (left)
                *left = MATIC_PAGE_SIZE - pos
                        - offsetof(struct ticket_entry, name);
        return (struct ticket_entry *)(buf->data + pos);
}

int
buf_append_ticket(struct matic_buffer *buf, struct ticket_desc *td)
{
        size_t left = 0;
        size_t len = offsetof(struct ticket_entry, name) + strlen(td->name) + 1;
        struct ticket_entry *nty = buf_next_ticket(buf, &left);
        if (!nty || len >= left)
                return ENOSPC;

        nty->total = td->size;
        nty->ticket = td->id;
        nty->mode = td->access;
        strcpy(nty->name, td->name);
        buf->head.size += len;
        return 0;
}

const char const *
access_mode_string(mode_t mode)
{
        static char result[12];
        static const char *modestr = "-rwxrwxrwx";
        int i;
        for (i = 0; i < 9; i++) {
                unsigned b = (mode & (1 << i));
                char c = b ? modestr[9 - i] : '-';
                result[9 - i] = c;
        }
        switch (mode >> 12) {
        case 0xc: /* S_IFMT, socket */
                result[0] = 's';
                break;
        case 0xa: /* S_IFLNK, symbolic link */
                result[0] = 'l';
                break;
        case 0x6: /* S_IFBLK, block device */
                result[0] = 'b';
                break;
        case 0x4: /* S_IFDIR, directory */
                result[0] = 'd';
                break;
        case 0x2: /* S_IFCHR, character device */
                result[0] = 'c';
                break;
        case 0x1: /* S_IFIFO, FIFO */
                result[0] = 'p';
                break;
        case 0x8: /* S_IFREG, regular file */
        default:
                result[0] = '-';
                break;
        }
        if (mode & 0x800) /* S_ISUID, set UID bit */
                result[3] = 's';
        if (mode & 0x400) /* S_ISGID, set-group-ID bit */
                result[6] = 's';
        if (mode & 0x200) /* S_ISVTX, sticky bit */
                result[9] = 's';
        result[10] = 0;
        return result;
}
