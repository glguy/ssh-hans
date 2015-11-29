#include <stdlib.h>
#include <zlib.h>

static
voidpf my_alloc (voidpf opaque, uInt items, uInt size)
{
        return calloc(items, size);
}

static
void my_free (voidpf opaque, voidpf address)
{
        free(address);
}

static inline
void initialize (z_streamp s)
{
        s->opaque   = NULL;
        s->next_in  = NULL;
        s->avail_in = 0;
        s->zfree    = my_free;
        s->zalloc   = my_alloc;
}

extern
int ssh_hans_zlib_inflateInit (z_streamp s)
{
        initialize(s);
        return inflateInit(s);
}

extern
int ssh_hans_zlib_deflateInit (z_streamp s)
{
        initialize(s);
        return deflateInit(s, Z_DEFAULT_COMPRESSION);
}
