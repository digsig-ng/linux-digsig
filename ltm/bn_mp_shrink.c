/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library was designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://math.libtomcrypt.org
 *
 * Modifications :
 *   - 29 Sept 2003, A. Apvrille, <axelle.apvrille@ericsson.ca>
 *     porting to kernel 2.5.66: realloc --> kmalloc, kfree
 */
#include <tommath.h>
#include "../dsi.h"		/* Add AxL */

/* shrink a bignum */
int mp_shrink(mp_int * a)
{
	if (a->alloc != a->used) {
		mp_digit *tmp;

		tmp =
		    (mp_digit *) kmalloc(sizeof(mp_digit) * a->used,
					 DIGSIG_SAFE_ALLOC);
		if (tmp == NULL)
			return MP_MEM;

		memcpy(tmp, a->dp, a->used * sizeof(mp_digit));
		kfree(a->dp);
		a->dp = tmp;

		/* AxL: realloc integrated in kernel.
		   if ((a->dp = OPT_CAST realloc (a->dp, sizeof (mp_digit) * a->used)) == NULL) {
		   return MP_MEM;
		   }
		 */
		a->alloc = a->used;
	}
	return MP_OKAY;
}
