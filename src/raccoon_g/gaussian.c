/*

 The MIT License (MIT)

 Copyright (c) 2026 edtubbs
 Copyright (c) 2026 The Dogecoin Foundation

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

/*
 * Raccoon-G-44 rounded Gaussian sampler — skeleton. Implementation lands in
 * Session 5 and uses MPFR (vendored via depends/) as the C analogue of the
 * upstream mpmath reference.
 *
 * Including <gmp.h> / <mpfr.h> here is gated to ensure compilation of the
 * skeleton works against either depends-built or system-supplied GMP/MPFR;
 * but no MPFR API is invoked yet — only the headers are smoke-tested so a
 * misconfigured build environment fails at compile time, not at first call.
 */

#include "gaussian.h"

#include <gmp.h>
#include <mpfr.h>

dogecoin_bool gaussian_sampler_init(void)
{
    /* Smoke test that GMP / MPFR are linkable without invoking any sampler
     * logic; the actual sigma/precision constants are pinned in Session 5. */
    mpfr_t link_smoke_test;
    mpfr_init2(link_smoke_test, 53);
    mpfr_clear(link_smoke_test);
    return false; /* sampler is not yet implemented */
}

void gaussian_sampler_shutdown(void)
{
    mpfr_free_cache();
}

dogecoin_bool gaussian_sample(int64_t* out, size_t n, const uint8_t seed[32])
{
    (void)out; (void)n; (void)seed;
    return false;
}
