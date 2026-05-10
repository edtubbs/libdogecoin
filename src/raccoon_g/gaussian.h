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

#ifndef LIBDOGECOIN_RACCOON_G_GAUSSIAN_H
#define LIBDOGECOIN_RACCOON_G_GAUSSIAN_H

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/*
 * Rounded Gaussian sampler for Raccoon-G-44.
 *
 * The upstream Python reference (p-11/lattice-hd-wallets) uses mpmath at
 * sigma = 2^7 / 2^40. The C analogue is MPFR with matching precision; this
 * is why GMP and MPFR are vendored in depends/. The sampler MUST produce
 * byte-identical samples to the reference for an identical seed; this is
 * the primary release-blocking gate.
 *
 * Implementation lands in Session 5, gated by a fixture of the first 2048
 * upstream samples (test/data/raccoong_gauss.json).
 */

dogecoin_bool gaussian_sampler_init(void);
void          gaussian_sampler_shutdown(void);

/*
 * Fill `out` with `n` samples of the Raccoon-G-44 rounded Gaussian, deriving
 * randomness from the supplied 32-byte seed via the same PRG construction the
 * upstream reference uses (Shake-256 or HMAC; pinned in README.md).
 */
dogecoin_bool gaussian_sample(int64_t* out, size_t n, const uint8_t seed[32]);

LIBDOGECOIN_END_DECL

#endif /* LIBDOGECOIN_RACCOON_G_GAUSSIAN_H */
