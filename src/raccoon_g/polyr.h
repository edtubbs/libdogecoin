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

#ifndef LIBDOGECOIN_RACCOON_G_POLYR_H
#define LIBDOGECOIN_RACCOON_G_POLYR_H

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/*
 * Z_q polynomial arithmetic for Raccoon-G-44.
 *
 * The modulus q, ring degree n, and on-the-wire encoding are pinned to the
 * upstream p-11/lattice-hd-wallets reference; see src/raccoon_g/README.md.
 * The functions below are stubs in this skeleton; they will be filled in
 * Session 3 alongside generated test vectors that are checked into
 * test/data/raccoong_polyr.json.
 *
 * No coefficient values, modulus, or degree are encoded in this header; doing
 * so before the upstream-vs-in-tree byte-equivalence harness lands would risk
 * baking in a wrong value.
 */

typedef struct polyr polyr; /* opaque; defined in polyr.c once parameters are set */

dogecoin_bool polyr_alloc(polyr** out);
void          polyr_free(polyr* p);

dogecoin_bool polyr_add(polyr* r, const polyr* a, const polyr* b);
dogecoin_bool polyr_sub(polyr* r, const polyr* a, const polyr* b);
dogecoin_bool polyr_mul(polyr* r, const polyr* a, const polyr* b);

dogecoin_bool polyr_serialize(const polyr* a, uint8_t* out, size_t out_len);
dogecoin_bool polyr_deserialize(polyr* r, const uint8_t* in, size_t in_len);

LIBDOGECOIN_END_DECL

#endif /* LIBDOGECOIN_RACCOON_G_POLYR_H */
