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
 * Raccoon-G-44 Z_q polynomial arithmetic — skeleton.
 *
 * Implementation is staged in Session 3. All routines currently return false
 * so any caller that reaches this code path (which it should not, until the
 * top-level raccoong_is_ready() flips to true) fails closed.
 *
 * See src/raccoon_g/README.md for the upstream reference commit pin.
 */

#include "polyr.h"

struct polyr {
    /* Placeholder. The coefficient layout (count, type, NTT-domain flag,
     * ownership) is pinned in Session 3 against the upstream reference and
     * replaces this field. Until then the struct is opaque and unallocatable
     * (polyr_alloc returns false), so no caller can depend on a layout that
     * does not yet exist. */
    int placeholder;
};

dogecoin_bool polyr_alloc(polyr** out)        { (void)out; return false; }
void          polyr_free(polyr* p)            { (void)p; }
dogecoin_bool polyr_add(polyr* r, const polyr* a, const polyr* b)
                                              { (void)r; (void)a; (void)b; return false; }
dogecoin_bool polyr_sub(polyr* r, const polyr* a, const polyr* b)
                                              { (void)r; (void)a; (void)b; return false; }
dogecoin_bool polyr_mul(polyr* r, const polyr* a, const polyr* b)
                                              { (void)r; (void)a; (void)b; return false; }
dogecoin_bool polyr_serialize(const polyr* a, uint8_t* out, size_t out_len)
                                              { (void)a; (void)out; (void)out_len; return false; }
dogecoin_bool polyr_deserialize(polyr* r, const uint8_t* in, size_t in_len)
                                              { (void)r; (void)in; (void)in_len; return false; }
