/*

 The MIT License (MIT)

 Copyright (c) 2009-2010 Satoshi Nakamoto
 Copyright (c) 2011 Vince Durham
 Copyright (c) 2009-2014 The Bitcoin developers
 Copyright (c) 2014-2016 Daniel Kraft
 Copyright (c) 2023 bluezr
 Copyright (c) 2023 The Dogecoin Foundation

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

#include <dogecoin/auxpow.h>

int get_expected_index (uint32_t nNonce, int nChainId, unsigned h)
{
  // Choose a pseudo-random slot in the chain merkle tree
  // but have it be fixed for a size/nonce/chain combination.
  //
  // This prevents the same work from being used twice for the
  // same chain while reducing the chance that two chains clash
  // for the same slot.

  /* This computation can overflow the uint32 used.  This is not an issue,
     though, since we take the mod against a power-of-two in the end anyway.
     This also ensures that the computation is, actually, consistent
     even if done in 64 bits as it was in the past on some systems.

     Note that h is always <= 30 (enforced by the maximum allowed chain
     merkle branch length), so that 32 bits are enough for the computation.  */

  uint32_t rand = nNonce;
  rand = rand * 1103515245 + 12345;
  rand += nChainId;
  rand = rand * 1103515245 + 12345;

  return rand % (1 << h);
}

// Computes the Merkle root from a given hash, Merkle branch, and index.
uint256_t* check_merkle_branch(uint256_t* hash, const vector_t* merkle_branch, int index) {
    if (index == -1) {
        return dogecoin_uint256_vla(1);  // Return a zeroed-out uint256_t array.
    }

    uint256_t* current_hash = dogecoin_uint256_vla(1);
    memcpy(current_hash, hash, sizeof(uint256_t)); // Copy the initial hash

    for (size_t i = 0; i < merkle_branch->len; ++i) {
        uint256_t* next_branch_hash = (uint256_t*)vector_idx(merkle_branch, i);
        uint8_t hash_input[DOGECOIN_HASH_LENGTH * 2];

        if (index & 1) {
            memcpy(hash_input, next_branch_hash, DOGECOIN_HASH_LENGTH);
            memcpy(hash_input + DOGECOIN_HASH_LENGTH, current_hash, DOGECOIN_HASH_LENGTH);
        } else {
            memcpy(hash_input, current_hash, DOGECOIN_HASH_LENGTH);
            memcpy(hash_input + DOGECOIN_HASH_LENGTH, next_branch_hash, DOGECOIN_HASH_LENGTH);
        }

        dogecoin_dblhash(hash_input, sizeof(hash_input), *current_hash);
        index >>= 1;
    }

    return current_hash;
}
