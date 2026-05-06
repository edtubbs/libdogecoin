# Thread-safety Valgrind Verification Report

This report captures final valgrind verification for thread-safe (`_ts`) and legacy binaries on branch `copilot/make-libdogecoin-stateless`.

## Environment
- Host: Ubuntu runner
- Valgrind: `valgrind-3.22.0`

## Commands and outcomes

### 1) Full unit test suite (covers context/wallet/transaction `_ts` APIs)
```bash
LIBDOGECOIN_TEST_PASSWD=testpass \
valgrind --leak-check=full --show-leak-kinds=all \
  --errors-for-leak-kinds=all --error-exitcode=99 ./build-local/tests
```
Result:
- `ERROR SUMMARY: 0 errors from 0 contexts`
- `All heap blocks were freed -- no leaks are possible`

### 2) `such_ts` startup/usage path
```bash
valgrind --leak-check=full --show-leak-kinds=all \
  --errors-for-leak-kinds=all --error-exitcode=99 ./such_ts --help
```
Result:
- `ERROR SUMMARY: 0 errors from 0 contexts`
- `All heap blocks were freed -- no leaks are possible`

### 3) `sendtx_ts` startup/usage path
```bash
valgrind --leak-check=full --show-leak-kinds=all \
  --errors-for-leak-kinds=all --error-exitcode=99 ./sendtx_ts --help
```
Result:
- `ERROR SUMMARY: 0 errors from 0 contexts`
- `All heap blocks were freed -- no leaks are possible`

### 4) `spvnode_ts` bounded scan with graceful shutdown
```bash
(sleep 20; echo q) | \
valgrind --leak-check=full --show-leak-kinds=all \
  --errors-for-leak-kinds=all --error-exitcode=99 \
  ./spvnode_ts -l -f 0 -o 2 -p scan
```
Result:
- `ERROR SUMMARY: 0 errors from 0 contexts`
- `All heap blocks were freed -- no leaks are possible`

### 5) Legacy `spvnode` parity check (bounded scan, graceful shutdown)
```bash
(sleep 15; echo q) | \
valgrind --leak-check=full --show-leak-kinds=all \
  --errors-for-leak-kinds=all --error-exitcode=99 \
  ./spvnode -l -f 0 -o 2 -p scan
```
Result:
- `ERROR SUMMARY: 0 errors from 0 contexts`
- `All heap blocks were freed -- no leaks are possible`

## Fixes made to reach clean valgrind status

1. **Wallet reorg test leak cleanup**
   - Freed `wtx` in `test_wallet_reorg_utxo_update()`.
2. **Transaction test global context cleanup**
   - Added `remove_all()` at end of large transaction test to release stored working transactions.
3. **libevent global lock cleanup at process exit**
   - Added `libevent_global_shutdown()` in `spvnode` scan shutdown path, eliminating remaining libevent global allocations.

## Conclusion
All targeted checks are now valgrind-clean with:
- zero definitely/indirectly/possibly lost,
- zero still reachable,
- zero errors.
