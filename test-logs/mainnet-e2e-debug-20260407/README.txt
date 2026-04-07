Mainnet E2E debug bundle
Generated at: 2026-04-07T03:38:43Z

Runs attempted:
1) contrib/mainnet_pq_cascade_test.sh (partial; Falcon stage progressed to SPV scan)
2) contrib/mainnet_falcon_test.sh (SPV timeout waiting for /getUTXOs txid)
3) contrib/mainnet_dilithium2_test.sh (SPV timeout waiting for /getUTXOs txid)
4) contrib/mainnet_raccoong_test.sh (exited after carrier pre-sign step; see tool output)

Key txids observed:
/home/runner/work/libdogecoin/libdogecoin/test-logs/mainnet-e2e-debug-20260407/falcon_run_tool_output.txt:Start broadcasting transaction: e03d7d2c554a62e82bf9ec8dc2e177b83c5e385a24efc4972b44740fbbc20fb0 with timeout 15 seconds
/home/runner/work/libdogecoin/libdogecoin/test-logs/mainnet-e2e-debug-20260407/dilithium2_run_tool_output.txt:Start broadcasting transaction: 5797ca29d2d490b1e8d79957c48be4683414e412fa2107c403276a4086b03818 with timeout 15 seconds

Key errors observed:
/home/runner/work/libdogecoin/libdogecoin/test-logs/mainnet-e2e-debug-20260407/falcon_run_tool_output.txt:sendtx-note: The transaction was not relayed back. Your transaction is very likely invalid (or was already broadcasted and picked up by an invalid node)
/home/runner/work/libdogecoin/libdogecoin/test-logs/mainnet-e2e-debug-20260407/falcon_run_tool_output.txt:[ERROR] Timed out waiting for txid e03d7d2c554a62e82bf9ec8dc2e177b83c5e385a24efc4972b44740fbbc20fb0 in /getUTXOs
/home/runner/work/libdogecoin/libdogecoin/test-logs/mainnet-e2e-debug-20260407/dilithium2_run_tool_output.txt:sendtx-note: The transaction was not relayed back. Your transaction is very likely invalid (or was already broadcasted and picked up by an invalid node)
/home/runner/work/libdogecoin/libdogecoin/test-logs/mainnet-e2e-debug-20260407/dilithium2_run_tool_output.txt:[ERROR] Timed out waiting for txid 5797ca29d2d490b1e8d79957c48be4683414e412fa2107c403276a4086b03818 in /getUTXOs
