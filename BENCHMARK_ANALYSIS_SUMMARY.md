# Benchmark Analysis and Ranking Feature

## Overview

Added comprehensive analysis and ranking system to the benchmark tool to make performance comparisons easier to understand.

## Key Features

### 1. Overall Speed Ranking
- All benchmarks sorted by average time (fastest first)
- Shows operations per second for each benchmark
- Easy to identify the fastest and slowest operations

### 2. Key Performance Comparisons
Automatically calculates and displays:
- How much slower Falcon512 is compared to secp256k1 for different operations
- Comparisons between SPHINCS+ variants and Falcon512
- Relative performance metrics with actual numbers

Example output:
```
• Keypair Generation:
  - Falcon512 is 189.8x SLOWER than secp256k1 (0.007213 vs 0.000038 sec)
• Signing:
  - Falcon512 is 7.5x SLOWER than secp256k1 (0.000263 vs 0.000035 sec)
```

### 3. Category Winners
Identifies the fastest algorithm in each operation category:
- Key Generation
- Signing
- Verification
- Commit operations

### 4. Summary Recommendations
Provides context and recommendations based on the benchmark results for quantum-resistant signature implementations.

## Implementation Details

### Data Structures
- `benchmark_result`: Stores results for each benchmark run
- Global array storing up to 50 benchmark results
- Results are collected during execution and analyzed at the end

### New Functions
- `compare_avg_time()`: Sorts benchmarks by average time
- `find_result()`: Looks up specific benchmarks by name
- `print_analysis()`: Main analysis and output function

### Modified Functions
- `run_benchmark()`: Now accepts a category parameter and stores results for later analysis

## Benefits

1. **Easier Comparison**: No need to manually compare numbers - the tool does it automatically
2. **Clear Ranking**: Instantly see which algorithms are fastest for each operation
3. **Context**: Performance ratios show relative differences (e.g., "190x slower")
4. **Decision Support**: Category winners and summaries help choose the right algorithm

## Sample Output Structure

```
[Regular benchmark output with timing data]

PERFORMANCE ANALYSIS & RANKINGS
├── Overall Speed Ranking (sorted by avg time)
├── Key Performance Comparisons
│   ├── Falcon vs secp256k1
│   └── SPHINCS+ vs Falcon
├── Category Winners
│   ├── Fastest Key Generation
│   ├── Fastest Signing
│   ├── Fastest Verification
│   └── Fastest Commit
└── Summary & Recommendations
```

## Usage

Simply run `./bench` as before. The analysis section will automatically appear at the end of the benchmark output.

## Testing

The feature works with or without liboqs:
- Without liboqs: Shows analysis for classical algorithms (SHA256, Scrypt, secp256k1)
- With liboqs: Shows full analysis including PQC comparisons (Falcon, Dilithium, SPHINCS+)

## Future Enhancements

Potential improvements:
- CSV/JSON output for automated processing
- Historical comparison (compare current run to previous runs)
- Performance regression detection
- Graphical visualization of rankings
