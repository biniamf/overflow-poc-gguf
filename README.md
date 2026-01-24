### Summary
An integer overflow vulnerability exists in the `ggml_nbytes()` function in `ggml/src/ggml.c`. When processing specially crafted GGUF model files with malicious tensor dimensions, the function performs unchecked arithmetic that overflows `size_t`, returning an incorrectly small byte count. This leads to undersized memory allocations and subsequent heap buffer overflows when tensor data is written.

### Affected version
- Confirmed on <= b7815

### Affected Code

**File:** `ggml/src/ggml.c`

```c
size_t ggml_nbytes(const struct ggml_tensor * tensor) {
    for (int i = 0; i < GGML_MAX_DIMS; ++i) {
        if (tensor->ne[i] <= 0) {
            return 0;
        }
    }

    size_t nbytes;
    const size_t blck_size = ggml_blck_size(tensor->type);
    if (blck_size == 1) {
        nbytes = ggml_type_size(tensor->type);
        for (int i = 0; i < GGML_MAX_DIMS; ++i) {
            nbytes += (tensor->ne[i] - 1)*tensor->nb[i];  // <--
        }
    } else {
        nbytes = tensor->ne[0]*tensor->nb[0]/blck_size;   // <--
        for (int i = 1; i < GGML_MAX_DIMS; ++i) {
            nbytes += (tensor->ne[i] - 1)*tensor->nb[i];  // <--
        }
    }

    return nbytes;
}
```

### Root Cause

The function computes tensor byte size by multiplying dimension sizes (`ne[]`) with strides (`nb[]`). These operations are unchecked and can overflow `size_t`.

### Data Flow

1. **Source (User Input):** Tensor dimensions are read from GGUF files in `gguf.cpp`:
   ```cpp
   // gguf.cpp 
   ok = ok && gr.read(info.t.ne[j]);  // Reads dimension from file
   ```

2. **Validation Gap:** The existing validation only checks element count against `INT64_MAX`:
   ```cpp
   // gguf.cpp 
   if ((INT64_MAX/info.t.ne[1] <= info.t.ne[0]) ||
       (INT64_MAX/info.t.ne[2] <= info.t.ne[0]*info.t.ne[1]) ||
       (INT64_MAX/info.t.ne[3] <= info.t.ne[0]*info.t.ne[1]*info.t.ne[2]))
   ```
   
3. **Vulnerable Code:** The overflow occurs in `ggml_nbytes()` when computing:
   ```c
   nbytes += (tensor->ne[i] - 1) * tensor->nb[i];
   ```

4. **Impact:** The undersized `nbytes` is used for memory allocation, causing heap buffer overflow.


### PoC

A specially crafted gguf can trigger the vulnerability: 

```bash
./bin/llama-gguf poc_segfault_oob-llama-gguf.gguf r 
gguf_ex_read_0: version:      3
gguf_ex_read_0: alignment:   32
gguf_ex_read_0: data offset: 608
gguf_ex_read_0: n_kv: 12
gguf_ex_read_0: kv[0]: key = general.alignment
gguf_ex_read_0: kv[1]: key = general.architecture
gguf_ex_read_0: kv[2]: key = general.name
gguf_ex_read_0: kv[3]: key = llama.context_length
gguf_ex_read_0: kv[4]: key = llama.embedding_length
gguf_ex_read_0: kv[5]: key = llama.block_count
gguf_ex_read_0: kv[6]: key = llama.attention.head_count
gguf_ex_read_0: kv[7]: key = llama.attention.head_count_kv
gguf_ex_read_0: kv[8]: key = tokenizer.ggml.model
gguf_ex_read_0: kv[9]: key = tokenizer.ggml.tokens
gguf_ex_read_0: kv[10]: key = tokenizer.ggml.scores
gguf_ex_read_0: kv[11]: key = tokenizer.ggml.token_type
gguf_ex_read_0: find key: some.parameter.string not found.
gguf_ex_read_0: n_tensors: 1
gguf_ex_read_0: tensor[0]: name = test.weight, size = 18446744073709551612, offset = 0
gguf_ex_read_1: version:      3
gguf_ex_read_1: alignment:   32
gguf_ex_read_1: data offset: 608
gguf_ex_read_1: n_kv: 12
gguf_ex_read_1: kv[0]: key = general.alignment
gguf_ex_read_1: kv[1]: key = general.architecture
gguf_ex_read_1: kv[2]: key = general.name
gguf_ex_read_1: kv[3]: key = llama.context_length
gguf_ex_read_1: kv[4]: key = llama.embedding_length
gguf_ex_read_1: kv[5]: key = llama.block_count
gguf_ex_read_1: kv[6]: key = llama.attention.head_count
gguf_ex_read_1: kv[7]: key = llama.attention.head_count_kv
gguf_ex_read_1: kv[8]: key = tokenizer.ggml.model
gguf_ex_read_1: kv[9]: key = tokenizer.ggml.tokens
gguf_ex_read_1: kv[10]: key = tokenizer.ggml.scores
gguf_ex_read_1: kv[11]: key = tokenizer.ggml.token_type
gguf_ex_read_1: n_tensors: 1
gguf_ex_read_1: tensor[0]: name = test.weight, size = 18446744073709551612, offset = 0, type = f32, n_elts = 4611686018427387903
gguf_ex_read_1: reading tensor 0 data
gguf_ex_read_1: tensor[0]: n_dims = 1, ne = (-1, 1, 1, 1), name = test.weight, data = 0x0
AddressSanitizer:DEADLYSIGNAL
=================================================================
==73125==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x000100af0a8c bp 0x00016f3122f0 sp 0x00016f311fe0 T0)
==73125==The signal is caused by a READ memory access.
==73125==Hint: address points to the zero page.
    #0 0x000100af0a8c in gguf_ex_read_1(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&, bool) gguf.cpp:216
    #1 0x000100aeee90 in main gguf.cpp:266
    #2 0x000194289d50  (<unknown module>)

==73125==Register values:
 x[0] = 0x000000000000000a   x[1] = 0x0000000100b00422   x[2] = 0x00000000000120a8   x[3] = 0x0000000000000016  
 x[4] = 0x0000000100b00420   x[5] = 0x000000016f311fd0   x[6] = 0x000000016eb18000   x[7] = 0x0000000000000001  
 x[8] = 0x0000000000000000   x[9] = 0x0000000000000000  x[10] = 0x0000000000000000  x[11] = 0x0000010000000000  
x[12] = 0x00000000fffffffd  x[13] = 0x0000000000000000  x[14] = 0x0000000000000000  x[15] = 0x0000000000000000  
x[16] = 0x000000010159fd34  x[17] = 0x0000000202b30860  x[18] = 0x0000000000000000  x[19] = 0x000000016f312020  
x[20] = 0x0000000201570e08  x[21] = 0x00000002012c4e00  x[22] = 0xfffffffffffffff0  x[23] = 0x0000000201574520  
x[24] = 0x0000000000000001  x[25] = 0x000000016f3126e0  x[26] = 0x0000000201574530  x[27] = 0x0000000000000000  
x[28] = 0x0000000000000000     fp = 0x000000016f3122f0     lr = 0x0000000100af09dc     sp = 0x000000016f311fe0  
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV gguf.cpp:216 in gguf_ex_read_1(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&, bool)
==73125==ABORTING
test.weight data[:10] : zsh: abort      ./bin/llama-gguf poc_segfault_oob-llama-gguf.gguf r
```

### Impact
Integer overflow vulnerability leading to heap buffer overflow, denial of service, potential remote code execution affecting users or systems loadong malicious gguf
