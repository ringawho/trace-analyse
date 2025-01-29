(in-package #:capstone)

(cffi:defctype cs-handle :size)

(cffi:defcunion (cs-detail-spec :size 1768)
  (arm64 (:struct cs-arm64-spec)))

;; capstone5 size 1864 (according to grovel), arch-spec offset is 96
;; capstone6 size 1928 (according to grovel), arch-spec offset is 160
(cffi:defcstruct cs-detail
  (regs-read :uint16 :count 20)
  (regs-read-count :uint8)
  #-libcapstone6 (regs-write :uint16 :count 20)
  #+libcapstone6 (regs-write :uint16 :count 47)
  (regs-write-count :uint8)
  #-libcapstone6 (groups :uint8 :count 8)
  #+libcapstone6 (groups :uint8 :count 16)
  (groups-count :uint8)
  (writeback :bool)
  (arch-spec (:union cs-detail-spec)))

(cffi:defcstruct cs-insn
  (id :uint)
  #+libcapstone6 (alias-id (:uint64))
  (address :uint64)
  (bytes-count :uint16)  ; origin is size
  (bytes :uint8 :count 24)
  (mnemonic :char :count 32)
  (op-str :char :count 160)
  #+libcapstone6 (is-alias (:bool))
  #+libcapstone6 (uses-alias-details (:bool))
  (detail (:pointer (:struct cs-detail))))

(cffi:defcenum cs-arch
  :ARM           ; = 0   ARM architecture (including Thumb, Thumb-2)
  :ARM64         ; ARM-64, also called AArch64
  #+libcapstone6 :systemz  ; SystemZ architecture
  :MIPS          ; Mips architecture
  :X86           ; X86 architecture (including x86 & x86-64)
  :PPC           ; PowerPC architecture
  :SPARC         ; Sparc architecture

  ;; systemz is move front
  #-libcapstone6 :SYSZ          ; SystemZ architecture
  :XCORE         ; XCore architecture
  :M68K          ; 68K architecture
  :TMS320C64X    ; TMS320C64x architecture
  :M680X         ; 680X architecture
  :EVM           ; Ethereum architecture
  :MOS65XX       ; MOS65XX architecture (including MOS6502)
  :WASM          ; WebAssembly architecture
  :BPF           ; Berkeley Packet Filter architecture (including eBPF)
  :RISCV         ; RISCV architecture
  :SH            ; SH architecture
  :TRICORE       ; TriCore architecture
  #+libcapstone6 :ALPHA      ; Alpha architecture
  #+libcapstone6 :HPPA       ; HPPA architecture
  #+libcapstone6 :LOONGARCH  ; LoongArch architecture
  #+libcapstone6 :XTENSA     ; Xtensa architecture
  #+libcapstone6 :ARC        ; ARC architecture
  :MAX
  (:ALL #xFFFF)) ; = 0xFFFF   All architectures - for cs_support()

(cffi:defcenum cs-mode
  (:LITTLE-ENDIAN 0)           ; little-endian mode (default mode)
  (:ARM 0)                     ; 32-bit ARM
  (:16 #.(ash 1 1))            ; 16-bit mode (X86)
  (:32 #.(ash 1 2))            ; 32-bit mode (X86)
  (:64 #.(ash 1 3))            ; 64-bit mode (X86, PPC)
  (:THUMB #.(ash 1 4))         ; ARM's Thumb mode, including Thumb-2
  (:MCLASS #.(ash 1 5))        ; ARM's Cortex-M series
  (:V8 #.(ash 1 6))            ; ARMv8 A32 encodings for ARM
  ;; #+libcapstone6 (:V9 #.(ash 1 4))      ; SparcV9 mode (Sparc)
  (:MICRO #.(ash 1 4))         ; MicroMips mode (MIPS)
  (:MIPS3 #.(ash 1 5))         ; Mips III ISA
  (:MIPS32R6 #.(ash 1 6))      ; Mips32r6 ISA
  (:MIPS2 #.(ash 1 7))         ; Mips II ISA
  (:V9 #.(ash 1 4))            ; SparcV9 mode (Sparc)
  (:QPX #.(ash 1 4))           ; Quad Processing eXtensions mode (PPC)
  (:SPE #.(ash 1 5))           ; Signal Processing Engine mode (PPC)
  (:BOOKE #.(ash 1 6))         ; Book-E mode (PPC)
  (:PS #.(ash 1 7))            ; Paired-singles mode (PPC)

  ;; TODO: some libcapstone6 enum
  (:M68K-000 #.(ash 1 1))      ; M68K 68000 mode
  (:M68K-010 #.(ash 1 2))      ; M68K 68010 mode
  (:M68K-020 #.(ash 1 3))      ; M68K 68020 mode
  (:M68K-030 #.(ash 1 4))      ; M68K 68030 mode
  (:M68K-040 #.(ash 1 5))      ; M68K 68040 mode
  (:M68K-060 #.(ash 1 6))      ; M68K 68060 mode
  (:BIG-ENDIAN #.(ash 1 31))   ; big-endian mode
  (:MIPS32 #.(ash 1 2))        ; Mips32 ISA (Mips)
  (:MIPS64 #.(ash 1 3))        ; Mips64 ISA (Mips)
  (:M680X-6301 #.(ash 1 1))    ; M680X Hitachi 6301,6303 mode
  (:M680X-6309 #.(ash 1 2))    ; M680X Hitachi 6309 mode
  (:M680X-6800 #.(ash 1 3))    ; M680X Motorola 6800,6802 mode
  (:M680X-6801 #.(ash 1 4))    ; M680X Motorola 6801,6803 mode
  (:M680X-6805 #.(ash 1 5))    ; M680X Motorola/Freescale 6805 mode
  (:M680X-6808 #.(ash 1 6))    ; M680X Motorola/Freescale/NXP 68HC08 mode
  (:M680X-6809 #.(ash 1 7))    ; M680X Motorola 6809 mode
  (:M680X-6811 #.(ash 1 8))    ; M680X Motorola/Freescale/NXP 68HC11 mode
  (:M680X-CPU12 #.(ash 1 9))   ; M680X Motorola/Freescale/NXP CPU12
  ;; used on M68HC12/HCS12
  (:M680X-HCS08 #.(ash 1 10))      ; M680X Freescale/NXP HCS08 mode
  (:BPF-CLASSIC 0)                 ; Classic BPF mode (default)
  (:BPF-EXTENDED #.(ash 1 0))      ; Extended BPF mode
  (:RISCV32  #.(ash 1 0))          ; RISCV RV32G
  (:RISCV64  #.(ash 1 1))          ; RISCV RV64G
  (:RISCVC   #.(ash 1 2))          ; RISCV compressed instructure mode
  (:MOS65XX-6502 #.(ash 1 1))      ; MOS65XXX MOS 6502
  (:MOS65XX-65C02 #.(ash 1 2))     ; MOS65XXX WDC 65c02
  (:MOS65XX-W65C02 #.(ash 1 3))    ; MOS65XXX WDC W65c02
  (:MOS65XX-65816 #.(ash 1 4))     ; MOS65XXX WDC 65816, 8-bit m/x
  (:MOS65XX-65816-LONG-M #.(ash 1 5)) ; MOS65XXX WDC 65816, 16-bit m, 8-bit x
  (:MOS65XX-65816-LONG-X #.(ash 1 6)) ; MOS65XXX WDC 65816, 8-bit m, 16-bit x
  (:MOS65XX-65816-LONG-MX #.(logand (ash 1 5) (ash 1 6)))
  (:SH2 #.(ash 1 1))               ; SH2
  (:SH2A #.(ash 1 2))              ; SH2A
  (:SH3 #.(ash 1 3))               ; SH3
  (:SH4 #.(ash 1 4))               ; SH4
  (:SH4A #.(ash 1 5))              ; SH4A
  (:SHFPU #.(ash 1 6))             ; w/ FPU
  (:SHDSP #.(ash 1 7))             ; w/ DSP
  (:TRICORE-110 #.(ash 1 1))       ; Tricore 1.1
  (:TRICORE-120 #.(ash 1 2))       ; Tricore 1.2
  (:TRICORE-130 #.(ash 1 3))       ; Tricore 1.3
  (:TRICORE-131 #.(ash 1 4))       ; Tricore 1.3.1
  (:TRICORE-160 #.(ash 1 5))       ; Tricore 1.6
  (:TRICORE-161 #.(ash 1 6))       ; Tricore 1.6.1
  (:TRICORE-162 #.(ash 1 7)))      ; Tricore 1.6.2

(cffi:defcenum cs-opt-type
  :CS-OPT-INVALID            ; No option specified
  :CS-OPT-SYNTAX             ; Assembly output syntax
  :CS-OPT-DETAIL             ; Break down instruction structure into details
  :CS-OPT-MODE               ; Change engine's mode at run-time
  :CS-OPT-MEM                ; User-defined dynamic memory related functions
  :CS-OPT-SKIPDATA           ; Skip data when disassembling. Then engine is in SKIPDATA mode.
  :CS-OPT-SKIPDATA-SETUP     ; Setup user-defined function for SKIPDATA option
  :CS-OPT-MNEMONIC           ; Customize instruction mnemonic
  :CS-OPT-UNSIGNED           ; print immediate operands in unsigned form
  #-libcapstone6 :CS-OPT-NO-BRANCH-OFFSET  ; ARM, prints branch immediates without offset.
  #+libcapstone6 :CS_OPT_ONLY_OFFSET_BRANCH  ; ARM, PPC, AArch64: Don't add the branch immediate value to the PC.
  #+libcapstone6 :CS_OPT_LITBASE)  ; Xtensa, set the LITBASE value. LITBASE is set to 0 by default.

#+libcapstone6
(cffi:defcenum cs-opt-value
  (:CS-OPT-OFF 0)                         ; Turn OFF an option - default for CS_OPT_DETAIL, CS_OPT_SKIPDATA, CS_OPT_UNSIGNED.
  (:CS-OPT-ON #.(ash 1 0))                ; Turn ON an option (CS_OPT_DETAIL, CS_OPT_SKIPDATA).
  (:CS-OPT-SYNTAX-DEFAULT #.(ash 1 1))    ; Default asm syntax (CS_OPT_SYNTAX).
  (:CS-OPT-SYNTAX-INTEL #.(ash 1 2))      ; X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
  (:CS-OPT-SYNTAX-ATT #.(ash 1 3))        ; X86 ATT asm syntax (CS_OPT_SYNTAX).
  (:CS-OPT-SYNTAX-NOREGNAME #.(ash 1 4))  ; Prints register name with only number (CS_OPT_SYNTAX)
  (:CS-OPT-SYNTAX-MASM #.(ash 1 5))       ; X86 Intel Masm syntax (CS_OPT_SYNTAX).
  (:CS-OPT-SYNTAX-MOTOROLA #.(ash 1 6))     ; MOS65XX use $ as hex prefix
  (:CS-OPT-SYNTAX-CS-REG-ALIAS #.(ash 1 7)) ; Prints common register alias which are not defined in LLVM (ARM: r9 = sb etc.)
  (:CS-OPT-SYNTAX-PERCENT #.(ash 1 8))      ; Prints the % in front of PPC registers.
  (:CS-OPT-SYNTAX-NO-DOLLAR #.(ash 1 9))    ; Does not print the $ in front of Mips, LoongArch registers.
  (:CS-OPT-DETAIL-REAL #.(ash 1 1)))        ; If enabled, always sets the real instruction detail. Even if the instruction is an alias.

(cffi:defcenum cs-err
  :OK        ; No error: everything was fine
  :MEM       ; Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
  :ARCH      ; Unsupported architecture: cs_open()
  :HANDLE    ; Invalid handle: cs_op_count(), cs_op_index()
  :CSH       ; Invalid csh argument: cs_close(), cs_errno(), cs_option()
  :MODE      ; Invalid/unsupported mode: cs_open()
  :OPTION    ; Invalid/unsupported option: cs_option()
  :DETAIL    ; Information is unavailable because detail option is OFF
  :MEMSETUP  ; Dynamic memory management uninitialized (see CS_OPT_MEM)
  :VERSION   ; Unsupported version (bindings)
  :DIET      ; Access irrelevant data in "diet" engine
  :SKIPDATA  ; Access irrelevant data for "data" instruction in SKIPDATA mode
  :X86-ATT   ; X86 AT&T syntax is unsupported (opt-out at compile time)
  :X86-INTEL ; X86 Intel syntax is unsupported (opt-out at compile time)
  :X86-MASM) ; X86 Masm syntax is unsupported (opt-out at compile time))

(cffi:defcfun "cs_version" :uint
  "Return combined API version & major and minor version numbers.

@major: major number of API version
@minor: minor number of API version

@return hexical number as (major << 8 | minor), which encodes both
    major & minor versions.
    NOTE: This returned value can be compared with version number made
    with macro CS_MAKE_VERSION

For example, second API version would return 1 in @major, and 1 in @minor
The return value would be 0x0101

NOTE: if you only care about returned value, but not major and minor values,
set both @major & @minor arguments to NULL."
  (major (:pointer :int))
  (minor (:pointer :int)))

(cffi:defcfun "cs_open" cs-err
  "Initialize CS handle: this must be done before any usage of CS.

@arch: architecture type (CS_ARCH_*)
@mode: hardware mode. This is combined of CS_MODE_*
@handle: pointer to handle, which will be updated at return time

@return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
for detailed error)."
  (arch cs-arch)
  (mode cs-mode)
  (handle (:pointer cs-handle)))

(cffi:defcfun "cs_close" cs-err
  "Close CS handle: MUST do to release the handle when it is not used anymore.
NOTE: this must be only called when there is no longer usage of Capstone,
not even access to cs_insn array. The reason is the this API releases some
cached memory, thus access to any Capstone API after cs_close() might crash
your application.

In fact,this API invalidate @handle by ZERO out its value (i.e *handle = 0).

@handle: pointer to a handle returned by cs_open()

@return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
for detailed error)."
  (handle (:pointer cs-handle)))

(cffi:defcfun "cs_option" cs-err
  "Set option for disassembling engine at runtime

@handle: handle returned by cs_open()
@type: type of option to be set
@value: option value corresponding with @type

@return: CS_ERR_OK on success, or other value on failure.
Refer to cs_err enum for detailed error.

NOTE: in the case of CS_OPT_MEM, handle's value can be anything,
so that cs_option(handle, CS_OPT_MEM, value) can (i.e must) be called
even before cs_open()"
  (handle cs-handle)
  (type cs-opt-type)
  (value :size))

(cffi:defcfun "cs_errno" cs-err
  "Report the last error number when some API function fail.
Like glibc's errno, cs_errno might not retain its old value once accessed.

@handle: handle returned by cs_open()

@return: error code of cs_err enum type (CS_ERR_*, see above)"
  (handle cs-handle))

(cffi:defcfun "cs_strerror" :string
  "Return a string describing given error code.

@code: error code (see CS_ERR_* above)

@return: returns a pointer to a string that describes the error code
    passed in the argument @code"
  (code cs-err))

(cffi:defcfun "cs_disasm" :size
  "Disassemble binary code, given the code buffer, size, address and number
of instructions to be decoded.
This API dynamically allocate memory to contain disassembled instruction.
Resulting instructions will be put into @*insn

NOTE 1: this API will automatically determine memory needed to contain
output disassembled instructions in @insn.

NOTE 2: caller must free the allocated memory itself to avoid memory leaking.

NOTE 3: for system with scarce memory to be dynamically allocated such as
OS kernel or firmware, the API cs_disasm_iter() might be a better choice than
cs_disasm(). The reason is that with cs_disasm(), based on limited available
memory, we have to calculate in advance how many instructions to be disassembled,
which complicates things. This is especially troublesome for the case @count=0,
when cs_disasm() runs uncontrollably (until either end of input buffer, or
when it encounters an invalid instruction).

@handle: handle returned by cs_open()
@code: buffer containing raw binary code to be disassembled.
@code_size: size of the above code buffer.
@address: address of the first instruction in given raw code buffer.
@insn: array of instructions filled in by this API.
      NOTE: @insn will be allocated by this function, and should be freed
      with cs_free() API.
@count: number of instructions to be disassembled, or 0 to get all of them

@return: the number of successfully disassembled instructions,
or 0 if this function failed to disassemble the given code

On failure, call cs_errno() for error code."
  (handle cs-handle)
  (code (:pointer :uint8))
  (code-size :size)
  (address :uint64)
  (count :size)
  (insn (:pointer (:pointer (:struct cs-insn)))))

(cffi:defcfun "cs_free" :void
  "Free memory allocated by cs_malloc() or cs_disasm() (argument @insn)

@insn: pointer returned by @insn argument in cs_disasm() or cs_malloc()
@count: number of cs_insn structures returned by cs_disasm(), or 1
    to free memory allocated by cs_malloc()."
  (insn (:pointer (:struct cs-insn)))
  (count :size))

(cffi:defcfun "cs_regs_access" cs-err
  " Retrieve all the registers accessed by an instruction, either explicitly or
implicitly.

WARN: when in 'diet' mode, this API is irrelevant because engine does not
store registers.

@handle: handle returned by cs_open()
@insn: disassembled instruction structure returned from cs_disasm() or cs_disasm_iter()
@regs_read: on return, this array contains all registers read by instruction.
@regs_read_count: number of registers kept inside @regs_read array.
@regs_write: on return, this array contains all registers written by instruction.
@regs_write_count: number of registers kept inside @regs_write array.

@return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
for detailed error)."
  (handle cs-handle)
  (insn (:pointer (:struct cs-insn)))
  (regs-read (:pointer :uint16))
  (regs-read-count (:pointer :uint8))
  (regs-write (:pointer :uint16))
  (regs-write-count (:pointer :uint8)))

