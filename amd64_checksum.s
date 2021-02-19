.globl	as_checksum

#uint16_t as_checksum(uint8_t *data, uint16_t len, uint16_t init);
#                               rdi,           rsi,          rdx
as_checksum:
  # Accumulative sum.
  movzwl %dx,%eax              # Move init value to rax. Stores accumulated sum.
  xor %r9,%r9                  # Clear out r9. Stores value of array.
  xor %r8,%r8                  # Clear out r8. Stores array index.
  movzwl %si, %ecx

  L1:
  cmp $32, %rcx                # If index is less than 32.
  jl L2                        # Jump to branch 'L2'.
  add (%rdi,%r8),%rax          # Sum acc with qword[0].
  adc 8(%rdi,%r8),%rax         # Sum with carry qword[1].
  adc 16(%rdi,%r8),%rax        # Sum with carry qword[2].
  adc 24(%rdi,%r8),%rax        # Sum with carry qword[3]
  adc $0, %rax                 # Sum carry-bit into acc.
  sub $32, %rcx                # Decrease left bytes by 32.
  add $32, %r8                 # Next 32 bytes.
  jmp L1                       # Go to beginning of loop.
  L2:
  cmp $16, %rcx                # If index is less than 16.
  jl L3                        # Jump to branch 'L3'.
  add (%rdi, %r8), %rax        # Sum acc with qword[0].
  adc 8(%rdi, %r8), %rax       # Sum with carry qword[1].
  adc $0, %rax                 # Sum carry-bit into acc.
  sub $16, %rcx                # Decrease left bytes by 16.
  add $16, %r8                 # Next 16 bytes.
  L3:
  cmp $8, %rcx                 # If index is less than 8.
  jl L4                        # Jump to branch 'L4'.
  add (%rdi, %r8), %rax        # Sum acc with qword[0].
  adc $0, %rax                 # Sum carry-bit into acc.
  sub $8, %rcx                 # Decrease left bytes by 8.
  add $8, %r8                  # Next 8 bytes.
  L4:
  cmp $4, %rcx                 # If index is less than 4.
  jl L5                        # Jump to branch 'L5'.
  mov (%rdi, %r8), %r9d        # Fetch 32-bit from data + r8 into r9d.
  add %r9, %rax                # Sum acc with r9. Accumulate carry.
  sub $4, %rcx                 # Decrease left bytes by 4.
  add $4, %r8                  # Next 4 bytes.
  L5:
  cmp $2, %rcx                 # If index is less than 2.
  jl L6                        # Jump to branch 'L6'.

  movzwq (%rdi, %r8), %r9      # Fetch 16-bit from data + r8 into r9.
  add %r9, %rax                # Sum acc with r9. Accumulate carry.
  sub $2, %rcx                 # Decrease left bytes by 2.
  add $2, %r8                  # Next 2 bytes.
  L6:
  cmp $1, %rcx                 # If index is less than 1.
  jl L7                        # Jump to branch 'L7'.

  movzbq (%rdi, %r8), %r9      # Fetch 8-bit from data + r8 into r9.
  add %r9, %rax                # Sum acc with r9. Accumulate carry.

  # Fold 64-bit into 16-bit.
  L7:
  mov %rax, %r9                # Assign acc to r9.
  shr $32, %r9                 # Shift r9 32-bit. Stores higher part of acc.
  mov %eax, %eax               # Clear out higher-part of rax. Stores lower part of acc.
  add %r9d, %eax               # 32-bit sum of acc and r9.
  adc $0, %eax                 # Sum carry to acc.
  mov %eax, %r9d               # Repeat for 16-bit.
  shr $16, %r9d
  and $0x0000ffff, %eax
  add %r9w, %ax
  adc $0, %ax

  # One's complement.
  not %rax                     # One-complement of rax.
  and $0xffff, %rax            # Clear out higher part of rax.
  retq
