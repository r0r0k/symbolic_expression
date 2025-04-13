import lief
from capstone import *
from triton import *

# 바이너리 로드
binary = lief.parse("bbs")
if binary is None:
    exit(1)

# 섹션 정보 출력
# for section in binary.sections:
#    print(f"[{section.name}] @ 0x{section.virtual_address:x}, size: {section.size}")

# .text 섹션 찾기
text_section = binary.get_section(".text")
if text_section is None:
    exit(1)

# 코드 및 베이스 주소 설정
code = text_section.content
base_addr = text_section.virtual_address
if not isinstance(code, bytes):
    code = bytes(code)

print(f"[Debug] base_addr = {hex(base_addr)}, code size = {len(code)}")

# Capstone으로 디스어셈블
md = Cs(CS_ARCH_X86, CS_MODE_64)
instructions = list(md.disasm(code, base_addr))

for inst in instructions:
   print(f"0x{inst.address:x}:\t{inst.mnemonic}\t{inst.op_str}")

# Triton 설정
ctx = TritonContext()
ctx.setArchitecture(ARCH.X86_64)
ctx.setMode(MODE.ALIGNED_MEMORY, True)

# 메모리 초기화
ctx.setConcreteMemoryAreaValue(base_addr, list(code))

# 초기 스택 및 레지스터 설정
ctx.setConcreteRegisterValue(ctx.registers.rsp, 0x7fffffffd000)
ctx.setConcreteRegisterValue(ctx.registers.rbp, 0x7fffffffd000)

# 심볼릭 실행
for inst in instructions:
    opcode = bytes(inst.bytes) if isinstance(inst.bytes, bytearray) else inst.bytes
    address = inst.address
    instruction = Instruction(address, opcode)

    # Triton 명령어 처리
    ctx.processing(instruction)

    # 심볼릭 표현 출력
    for expr in instruction.getSymbolicExpressions():
        print(f"[Symbolic] {expr.getComment()} -> {expr}")

# RCX slicing
rcx_expr = ctx.getSymbolicRegister(ctx.registers.rcx)
slicing = ctx.sliceExpressions(rcx_expr)

for key, expr in sorted(slicing.items()):
    print(f"[Slicing] {expr.getComment()} -> {expr}")
