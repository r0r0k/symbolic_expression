import sys
from lief import *
from capstone import *
from triton import *

debug = 0

def main():
    assert len(sys.argv) == 3, 'Usage : python3 se.py <binary_path> <function_name>'
        
    # [1] Init using lief
    bin = parse(sys.argv[1])  # lief

    func = bin.get_symbol(sys.argv[2])
    assert func, 'invalid function'

    func_entry = func.value
    func_size = func.size
    bytecode = bin.get_content_from_virtual_address(func_entry, func_size)

    # [2] Disassemble using capstone
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    instructions = list(md.disasm(bytecode, func_entry))

    if debug:
        for inst in instructions:
            print(f"0x{inst.address:x}:\t{inst.mnemonic}\t{inst.op_str}")

    # 1. Collect registers used in function with capstone
    used_regs = set()
    for inst in instructions:
        used_regs.update(inst.regs_read + inst.regs_write)

    # 2. Convert capstone registers to triton registers
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    for reg in [ctx.registers.rax, ctx.registers.rbx, ctx.registers.rcx,
            ctx.registers.rdx, ctx.registers.rsi, ctx.registers.rdi,
            ctx.registers.rbp, ctx.registers.rsp, ctx.registers.r8,
            ctx.registers.r9, ctx.registers.r10, ctx.registers.r11,
            ctx.registers.r12, ctx.registers.r13, ctx.registers.r14,
            ctx.registers.r15]:
        ctx.symbolizeRegister(reg)


    triton_used_regs = set()
    for reg_id in used_regs:
        capstone_reg = md.reg_name(reg_id)
        try:
            triton_reg = getattr(ctx.registers, capstone_reg.lower())
            triton_used_regs.add(triton_reg)
        except AttributeError:
            pass  # dismiss if triton doesn't have capstone registers

    # 3. Load binary in memory
    for segment in bin.segments:
        ctx.setConcreteMemoryAreaValue(segment.virtual_address, bytes(segment.content))

    # 4. Print symbolic expression for all bytecode
    print('[1] Symbolic expression for all bytecode')
    for inst in instructions:
        ins = Instruction()
        ins.setOpcode(bytes(inst.bytes))
        ins.setAddress(inst.address)

        ctx.processing(ins)

        for se in ins.getSymbolicExpressions():
            se.setComment(str(ins))
            print(f"    {se.getComment()} -> {se.getAst()}")

    # 5. Print symbolic expression for used registers
    print('\n'+'#' * 100)
    print('#' * 100)
    print('#' * 100)
    print("\n[2] Symbolic expressions for used registers")
    for reg in triton_used_regs:
        if ctx.isRegisterSymbolized(reg):
            expr = ctx.getSymbolicRegister(reg)
            print(f"    {reg.getName()} -> {expr.getAst()}")

    # 6. Print symbolic expression for all registers
    print('\n'+'#' * 100)
    print('#' * 100)
    print('#' * 100)
    print("\n[3] Symbolic expressions for all registers")
    for reg_id, expr in ctx.getSymbolicRegisters().items():
        reg_name = ctx.getRegister(reg_id).getName()
        print(f"    {reg_name} (ID: {reg_id}) -> {expr.getAst()}")


if __name__ == '__main__':
    main()
