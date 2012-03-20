/* 
  This is a port of QEMU's arm decoding and translation engine.
  - Cmw / cmw@cmw.me

 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.

*/
/* Constants */
var ARM_CPU_MODE_USR = 0x10;
var ARM_CPU_MODE_FIQ = 0x11;
var ARM_CPU_MODE_IRQ = 0x12;
var ARM_CPU_MODE_SVC = 0x13;
var ARM_CPU_MODE_ABT = 0x17;
var ARM_CPU_MODE_UND = 0x1b;
var ARM_CPU_MODE_SYS = 0x1f;

var DISAS_NEXT    = 0; /* next instruction can be analyzed */
var DISAS_JUMP    = 1; /* only pc was modified dynamically */
var DISAS_UPDATE  = 2; /* cpu state was modified dynamically */
var DISAS_TB_JUMP = 3; /* only pc was modified statically */

var cpu_single_env = 0;
var T0 = 0;
var T1 = 0;
var T2 = 0;
var cur_tb_op = 0;

var ARM_FEATURE_VFP = 0;
var ARM_FEATURE_AUXCR = 1;
var ARM_FEATURE_XSCALE = 2;
var ARM_FEATURE_IWMMXT = 3;
var ARM_FEATURE_V6 = 4;
var ARM_FEATURE_V6K = 5;
var ARM_FEATURE_V7 = 6;
var ARM_FEATURE_THUMB2 = 7;
var ARM_FEATURE_MPU = 8
var ARM_FEATURE_VFP3 = 9;
var ARM_FEATURE_NEON = 10;
var ARM_FEATURE_DIV = 11;
var ARM_FEATURE_M = 12;
var ARM_FEATURE_OMAPCP = 13;

/* typedef struct DisasContext { */
function DisasContext() {
    this.pc = 0;/* target_ulong*/ 
    this.is_jmp = DISAS_NEXT;
    /* Nonzero if this instruction has been conditionally skipped.  */
    this.condjmp = 0;
    /* The label that will be jumped to when the instruction is skipped.  */
    this.condlabel = 0;
    /* Thumb-2 condtional execution bits.  */
    this.condexec_mask = 0;
    this.condexec_cond = 0;
    //struct TranslationBlock *tb;
    this.singlestep_enabled = 0;
    this.thumb = 0;
    this.is_mem = 0;

    this.user = 0;

} /* DisasContext; */


/* exec-cpu code */
function handle_cpu_signal(/* unsigned long */ pc, /* unsigned long */ address,
                                    /* int */ is_write, /* sigset_t * */ old_set,
                                    /* void * */puc)
{
    TranslationBlock *tb;
    var ret;

    if (cpu_single_env)
        env = cpu_single_env; /* XXX: find a correct solution for multithread */
    //printf("qemu: SIGSEGV pc=0x%08lx address=%08lx w=%d oldset=0x%08lx\n", pc, address, is_write, *(unsigned long *)old_set);
    /* XXX: locking issue */
    if (is_write && page_unprotect(h2g(address), pc, puc)) {
        return 1;
    }
    /* see if it is an MMU fault */
    ret = cpu_arm_handle_mmu_fault(env, address, is_write, MMU_USER_IDX, 0);
    if (ret < 0)
        return 0; /* not an MMU fault */
    if (ret == 0)
        return 1; /* the MMU fault was handled without causing real CPU fault */
    /* now we have a real cpu fault */
    tb = tb_find_pc(pc);
    if (tb) {
        /* the PC is inside the translated code. It means that we have
           a virtual CPU fault */
        cpu_restore_state(tb, env, pc, puc);
    }
    /* we restore the process signal mask as the sigreturn should
       do it (XXX: use sigsetjmp) */
    //sigprocmask(SIG_SETMASK, old_set, NULL);
    cpu_loop_exit();
}

function cpu_signal_handler(/*int */ host_signum, /* void * */pinfo,
                       /* void * */puc)
{
    /*
    siginfo_t *info = pinfo;
    struct ucontext *uc = puc;
    unsigned long pc;
    int is_write;

    pc = uc->uc_mcontext.gregs[R15];
    // XXX: compute is_write 
    is_write = 0;
    return handle_cpu_signal(pc, (unsigned long)info->si_addr,
                             is_write,
                             &uc->uc_sigmask, puc);
    */
}



/*
function MakeEnum(vals) { 
    for (e in val) { 
        this[vals[e]] = e;
    }
}

var index_enum_t = MakeEnum([
*/

function op_movl_T0_r0()
{
    T0 = (cpu_single_env.regs[0]);
}
function op_movl_T1_r0()
{
    T1 = (cpu_single_env.regs[0]);
}
function op_movl_T2_r0()
{
    T2 = (cpu_single_env.regs[0]);
}
function op_movl_r0_T0()
{
    (cpu_single_env.regs[0]) = T0;
}
function op_movl_r0_T1()
{
    //console.log("op_movl_r0_T1 r0=0x" + cpu_single_env.regs[0].toString(16) + " T1=0x" + T1.toString(16));
    (cpu_single_env.regs[0]) = T1;
}
function op_movl_T0_r1()
{
    T0 = (cpu_single_env.regs[1]);
}
function op_movl_T1_r1()
{
    T1 = (cpu_single_env.regs[1]);
}
function op_movl_T2_r1()
{
    T2 = (cpu_single_env.regs[1]);
}
function op_movl_r1_T0()
{
    (cpu_single_env.regs[1]) = T0;
}
function op_movl_r1_T1()
{
    (cpu_single_env.regs[1]) = T1;
}
function op_movl_T0_r2()
{
    T0 = (cpu_single_env.regs[2]);
}
function op_movl_T1_r2()
{
    T1 = (cpu_single_env.regs[2]);
}
function op_movl_T2_r2()
{
    T2 = (cpu_single_env.regs[2]);
}
function op_movl_r2_T0()
{
    (cpu_single_env.regs[2]) = T0;
}
function op_movl_r2_T1()
{
    (cpu_single_env.regs[2]) = T1;
}
function op_movl_T0_r3()
{
    T0 = (cpu_single_env.regs[3]);
}
function op_movl_T1_r3()
{
    T1 = (cpu_single_env.regs[3]);
}
function op_movl_T2_r3()
{
    T2 = (cpu_single_env.regs[3]);
}
function op_movl_r3_T0()
{
    (cpu_single_env.regs[3]) = T0;
}
function op_movl_r3_T1()
{
    (cpu_single_env.regs[3]) = T1;
}
function op_movl_T0_r4()
{
    T0 = (cpu_single_env.regs[4]);
}
function op_movl_T1_r4()
{
    T1 = (cpu_single_env.regs[4]);
}
function op_movl_T2_r4()
{
    T2 = (cpu_single_env.regs[4]);
}
function op_movl_r4_T0()
{
    (cpu_single_env.regs[4]) = T0;
}
function op_movl_r4_T1()
{
    (cpu_single_env.regs[4]) = T1;
}
function op_movl_T0_r5()
{
    T0 = (cpu_single_env.regs[5]);
}
function op_movl_T1_r5()
{
    T1 = (cpu_single_env.regs[5]);
}
function op_movl_T2_r5()
{
    T2 = (cpu_single_env.regs[5]);
}
function op_movl_r5_T0()
{
    (cpu_single_env.regs[5]) = T0;
}
function op_movl_r5_T1()
{
    (cpu_single_env.regs[5]) = T1;
}
function op_movl_T0_r6()
{
    T0 = (cpu_single_env.regs[6]);
}
function op_movl_T1_r6()
{
    T1 = (cpu_single_env.regs[6]);
}
function op_movl_T2_r6()
{
    T2 = (cpu_single_env.regs[6]);
}
function op_movl_r6_T0()
{
    (cpu_single_env.regs[6]) = T0;
}
function op_movl_r6_T1()
{
    (cpu_single_env.regs[6]) = T1;
}
function op_movl_T0_r7()
{
    T0 = (cpu_single_env.regs[7]);
}
function op_movl_T1_r7()
{
    T1 = (cpu_single_env.regs[7]);
}
function op_movl_T2_r7()
{
    T2 = (cpu_single_env.regs[7]);
}
function op_movl_r7_T0()
{
    (cpu_single_env.regs[7]) = T0;
}
function op_movl_r7_T1()
{
    (cpu_single_env.regs[7]) = T1;
}
function op_movl_T0_r8()
{
    T0 = (cpu_single_env.regs[8]);
}
function op_movl_T1_r8()
{
    T1 = (cpu_single_env.regs[8]);
}
function op_movl_T2_r8()
{
    T2 = (cpu_single_env.regs[8]);
}
function op_movl_r8_T0()
{
    (cpu_single_env.regs[8]) = T0;
}
function op_movl_r8_T1()
{
    (cpu_single_env.regs[8]) = T1;
}
function op_movl_T0_r9()
{
    T0 = (cpu_single_env.regs[9]);
}
function op_movl_T1_r9()
{
    T1 = (cpu_single_env.regs[9]);
}
function op_movl_T2_r9()
{
    T2 = (cpu_single_env.regs[9]);
}
function op_movl_r9_T0()
{
    (cpu_single_env.regs[9]) = T0;
}
function op_movl_r9_T1()
{
    (cpu_single_env.regs[9]) = T1;
}
function op_movl_T0_r10()
{
    T0 = (cpu_single_env.regs[10]);
}
function op_movl_T1_r10()
{
    T1 = (cpu_single_env.regs[10]);
}
function op_movl_T2_r10()
{
    T2 = (cpu_single_env.regs[10]);
}
function op_movl_r10_T0()
{
    (cpu_single_env.regs[10]) = T0;
}
function op_movl_r10_T1()
{
    (cpu_single_env.regs[10]) = T1;
}
function op_movl_T0_r11()
{
    T0 = (cpu_single_env.regs[11]);
}
function op_movl_T1_r11()
{
    T1 = (cpu_single_env.regs[11]);
}
function op_movl_T2_r11()
{
    T2 = (cpu_single_env.regs[11]);
}
function op_movl_r11_T0()
{
    (cpu_single_env.regs[11]) = T0;
}
function op_movl_r11_T1()
{
    (cpu_single_env.regs[11]) = T1;
}
function op_movl_T0_r12()
{
    T0 = (cpu_single_env.regs[12]);
}
function op_movl_T1_r12()
{
    T1 = (cpu_single_env.regs[12]);
}
function op_movl_T2_r12()
{
    T2 = (cpu_single_env.regs[12]);
}
function op_movl_r12_T0()
{
    (cpu_single_env.regs[12]) = T0;
}
function op_movl_r12_T1()
{
    (cpu_single_env.regs[12]) = T1;
}
function op_movl_T0_r13()
{
    T0 = (cpu_single_env.regs[13]);
}
function op_movl_T1_r13()
{
    T1 = (cpu_single_env.regs[13]);
}
function op_movl_T2_r13()
{
    T2 = (cpu_single_env.regs[13]);
}
function op_movl_r13_T0()
{
    (cpu_single_env.regs[13]) = T0;
}
function op_movl_r13_T1()
{
    (cpu_single_env.regs[13]) = T1;
}
function op_movl_T0_r14()
{
    T0 = (cpu_single_env.regs[14]);
}
function op_movl_T1_r14()
{
    T1 = (cpu_single_env.regs[14]);
}
function op_movl_T2_r14()
{
    T2 = (cpu_single_env.regs[14]);
}
function op_movl_r14_T0()
{
    (cpu_single_env.regs[14]) = T0;
}
function op_movl_r14_T1()
{
    (cpu_single_env.regs[14]) = T1;
}
function op_movl_T0_r15()
{
    T0 = (cpu_single_env.regs[15]);
}
function op_movl_T1_r15()
{
    T1 = (cpu_single_env.regs[15]);
}
function op_movl_T2_r15()
{
    T2 = (cpu_single_env.regs[15]);
}
function op_movl_r15_T0()
{
    (cpu_single_env.regs[15]) = T0 & ~/* (uint32_t) */1;
}
function op_movl_r15_T1()
{
    (cpu_single_env.regs[15]) = T1 & ~/* (uint32_t) */1;
}
function op_bx_T0()
{
  cpu_single_env.regs[15] = T0 & ~/* (uint32_t) */1;
  cpu_single_env.thumb = (T0 & 1) != 0;
}
function op_movl_T0_0()
{
    T0 = 0;
}
function op_movl_T0_im(param1)
{
    //console.log("op_movl_T0_im 0x" + param1.toString(16));
    T0 = param1; //( gen_opparam_ptr[gen_opparam_ptr.length - 1]);
}
function op_movl_T1_im(param1)
{
    //console.log("op_movl_T1_im 0x" + param1.toString(16));
    T1 = param1; //(param1);
}
function op_mov_CF_T1()
{
    cpu_single_env.CF = (/* (uint32_t) */T1) >> 31;
}
function op_movl_T2_im(param1)
{
    T2 = param1;//(param1);
}
function op_addl_T1_im(param1)
{
    T1 += param1;//(param1);
}
function op_addl_T1_T2()
{
    T1 += T2;
}
function op_subl_T1_T2()
{
    T1 -= T2;
}
function op_addl_T0_T1()
{
    T0 += T1;
}
function op_addl_T0_T1_cc()
{
    var /* unsigned  int*/ src1;
    src1 = T0;
    T0 += T1;
    cpu_single_env.NZF = T0;
    cpu_single_env.CF = T0 < src1;
    cpu_single_env.VF = (src1 ^ T1 ^ -1) & (src1 ^ T0);
}
function op_adcl_T0_T1()
{
    T0 += T1 + cpu_single_env.CF;
}
function op_adcl_T0_T1_cc()
{
    var /* unsigned int */ src1;
    src1 = T0;
    if (!cpu_single_env.CF) {
        T0 += T1;
        cpu_single_env.CF = T0 < src1;
    } else {
        T0 += T1 + 1;
        cpu_single_env.CF = T0 <= src1;
    }
    cpu_single_env.VF = (src1 ^ T1 ^ -1) & (src1 ^ T0);
    cpu_single_env.NZF = T0;
    //
}
function op_subl_T0_T1() { 
    T0 = T0 - T1; 
} 

function op_subl_T0_T1_cc() 
{ 
    var /* unsigned int */ src1; 
    src1 = T0; T0 -= T1; 
    cpu_single_env.NZF = T0; 
    cpu_single_env.CF = src1 >= T1; 
    cpu_single_env.VF = (src1 ^ T1) & (src1 ^ T0);
    T0 = T0; 
} 
function op_sbcl_T0_T1() 
{ 
    T0 = T0 - T1 + cpu_single_env.CF - 1;
} 

function op_sbcl_T0_T1_cc() { 
    var /* unsigned int*/ src1; 
    src1 = T0; 
    if (!cpu_single_env.CF) 
    { 
        T0 = T0 - T1 - 1; 
        cpu_single_env.CF = src1 > T1;
    } else { 
        T0 = T0 - T1; 
        cpu_single_env.CF = src1 >= T1;
    } 
    cpu_single_env.VF = (src1 ^ T1) & (src1 ^ T0);
    cpu_single_env.NZF = T0; T0 = T0;
    /*  */
}
function op_rsbl_T0_T1()
{
    T0 = T1 - T0; 
} 
function op_rsbl_T0_T1_cc() 
{ 
    var /* unsigned int */ src1; 
    src1 = T1; 
    T1 -= T0; 
    cpu_single_env.NZF = T1; 
    cpu_single_env.CF = src1 >= T0;
    cpu_single_env.VF = (src1 ^ T0) & (src1 ^ T1);
    T0 = T1;
}
function op_rscl_T0_T1() 
{
    T0 = T1 - T0 + cpu_single_env.CF - 1;
} 
function op_rscl_T0_T1_cc() 
{
    var /* unsigned int */src1;
    src1 = T1; 
    if (!cpu_single_env.CF) { 
        T1 = T1 - T0 - 1;
        cpu_single_env.CF = src1 > T0;
    } else { 
        T1 = T1 - T0; 
        cpu_single_env.CF = src1 >= T0;
    } cpu_single_env.VF = (src1 ^ T0) & (src1 ^ T1);
    cpu_single_env.NZF = T1; 
    T0 = T1; /*  */ 
}
function op_andl_T0_T1()
{
    T0 &= T1;
}
function op_xorl_T0_T1()
{
    T0 ^= T1;
}
function op_orl_T0_T1()
{
    T0 |= T1;
}
function op_bicl_T0_T1()
{
    T0 &= ~T1;
}
function op_notl_T0()
{
    T0 = ~T0;
}
function op_notl_T1()
{
    T1 = ~T1;
}
function op_logic_T0_cc()
{
    cpu_single_env.NZF = T0;
}
function op_logic_T1_cc()
{
    cpu_single_env.NZF = T1;
}

function op_test_eq(param1)
{
    if (cpu_single_env.NZF == 0)
        cur_tb_op = gen_labels[param1];
        //asm volatile ("jmp " "__op_gen_label" "1");;
    
}
function op_test_ne(param1)
{
    if (cpu_single_env.NZF != 0)
         cur_tb_op = gen_labels[param1];
        //asm volatile ("jmp " "__op_gen_label" "1");;
}

function op_test_cs(param1)
{
    if (cpu_single_env.CF != 0)
        cur_tb_op = gen_labels[param1];
    
}
function op_test_cc(param1)
{
    if (cpu_single_env.CF == 0)
        cur_tb_op = gen_labels[param1];
    
}
function op_test_mi(param1)
{
    if ((cpu_single_env.NZF & 0x80000000) != 0)
       cur_tb_op = gen_labels[param1];
    
}
function op_test_pl(param1)
{
    if ((cpu_single_env.NZF & 0x80000000) == 0)
        cur_tb_op = gen_labels[param1];
    
}
function op_test_vs(param1)
{
    if ((cpu_single_env.VF & 0x80000000) != 0)
        cur_tb_op = gen_labels[param1];
    
}
function op_test_vc(param1)
{
    if ((cpu_single_env.VF & 0x80000000) == 0)
        cur_tb_op = gen_labels[param1];
    
}
function op_test_hi(param1)
{
   if (cpu_single_env.CF != 0 && cpu_single_env.NZF != 0)
        cur_tb_op = gen_labels[param1];
    
}
function op_test_ls(param1)
{
    if (cpu_single_env.CF == 0 || cpu_single_env.NZF == 0)
        cur_tb_op = gen_labels[param1];
    
}
function op_test_ge(param1)
{
    if (((cpu_single_env.VF ^ cpu_single_env.NZF) & 0x80000000) == 0)
        cur_tb_op = gen_labels[param1];
    
}
function op_test_lt(param1)
{
    if (((cpu_single_env.VF ^ cpu_single_env.NZF) & 0x80000000) != 0)
        cur_tb_op = gen_labels[param1];
    
}
function op_test_gt(param1)
{
    if (cpu_single_env.NZF != 0 && ((cpu_single_env.VF ^ cpu_single_env.NZF) & 0x80000000) == 0)
        cur_tb_op = gen_labels[param1];
    
}
function gen_set_condexec (s)
{
    if (s.condexec_mask) {
        gen_op_set_condexec((s.condexec_cond << 4) | (s.condexec_mask >> 1));
    }
}

function op_test_le(param1)
{
    if (cpu_single_env.NZF == 0 || ((cpu_single_env.VF ^ cpu_single_env.NZF) & 0x80000000) != 0)
        cur_tb_op = gen_labels[param1];
    
}
function op_test_T0()
{
    if (T0)
        cur_tb_op = gen_labels[param1];
    
}
function op_testn_T0()
{
    if (!T0)
        cur_tb_op = gen_labels[param1];
    
}
function op_goto_tb0()
{
    console.log("op_goto_tb0 - not implemented");
    //do { 
    //  static void __attribute__((used)) 
    //  *dummy0 = &&dummy_label0; 
    //  static void __attribute__((used))
    //   *__op_label0 __asm__("__op_label" "0" "." "op_goto_tb0") = &&label0; 
    //   goto *(void *)(((TranslationBlock *)(param1))->tb_next[0]);label0:
    //    ;dummy_label0: ;} while (0);
}
function op_goto_tb1()
{
    console.log("op_goto_tb1 - not implemented");
    //do { static void __attribute__((used)) *dummy1 = &&dummy_label1; static void __attribute__((used)) *__op_label1 __asm__("__op_label" "1" "." "op_goto_tb1") = &&label1; goto *(void *)(((TranslationBlock *)(param1))->tb_next[1]);label1: ;dummy_label1: ;} while (0);
}
function op_exit_tb()
{
    console.log("op_exit_tb - not implemented");
    //asm volatile ("ret");
}
function op_movl_T0_cpsr()
{
    T0 = cpsr_read(cpu_single_env) & ~((1 << 5) | ((3 << 25) | (0xfc00)) | (1 << 24));
    
}
function op_movl_T0_spsr()
{
    T0 = cpu_single_env.spsr;
}
function op_movl_spsr_T0(param1)
{
    var /* uint32_t */ mask = (param1) >>> 0;
    cpu_single_env.spsr = (cpu_single_env.spsr & ~mask) | (T0 & mask);
}
function op_movl_cpsr_T0(param1)
{
    cpsr_write(cpu_single_env, T0, (param1));
    
}
function op_mul_T0_T1()
{
    T0 = T0 * T1;
}
function op_mull_T0_T1()
{
    var /* uint64_t */ res;
    res = T0 * T1;
    T1 = res >> 32;
    T0 = res;
}
function op_imull_T0_T1()
{
    var /* uint64_t */ res;
    res = (T0) * (T1);
    T1 = res >> 32;
    T0 = res;
}
function op_imulw_T0_T1()
{
  var /* uint64_t */ res;
  res = (T0) * /* (int64_t) */(/* (int32_t) */T1);
  T0 = res >> 16;
}
function op_addq_T0_T1(param1, param2)
{
    var /* uint64_t */ res;
    res = (/* (uint64_t) */T1 << 32) | T0;
    res += ((cpu_single_env.regs[param2]) << 32) | (cpu_single_env.regs[param1]);
    T1 = res >> 32;
    T0 = res;
}
function op_addq_lo_T0_T1()
{
    var /* uint64_t */ res;
    res = (/* (uint64_t) */T1 << 32) | T0;
    res += /* (uint64_t) */(cpu_single_env.regs[(param1)]);
    T1 = res >> 32;
    T0 = res;
}
function op_addq_T0_T1_dual(param1, param2)
{
  var /* uint64_t  */ res;
  res = (/* (uint64_t) */(cpu_single_env.regs[param2]) << 32) | (cpu_single_env.regs[param1]);
  res += /* (int32_t) */T0;
  res += /* (int32_t) */T1;
  cpu_single_env.regs[param1] = /* (uint32_t) */res;
  cpu_single_env.regs[param2] = res >> 32;
}
function op_subq_T0_T1_dual(param1, param2)
{
  var /* uint64_t */ res;
  res = (/* (uint64_t) */(cpu_single_env.regs[param2]) << 32) | (cpu_single_env.regs[param1]);
  res += /* (int32_t) */T0;
  res -= /* (int32_t) */T1;
  cpu_single_env.regs[param1] = /* (uint32_t) */res;
  cpu_single_env.regs[param2] = res >> 32;
}
function op_logicq_cc()
{
    cpu_single_env.NZF = (T1 & 0x80000000) | ((T0 | T1) != 0);
}
function op_ldl_kernel()
{
    T0 = ld32_phys(T1) >>> 0;
}
function stl_kernel(address, data)
{
    st32_phys(address, data);    
}

function helper_get_cp(env, insn)
{
    var op1 = (insn >>> 8) & 0xf;
    cpu_abort(env, "cp%i insn %08x\n", op1, insn);
    return 0;
}

/*
function op_ldub_raw() { T0 = ldub_p((uint8_t *)((T1)));  }
function op_ldsb_raw() { T0 = ldsb_p((uint8_t *)((T1)));  }
function op_lduw_raw() { T0 = lduw_le_p((uint8_t *)((T1)));  }
function op_ldsw_raw() { T0 = ldsw_le_p((uint8_t *)((T1)));  }
function op_ldl_raw() { T0 = ldl_le_p((uint8_t *)((T1)));  }
function op_stb_raw() { stb_p((uint8_t *)((T1)), T0);  }
function op_stw_raw() { stw_le_p((uint8_t *)((T1)), T0);  }
function op_stl_raw() { stl_le_p((uint8_t *)((T1)), T0);  }
function op_swpb_raw() { uint32_t tmp; cpu_lock(); tmp = ldub_p((uint8_t *)((T1))); stb_p((uint8_t *)((T1)), T0); T0 = tmp; cpu_unlock();  }
function op_swpl_raw() { uint32_t tmp; cpu_lock(); tmp = ldl_le_p((uint8_t *)((T1))); stl_le_p((uint8_t *)((T1)), T0); T0 = tmp; cpu_unlock();  }
function op_ldbex_raw() { cpu_lock(); helper_mark_exclusive(env, T1); T0 = ldub_p((uint8_t *)((T1))); cpu_unlock();  } void op_stbex_raw() { int failed; cpu_lock(); failed = helper_test_exclusive(env, T1); if (!failed) { stb_p((uint8_t *)((T1)), T0); } T0 = failed; cpu_unlock();  }
function op_ldwex_raw() { cpu_lock(); helper_mark_exclusive(env, T1); T0 = lduw_le_p((uint8_t *)((T1))); cpu_unlock();  } void op_stwex_raw() { int failed; cpu_lock(); failed = helper_test_exclusive(env, T1); if (!failed) { stw_le_p((uint8_t *)((T1)), T0); } T0 = failed; cpu_unlock();  }
function op_ldlex_raw() { cpu_lock(); helper_mark_exclusive(env, T1); T0 = ldl_le_p((uint8_t *)((T1))); cpu_unlock();  } void op_stlex_raw() { int failed; cpu_lock(); failed = helper_test_exclusive(env, T1); if (!failed) { stl_le_p((uint8_t *)((T1)), T0); } T0 = failed; cpu_unlock();  }
function op_ldqex_raw()
{
    cpu_lock();
    helper_mark_exclusive(env, T1);
    T0 = ldl_le_p((uint8_t *)((T1)));
    T1 = ldl_le_p((uint8_t *)(((T1 + 4))));
    cpu_unlock();
    
}
function op_stqex_raw()
{
    int failed;
    cpu_lock();
    failed = helper_test_exclusive(env, T1);
    if (!failed) {
        stl_le_p((uint8_t *)((T1)), T0);
        stl_le_p((uint8_t *)(((T1 + 4))), T2);
    }
    T0 = failed;
    cpu_unlock();
    
}
function op_vfp_lds_raw() { cpu_single_env.vfp.tmp0s = ldfl_le_p((uint8_t *)((T1)));  } void op_vfp_sts_raw() { stfl_le_p((uint8_t *)((T1)), cpu_single_env.vfp.tmp0s);  }
function op_vfp_ldd_raw() { cpu_single_env.vfp.tmp0d = ldfq_le_p((uint8_t *)((T1)));  } void op_vfp_std_raw() { stfq_le_p((uint8_t *)((T1)), cpu_single_env.vfp.tmp0d);  }
function op_iwmmxt_ldb_raw() { cpu_single_env.iwmmxt.val = ldub_p((uint8_t *)((T1)));  } void op_iwmmxt_stb_raw() { stb_p((uint8_t *)((T1)), cpu_single_env.iwmmxt.val);  }
function op_iwmmxt_ldw_raw() { cpu_single_env.iwmmxt.val = lduw_le_p((uint8_t *)((T1)));  } void op_iwmmxt_stw_raw() { stw_le_p((uint8_t *)((T1)), cpu_single_env.iwmmxt.val);  }
function op_iwmmxt_ldl_raw() { cpu_single_env.iwmmxt.val = ldl_le_p((uint8_t *)((T1)));  } void op_iwmmxt_stl_raw() { stl_le_p((uint8_t *)((T1)), cpu_single_env.iwmmxt.val);  }
function op_iwmmxt_ldq_raw() { cpu_single_env.iwmmxt.val = ldq_le_p((uint8_t *)((T1)));  } void op_iwmmxt_stq_raw() { stq_le_p((uint8_t *)((T1)), cpu_single_env.iwmmxt.val);  }
void helper_ld/* (uint32_t);
function op_ldub_user() { T0 = ldub_user(T1);  }
function op_ldsb_user() { T0 = ldsb_user(T1);  }
function op_lduw_user() { T0 = lduw_user(T1);  }
function op_ldsw_user() { T0 = ldsw_user(T1);  }
function op_ldl_user() { T0 = ldl_user(T1);  }
function op_stb_user() { stb_user(T1, T0);  }
function op_stw_user() { stw_user(T1, T0);  }
function op_stl_user() { stl_user(T1, T0);  }
function op_swpb_user() { uint32_t tmp; cpu_lock(); tmp = ldub_user(T1); stb_user(T1, T0); T0 = tmp; cpu_unlock();  }
function op_swpl_user() { uint32_t tmp; cpu_lock(); tmp = ldl_user(T1); stl_user(T1, T0); T0 = tmp; cpu_unlock();  }
function op_ldbex_user() { cpu_lock(); helper_mark_exclusive(env, T1); T0 = ldub_user(T1); cpu_unlock();  } void op_stbex_user() { int failed; cpu_lock(); failed = helper_test_exclusive(env, T1); if (!failed) { stb_user(T1, T0); } T0 = failed; cpu_unlock();  }
function op_ldwex_user() { cpu_lock(); helper_mark_exclusive(env, T1); T0 = lduw_user(T1); cpu_unlock();  } void op_stwex_user() { int failed; cpu_lock(); failed = helper_test_exclusive(env, T1); if (!failed) { stw_user(T1, T0); } T0 = failed; cpu_unlock();  }
function op_ldlex_user() { cpu_lock(); helper_mark_exclusive(env, T1); T0 = ldl_user(T1); cpu_unlock();  } void op_stlex_user() { int failed; cpu_lock(); failed = helper_test_exclusive(env, T1); if (!failed) { stl_user(T1, T0); } T0 = failed; cpu_unlock();  }
function op_ldqex_user()
{
    cpu_lock();
    helper_mark_exclusive(env, T1);
    T0 = ldl_user(T1);
    T1 = ldl_user((T1 + 4));
    cpu_unlock();
    
}

function op_stqex_user()
{
    int failed;
    cpu_lock();
    failed = helper_test_exclusive(env, T1);
    if (!failed) {
        stl_user(T1, T0);
        stl_user((T1 + 4), T2);
    }
    T0 = failed;
    cpu_unlock();
    
}

function op_vfp_lds_user() { cpu_single_env.vfp.tmp0s = ldfl_user(T1);  } void op_vfp_sts_user() { stfl_user(T1, cpu_single_env.vfp.tmp0s);  }
function op_vfp_ldd_user() { cpu_single_env.vfp.tmp0d = ldfq_user(T1);  } void op_vfp_std_user() { stfq_user(T1, cpu_single_env.vfp.tmp0d);  }
function op_iwmmxt_ldb_user() { cpu_single_env.iwmmxt.val = ldub_user(T1);  } void op_iwmmxt_stb_user() { stb_user(T1, cpu_single_env.iwmmxt.val);  }
function op_iwmmxt_ldw_user() { cpu_single_env.iwmmxt.val = lduw_user(T1);  } void op_iwmmxt_stw_user() { stw_user(T1, cpu_single_env.iwmmxt.val);  }
function op_iwmmxt_ldl_user() { cpu_single_env.iwmmxt.val = ldl_user(T1);  } void op_iwmmxt_stl_user() { stl_user(T1, cpu_single_env.iwmmxt.val);  }
function op_iwmmxt_ldq_user() { cpu_single_env.iwmmxt.val = ldq_user(T1);  } void op_iwmmxt_stq_user() { stq_user(T1, cpu_single_env.iwmmxt.val);  }
void helper_ld;
*/
function op_ldub_kernel() 
{
    T0 = ldub_kernel(T1);  
}
function op_ldsb_kernel() 
{
    T0 = ldsb_kernel(T1);  
}
function op_lduw_kernel() 
{ 
    T0 = lduw_kernel(T1);  
}
function op_ldsw_kernel() 
{ 
    T0 = ldsw_kernel(T1);  
}
function op_stb_kernel() 
{ 
    stb_kernel(T1, T0); 
}
function op_stw_kernel() 
{ 
    stw_kernel(T1, T0);  
}
function op_stl_kernel() 
{ 
    stl_kernel(T1, T0);  
}
function op_swpb_kernel() 
{ 
    var tmp; 
    //cpu_lock(); 
    tmp = ldub_kernel(T1); 
    stb_kernel(T1, T0); 
    T0 = tmp; 
    //cpu_unlock(); 
}
//function op_swpl_kernel() { uint32_t tmp; cpu_lock(); tmp = ldl_kernel(T1); stl_kernel(T1, T0); T0 = tmp; cpu_unlock();  }
//function op_ldbex_kernel() { cpu_lock(); helper_mark_exclusive(env, T1); T0 = ldub_kernel(T1); cpu_unlock();  } void op_stbex_kernel() { int failed; cpu_lock(); failed = helper_test_exclusive(env, T1); if (!failed) { stb_kernel(T1, T0); } T0 = failed; cpu_unlock();  }
//function op_ldwex_kernel() { cpu_lock(); helper_mark_exclusive(env, T1); T0 = lduw_kernel(T1); cpu_unlock();  } void op_stwex_kernel() { int failed; cpu_lock(); failed = helper_test_exclusive(env, T1); if (!failed) { stw_kernel(T1, T0); } T0 = failed; cpu_unlock();  }
//function op_ldlex_kernel() { cpu_lock(); helper_mark_exclusive(env, T1); T0 = ldl_kernel(T1); cpu_unlock();  } void op_stlex_kernel() { int failed; cpu_lock(); failed = helper_test_exclusive(env, T1); if (!failed) { stl_kernel(T1, T0); } T0 = failed; cpu_unlock();  }

/*
function op_ldqex_kernel()
{
    cpu_lock();
    helper_mark_exclusive(env, T1);
    T0 = ldl_kernel(T1);
    T1 = ldl_kernel((T1 + 4));
    cpu_unlock();
    
}
function op_stqex_kernel()
{
    int failed;
    cpu_lock();
    failed = helper_test_exclusive(env, T1);
    if (!failed) {
        stl_kernel(T1, T0);
        stl_kernel((T1 + 4), T2);
    }
    T0 = failed;
    cpu_unlock();
    
}
function op_vfp_lds_kernel() { cpu_single_env.vfp.tmp0s = ldfl_kernel(T1);  } void op_vfp_sts_kernel() { stfl_kernel(T1, cpu_single_env.vfp.tmp0s);  }
function op_vfp_ldd_kernel() { cpu_single_env.vfp.tmp0d = ldfq_kernel(T1);  } void op_vfp_std_kernel() { stfq_kernel(T1, cpu_single_env.vfp.tmp0d);  }
function op_iwmmxt_ldb_kernel() { cpu_single_env.iwmmxt.val = ldub_kernel(T1);  } void op_iwmmxt_stb_kernel() { stb_kernel(T1, cpu_single_env.iwmmxt.val);  }
function op_iwmmxt_ldw_kernel() { cpu_single_env.iwmmxt.val = lduw_kernel(T1);  } void op_iwmmxt_stw_kernel() { stw_kernel(T1, cpu_single_env.iwmmxt.val);  }
function op_iwmmxt_ldl_kernel() { cpu_single_env.iwmmxt.val = ldl_kernel(T1);  } void op_iwmmxt_stl_kernel() { stl_kernel(T1, cpu_single_env.iwmmxt.val);  }
function op_iwmmxt_ldq_kernel() { cpu_single_env.iwmmxt.val = ldq_kernel(T1);  } void op_iwmmxt_stq_kernel() { stq_kernel(T1, cpu_single_env.iwmmxt.val);  }
*/
function op_clrex()
{
    cpu_lock();
    helper_clrex(env);
    cpu_unlock();
}
function op_shll_T0_im(param1)
{
    T1 = T1 << (param1);
}
function op_shll_T1_im(param1)
{
    T1 = T1 << (param1);
}
function op_shrl_T1_im(param1)
{
    T1 = /* (uint32_t) */T1 >> (param1);
}
function op_shrl_T1_0()
{
    T1 = 0;
}
function op_sarl_T1_im(param1)
{
    T1 = /* (int32_t) */T1 >> (param1);
}
function op_sarl_T1_0()
{
    T1 = /* (int32_t) */T1 >> 31;
}
function op_rorl_T1_im(param1)
{
    var shift;
    shift = (param1);
    T1 = (/* (uint32_t) */T1 >> shift) | (T1 << (32 - shift));
}
function op_rrxl_T1()
{
    T1 = (/* (uint32_t) */T1 >> 1) | (/* (uint32_t) */cpu_single_env.CF << 31);
}
function op_shll_T1_im_cc(param1)
{
    cpu_single_env.CF = (T1 >>> (32 - param1)) & 1;
    T1 = T1 << param1;
}
function op_shrl_T1_im_cc(param1)
{
    cpu_single_env.CF = (T1 >> (param1 - 1)) & 1;
    T1 = /* (uint32_t) */T1 >> (param1);
}
function op_shrl_T1_0_cc()
{
    cpu_single_env.CF = (T1 >> 31) & 1;
    T1 = 0;
}
function op_sarl_T1_im_cc(param1)
{
    cpu_single_env.CF = (T1 >> ((param1) - 1)) & 1;
    T1 = /* (int32_t) */T1 >> (param1);
}
function op_sarl_T1_0_cc()
{
    cpu_single_env.CF = (T1 >> 31) & 1;
    T1 = /* (int32_t) */T1 >> 31;
}
function op_rorl_T1_im_cc(param1)
{
    var shift;
    shift = (param1);
    cpu_single_env.CF = (T1 >> (shift - 1)) & 1;
    T1 = (/* (uint32_t) */T1 >> shift) | (T1 << (32 - shift));
}
function op_rrxl_T1_cc()
{
    var c;
    c = T1 & 1;
    T1 = (/* (uint32_t) */T1 >> 1) | (/* (uint32_t) */cpu_single_env.CF << 31);
    cpu_single_env.CF = c;
}
function op_shll_T2_im(param1)
{
    T2 = T2 << (param1);
}
function op_shrl_T2_im()
{
    T2 = /* (uint32_t) */T2 >> (param1);
}
function op_shrl_T2_0()
{
    T2 = 0;
}
function op_sarl_T2_im(param1)
{
    T2 = /* (int32_t) */T2 >> (param1);
}
function op_sarl_T2_0()
{
    T2 = /* (int32_t) */T2 >>> 31;
}
function op_rorl_T2_im(param1)
{
    var shift;
    shift = (param1);
    T2 = (/* (uint32_t) */T2 >> shift) | (T2 << (32 - shift));
}
function op_rrxl_T2()
{
    T2 = (/* (uint32_t) */T2 >>> 1) | (/* (uint32_t) */cpu_single_env.CF << 31);
}
function op_shll_T1_T0()
{
    var shift;
    shift = T0 & 0xff;
    if (shift >= 32)
        T1 = 0;
    else
        T1 = T1 << shift;
    
}
function op_shrl_T1_T0()
{
    var shift;
    shift = T0 & 0xff;
    if (shift >= 32)
        T1 = 0;
    else
        T1 = /* (uint32_t) */T1 >> shift;
    
}
function op_sarl_T1_T0()
{
    var shift;
    shift = T0 & 0xff;
    if (shift >= 32)
        shift = 31;
    T1 = /* (int32_t) */T1 >> shift;
}
function op_rorl_T1_T0()
{
    var shift;
    shift = T0 & 0x1f;
    if (shift) {
        T1 = (/* (uint32_t) */T1 >> shift) | (T1 << (32 - shift));
    }
    
}
function op_shll_T1_T0_cc()
{
    var shift;
    shift = T0 & 0xff;
    if (shift >= 32) {
        if (shift == 32)
            cpu_single_env.CF = T1 & 1;
        else
            cpu_single_env.CF = 0;
        T1 = 0;
    } else if (shift != 0) {
        cpu_single_env.CF = (T1 >> (32 - shift)) & 1;
        T1 = T1 << shift;
    }
    
}
function op_shrl_T1_T0_cc()
{
    var shift;
    shift = T0 & 0xff;
    if (shift >= 32) {
        if (shift == 32)
            cpu_single_env.CF = (T1 >> 31) & 1;
        else
            cpu_single_env.CF = 0;
        T1 = 0;
    } else if (shift != 0) {
        cpu_single_env.CF = (T1 >> (shift - 1)) & 1;
        T1 = /* (uint32_t) */T1 >> shift;
    }
    
}
function op_sarl_T1_T0_cc()
{
    var shift;
    shift = T0 & 0xff;
    if (shift >= 32) {
        cpu_single_env.CF = (T1 >> 31) & 1;
        T1 = /* (int32_t) */T1 >> 31;
    } else if (shift != 0) {
        cpu_single_env.CF = (T1 >> (shift - 1)) & 1;
        T1 = /* (int32_t) */T1 >> shift;
    }
    
}
function op_rorl_T1_T0_cc()
{
    var shift1, shift;
    shift1 = T0 & 0xff;
    shift = shift1 & 0x1f;
    if (shift == 0) {
        if (shift1 != 0)
            cpu_single_env.CF = (T1 >>> 31) & 1;
    } else {
        cpu_single_env.CF = (T1 >>> (shift - 1)) & 1;
        T1 = (/* (uint32_t) */T1 >>> shift) | (T1 << (32 - shift));
    }
    
}
function op_clz_T0()
{
    var count;
    for (count = 32; T0 >>> 0; count--)
        T0 = T0 >>> 1;
    T0 = count;
    
}
function op_sarl_T0_im(param1)
{
    T0 = /* (int32_t) */T0 >>> param1;
}
function op_sxth_T0()
{
  T0 = T0;
}
function op_sxth_T1()
{
  T1 = T1;
}
function op_sxtb_T1()
{
    T1 = T1;
}
function op_uxtb_T1()
{
    T1 = T1;
}
function op_uxth_T1()
{
    T1 = T1;
}
function op_sxtb16_T1()
{
    var res;
    res = T1;
    res |= /* (uint32_t) */(T1 >> 16) << 16;
    T1 = res;
}
function op_uxtb16_T1()
{
    var res;
    res = T1;
    res |= /* (uint32_t) */(T1 >> 16) << 16;
    T1 = res;
}
function op_addl_T0_T1_setq()
{
  var res;
  res = (T0 >>>0) + (T1 >>> 0);
  if (((res ^ T0) & /* (uint32_t) */0x80000000) && !((T0 ^ T1) & /* (uint32_t) */0x80000000))
      cpu_single_env.QF = 1;
  T0 = res;
  
}
function op_addl_T0_T1_saturate()
{
  var res;
  res = (T0 >>>0) + (T1 >>> 0);
  if (((res ^ T0) & /* (uint32_t) */0x80000000) && !((T0 ^ T1) & /* (uint32_t) */0x80000000)) {
      cpu_single_env.QF = 1;
      if (T0 & /* (uint32_t) */0x80000000)
          T0 = 0x80000000;
      else
          T0 = 0x7fffffff;
  }
  else
    T0 = res;
  
}
function op_subl_T0_T1_saturate()
{
  var res;
  res = (T0 >>>0) - (T1 >>> 0);
  if (((res ^ T0) & /* (uint32_t) */0x80000000) && ((T0 ^ T1) & /* (uint32_t) */0x80000000)) {
      cpu_single_env.QF = 1;
      if (T0 & /* (uint32_t) */0x80000000)
          T0 = 0x80000000 >>> 0;
      else
          T0 = 0x7fffffff >>> 0;
  }
  else
    T0 = res;
  
}
function op_double_T1_saturate()
{
  var val;
  val = T1;
  if (val >= 0x40000000) {
      T1 = 0x7fffffff;
      cpu_single_env.QF = 1;
  } else if (val <= /* (int32_t) */0xc0000000) {
      T1 = 0x80000000;
      cpu_single_env.QF = 1;
  } else {
      T1 = val << 1;
  }
  
}
function op_addl_T0_T1_usaturate()
{
  var res;
  res = T0 + T1;
  if (res < T0) {
      cpu_single_env.QF = 1;
      T0 = 0xffffffff;
  } else {
      T0 = res;
  }
  
}
function op_subl_T0_T1_usaturate()
{
  var res;
  res = T0 - T1;
  if (res > T0) {
      cpu_single_env.QF = 1;
      T0 = 0;
  } else {
      T0 = res;
  }
  
}
function op_shll_T0_im_thumb_cc(param1)
{
    var shift;
    shift = param1;
    if (shift != 0) {
           cpu_single_env.CF = (T0 >>> (32 - shift)) & 1;
            T0 = T0 << shift;
    }
    cpu_single_env.NZF = T0;
    
}
function op_shll_T0_im_thumb(param1)
{
    T0 = T0 << param1;
    
}
function op_shrl_T0_im_thumb_cc(param1)
{
    var shift;
    shift = param1;
    if (shift == 0) {
        cpu_single_env.CF = (/* (uint32_t) */T0) >> 31;
        T0 = 0;
    } else {
        cpu_single_env.CF = (T0 >> (shift - 1)) & 1;
        T0 = T0 >> shift;
    }
    cpu_single_env.NZF = T0;
    
}
function op_shrl_T0_im_thumb(param1)
{
    var shift;
    shift = param1;
    if (shift == 0) {
        T0 = 0;
    } else {
        T0 = T0 >> shift;
    }
    
}
function op_sarl_T0_im_thumb_cc(param1)
{
    var shift;
    shift = param1;
    if (shift == 0) {
        T0 = (/* (int32_t) */T0) >> 31;
        cpu_single_env.CF = T0 & 1;
    } else {
        cpu_single_env.CF = (T0 >> (shift - 1)) & 1;
        T0 = (/* (int32_t) */T0) >> shift;
    }
    cpu_single_env.NZF = T0;
    
}
function op_sarl_T0_im_thumb(param1)
{
    var shift;
    shift = param1;
    if (shift == 0) {
        cpu_single_env.CF = T0 & 1;
    } else {
        T0 = (/* (int32_t) */T0) >> shift;
    }
    
}
function op_swi()
{
    cpu_single_env.exception_index = 2;
    cpu_loop_exit();
}
function op_undef_insn()
{
    cpu_single_env.exception_index = 1;
    cpu_loop_exit();
}
function op_debug()
{
    cpu_single_env.exception_index = 0x10002;
    cpu_loop_exit();
}
function op_wfi()
{
    cpu_single_env.exception_index = 0x10001;
    cpu_single_env.halted = 1;
    cpu_loop_exit();
}
function op_bkpt()
{
    cpu_single_env.exception_index = 7;
    cpu_loop_exit();
}
function op_exception_exit()
{
    cpu_single_env.exception_index = 8;
    cpu_loop_exit();
}
/*
function op_vfp_adds() { cpu_single_env.vfp.tmp0s = float32_add (cpu_single_env.vfp.tmp0s, cpu_single_env.vfp.tmp1s, &cpu_single_env.vfp.fp_status); } void op_vfp_addd() { cpu_single_env.vfp.tmp0d = float64_add (cpu_single_env.vfp.tmp0d, cpu_single_env.vfp.tmp1d, &cpu_single_env.vfp.fp_status); }
function op_vfp_subs() { cpu_single_env.vfp.tmp0s = float32_sub (cpu_single_env.vfp.tmp0s, cpu_single_env.vfp.tmp1s, &cpu_single_env.vfp.fp_status); } void op_vfp_subd() { cpu_single_env.vfp.tmp0d = float64_sub (cpu_single_env.vfp.tmp0d, cpu_single_env.vfp.tmp1d, &cpu_single_env.vfp.fp_status); }
function op_vfp_muls() { cpu_single_env.vfp.tmp0s = float32_mul (cpu_single_env.vfp.tmp0s, cpu_single_env.vfp.tmp1s, &cpu_single_env.vfp.fp_status); } void op_vfp_muld() { cpu_single_env.vfp.tmp0d = float64_mul (cpu_single_env.vfp.tmp0d, cpu_single_env.vfp.tmp1d, &cpu_single_env.vfp.fp_status); }
function op_vfp_divs() { cpu_single_env.vfp.tmp0s = float32_div (cpu_single_env.vfp.tmp0s, cpu_single_env.vfp.tmp1s, &cpu_single_env.vfp.fp_status); } void op_vfp_divd() { cpu_single_env.vfp.tmp0d = float64_div (cpu_single_env.vfp.tmp0d, cpu_single_env.vfp.tmp1d, &cpu_single_env.vfp.fp_status); }
function op_vfp_abss() { do_vfp_abss(); } void op_vfp_absd() { do_vfp_absd(); }
function op_vfp_sqrts() { do_vfp_sqrts(); } void op_vfp_sqrtd() { do_vfp_sqrtd(); }
function op_vfp_cmps() { do_vfp_cmps(); } void op_vfp_cmpd() { do_vfp_cmpd(); }
function op_vfp_cmpes() { do_vfp_cmpes(); } void op_vfp_cmped() { do_vfp_cmped(); }
function op_vfp_negs()
{
    cpu_single_env.vfp.tmp0s = float32_chs(cpu_single_env.vfp.tmp0s);
}
function op_vfp_negd()
{
    cpu_single_env.vfp.tmp0d = float64_chs(cpu_single_env.vfp.tmp0d);
}
function op_vfp_F1_ld0s()
{
    union {
        uint32_t i;
        float32 s;
    } v;
    v.i = 0;
    cpu_single_env.vfp.tmp1s = v.s;
}
function op_vfp_F1_ld0d()
{
    union {
        uint64_t i;
        float64 d;
    } v;
    v.i = 0;
    cpu_single_env.vfp.tmp1d = v.d;
}
function float32 vfp_itos(uint32_t i)
{
    union {
        uint32_t i;
        float32 s;
    } v;
    v.i = i;
    return v.s;
}
function uint32_t vfp_stoi(float32 s)
{
    union {
        uint32_t i;
        float32 s;
    } v;
    v.s = s;
    return v.i;
}
function float64 vfp_itod(uint64_t i)
{
    union {
        uint64_t i;
        float64 d;
    } v;
    v.i = i;
    return v.d;
}
function uint64_t vfp_dtoi(float64 d)
{
    union {
        uint64_t i;
        float64 d;
    } v;
    v.d = d;
    return v.i;
}
function op_vfp_uitos()
{
    cpu_single_env.vfp.tmp0s = uint32_to_float32(vfp_stoi(cpu_single_env.vfp.tmp0s), &cpu_single_env.vfp.fp_status);
}
function op_vfp_uitod()
{
    cpu_single_env.vfp.tmp0d = uint32_to_float64(vfp_stoi(cpu_single_env.vfp.tmp0s), &cpu_single_env.vfp.fp_status);
}
function op_vfp_sitos()
{
    cpu_single_env.vfp.tmp0s = int32_to_float32(vfp_stoi(cpu_single_env.vfp.tmp0s), &cpu_single_env.vfp.fp_status);
}
function op_vfp_sitod()
{
    cpu_single_env.vfp.tmp0d = int32_to_float64(vfp_stoi(cpu_single_env.vfp.tmp0s), &cpu_single_env.vfp.fp_status);
}
function op_vfp_touis()
{
    cpu_single_env.vfp.tmp0s = vfp_itos(float32_to_uint32(cpu_single_env.vfp.tmp0s, &cpu_single_env.vfp.fp_status));
}
function op_vfp_touid()
{
    cpu_single_env.vfp.tmp0s = vfp_itos(float64_to_uint32(cpu_single_env.vfp.tmp0d, &cpu_single_env.vfp.fp_status));
}
function op_vfp_tosis()
{
    cpu_single_env.vfp.tmp0s = vfp_itos(float32_to_int32(cpu_single_env.vfp.tmp0s, &cpu_single_env.vfp.fp_status));
}
function op_vfp_tosid()
{
    cpu_single_env.vfp.tmp0s = vfp_itos(float64_to_int32(cpu_single_env.vfp.tmp0d, &cpu_single_env.vfp.fp_status));
}
function op_vfp_touizs()
{
    cpu_single_env.vfp.tmp0s = vfp_itos(float32_to_uint32_round_to_zero(cpu_single_env.vfp.tmp0s, &cpu_single_env.vfp.fp_status));
}
function op_vfp_touizd()
{
    cpu_single_env.vfp.tmp0s = vfp_itos(float64_to_uint32_round_to_zero(cpu_single_env.vfp.tmp0d, &cpu_single_env.vfp.fp_status));
}
function op_vfp_tosizs()
{
    cpu_single_env.vfp.tmp0s = vfp_itos(float32_to_int32_round_to_zero(cpu_single_env.vfp.tmp0s, &cpu_single_env.vfp.fp_status));
}
function op_vfp_tosizd()
{
    cpu_single_env.vfp.tmp0s = vfp_itos(float64_to_int32_round_to_zero(cpu_single_env.vfp.tmp0d, &cpu_single_env.vfp.fp_status));
}
function op_vfp_fcvtds()
{
    cpu_single_env.vfp.tmp0d = float32_to_float64(cpu_single_env.vfp.tmp0s, &cpu_single_env.vfp.fp_status);
}
function op_vfp_fcvtsd()
{
    cpu_single_env.vfp.tmp0s = float64_to_float32(cpu_single_env.vfp.tmp0d, &cpu_single_env.vfp.fp_status);
}
*/

function op_signbit_T1_T0()
{
    T1 = /* (int32_t) */T0 >>> 31;
}
function op_movl_cp_T0(param1)
{
    helper_set_cp(cpu_single_env, (param1), T0);
    
}
function op_movl_T0_cp(param1)
{
    T0 = helper_get_cp(cpu_single_env, param1);
    
}
function op_movl_cp15_T0(param1)
{
    helper_set_cp15(cpu_single_env, param1, T0);
    
}
function op_movl_T0_cp15(param1)
{
    T0 = helper_get_cp15(cpu_single_env, param1);
    
}
function op_movl_T0_user(param1)
{
    var regno = (param1);
    if (regno == 13) {
        T0 = cpu_single_env.banked_r13[0];
    } else if (regno == 14) {
        T0 = cpu_single_env.banked_r14[0];
    } else if ((cpu_single_env.uncached_cpsr & 0x1f) == ARM_CPU_MODE_FIQ) {
        T0 = cpu_single_env.usr_regs[regno - 8];
    } else {
        T0 = cpu_single_env.regs[regno];
    }
    
}
function op_movl_user_T0(param1)
{
    var regno = (param1);
    if (regno == 13) {
        cpu_single_env.banked_r13[0] = T0;
    } else if (regno == 14) {
        cpu_single_env.banked_r14[0] = T0;
    } else if ((cpu_single_env.uncached_cpsr & 0x1f) == ARM_CPU_MODE_FIQ) {
        cpu_single_env.usr_regs[regno - 8] = T0;
    } else {
        cpu_single_env.regs[regno] = T0;
    }
    
}
function op_movl_T0_T1()
{
    T0 = T1;
}
function op_movl_T0_T2()
{
    T0 = T2;
}
function op_movl_T1_T0()
{
    T1 = T0;
}
function op_movl_T1_T2()
{
    T1 = T2;
}
function op_movl_T2_T0()
{
    T2 = T0;
}
function add16_sat( a, b)
{
    var res;
    res = a + b;
    if (((res ^ a) & 0x8000) && !((a ^ b) & 0x8000)) {
        if (a & 0x8000)
            res = 0x8000;
        else
            res = 0x7fff;
    }
    return res;
}
function add8_sat(a, b)
{
    var res;
    res = a + b;
    if (((res ^ a) & 0x80) && !((a ^ b) & 0x80)) {
        if (a & 0x80)
            res = 0x80;
        else
            res = 0x7f;
    }
    return res;
}
function sub16_sat(a, b)
{
    var res;
    res = a - b;
    if (((res ^ a) & 0x8000) && ((a ^ b) & 0x8000)) {
        if (a & 0x8000)
            res = 0x8000;
        else
            res = 0x7fff;
    }
    return res;
}
function sub8_sat( a,  b)
{
    var res;
    res = a - b;
    if (((res ^ a) & 0x80) && ((a ^ b) & 0x80)) {
        if (a & 0x80)
            res = 0x80;
        else
            res = 0x7f;
    }
    return res;
}
function op_qadd16_T0_T1()
{
    varres = 0;
    do{}while(0);
    res |= (/* (uint32_t) */(add16_sat(T0, T1))) << (0 * 16);;
    res |= (/* (uint32_t) */(add16_sat(T0 >>> 16, T1 >>> 16))) << (1 * 16);;
    do{}while(0);
    T0 = res;
    
}
function op_qadd8_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */(add8_sat(T0, T1))) << (0 * 8);;
    res |= (/* (uint32_t) */(add8_sat(T0 >> 8, T1 >> 8))) << (1 * 8);;
    res |= (/* (uint32_t) */(add8_sat(T0 >> 16, T1 >> 16))) << (2 * 8);;
    res |= (/* (uint32_t) */(add8_sat(T0 >> 24, T1 >> 24))) << (3 * 8);;
    do{}while(0);
    T0 = res;
    
}
function op_qsub16_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */(sub16_sat(T0, T1))) << (0 * 16);;
    res |= (/* (uint32_t) */(sub16_sat(T0 >> 16, T1 >> 16))) << (1 * 16);;
    do{}while(0);
    T0 = res;
    
}
function op_qsub8_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */(sub8_sat(T0, T1))) << (0 * 8);;
    res |= (/* (uint32_t) */(sub8_sat(T0 >> 8, T1 >> 8))) << (1 * 8);;
    res |= (/* (uint32_t) */(sub8_sat(T0 >> 16, T1 >> 16))) << (2 * 8);;
    res |= (/* (uint32_t) */(sub8_sat(T0 >> 24, T1 >> 24))) << (3 * 8);;
    do{}while(0);
    T0 = res;
    
}
function op_qsubaddx_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */(add16_sat(T0, T1))) << (0 * 16);;
    res |= (/* (uint32_t) */(sub16_sat(T0 >> 16, T1 >> 16))) << (1 * 16);;
    do{}while(0);
    T0 = res;
    
}
function op_qaddsubx_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */(sub16_sat(T0, T1))) << (0 * 16);;
    res |= (/* (uint32_t) */(add16_sat(T0 >> 16, T1 >> 16))) << (1 * 16);;
    do{}while(0);
    T0 = res;
    
}
function /* uint16_t */ add16_usat( a,  b)
{
    var res;
    res = a + b;
    if (res < a)
        res = 0xffff;
    return res;
}
function sub16_usat( a,  b)
{
    if (a < b)
        return a - b;
    else
        return 0;
}
function add8_usat(a, b)
{
    var res;
    res = a + b;
    if (res < a)
        res = 0xff;
    return res;
}
function sub8_usat(a, b)
{
    if (a < b)
        return a - b;
    else
        return 0;
}
function op_uqadd16_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */(add16_usat(T0, T1))) << (0 * 16);;
    res |= (/* (uint32_t) */(add16_usat(T0 >> 16, T1 >> 16))) << (1 * 16);;
    do{}while(0);
    T0 = res;
    
}
function op_uqadd8_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */(add8_usat(T0, T1))) << (0 * 8);;
    res |= (/* (uint32_t) */(add8_usat(T0 >> 8, T1 >> 8))) << (1 * 8);;
    res |= (/* (uint32_t) */(add8_usat(T0 >> 16, T1 >> 16))) << (2 * 8);;
    res |= (/* (uint32_t) */(add8_usat(T0 >> 24, T1 >> 24))) << (3 * 8);;
    do{}while(0);
    T0 = res;
    
}
function op_uqsub16_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */(sub16_usat(T0, T1))) << (0 * 16);;
    res |= (/* (uint32_t) */(sub16_usat(T0 >> 16, T1 >> 16))) << (1 * 16);;
    do{}while(0);
    T0 = res;
    
}
function op_uqsub8_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */(sub8_usat(T0, T1))) << (0 * 8);;
    res |= (/* (uint32_t) */(sub8_usat(T0 >> 8, T1 >> 8))) << (1 * 8);;
    res |= (/* (uint32_t) */(sub8_usat(T0 >> 16, T1 >> 16))) << (2 * 8);;
    res |= (/* (uint32_t) */(sub8_usat(T0 >> 24, T1 >> 24))) << (3 * 8);;
    do{}while(0);
    T0 = res;
    
}
function op_uqsubaddx_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */(add16_usat(T0, T1))) << (0 * 16);;
    res |= (/* (uint32_t) */(sub16_usat(T0 >> 16, T1 >> 16))) << (1 * 16);;
    do{}while(0);
    T0 = res;
    
}
function op_uqaddsubx_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */(sub16_usat(T0, T1))) << (0 * 16);;
    res |= (/* (uint32_t) */(add16_usat(T0 >> 16, T1 >> 16))) << (1 * 16);;
    do{}while(0);
    T0 = res;
    
}
function op_sadd16_T0_T1()
{
    var res = 0;
    var ge = 0;
    do { var sum; sum = ((T0) + (T1)); res |= ((sum)) << (0 * 16); if (sum >= 0) ge |= 3 << (0 * 2); } while(0);
    do { var sum; sum = ((T0 >>> 16) + (T1 >>> 16)); res |= (/* (uint32_t) */(sum)) << (1 * 16); if (sum >= 0) ge |= 3 << (1 * 2); } while(0);
    cpu_single_env.GE = ge;
    T0 = res;
    
}
function op_sadd8_T0_T1()
{
    var res = 0;
    var ge = 0;
    do { var sum; sum = ((T0) + (T1)); res |= (/* (uint32_t) */(sum)) << (0 * 8); if (sum >= 0) ge |= 1 << 0; } while(0);
    do { var sum; sum = ((T0 >>> 8) + (T1 >>> 8)); res |= (/* (uint32_t) */(sum)) << (1 * 8); if (sum >= 0) ge |= 1 << 1; } while(0);
    do { var sum; sum = ((T0 >>> 16) + (T1 >>> 16)); res |= (/* (uint32_t) */(sum)) << (2 * 8); if (sum >= 0) ge |= 1 << 2; } while(0);
    do { var sum; sum = ((T0 >>> 24) + (T1 >>> 24)); res |= (/* (uint32_t) */(sum)) << (3 * 8); if (sum >= 0) ge |= 1 << 3; } while(0);
    cpu_single_env.GE = ge;
    T0 = res;
    
}
function op_ssub16_T0_T1()
{
    var res = 0;
    var ge = 0;
    do { var sum; sum = ((T0) - (T1)); res |= (/* (uint32_t) */(sum)) << (0 * 16); if (sum >= 0) ge |= 3 << (0 * 2); } while(0);
    do { var sum; sum = ((T0 >>> 16) - (T1 >>> 16)); res |= (/* (uint32_t) */(sum)) << (1 * 16); if (sum >= 0) ge |= 3 << (1 * 2); } while(0);
    cpu_single_env.GE = ge;
    T0 = res;
    
}
function op_ssub8_T0_T1()
{
    var res = 0;
    var ge = 0;
    do { var sum; sum = ((T0) - (T1)); res |= (/* (uint32_t) */(sum)) << (0 * 8); if (sum >= 0) ge |= 1 << 0; } while(0);
    do { var sum; sum = ((T0 >> 8) - (T1 >> 8)); res |= (/* (uint32_t) */(sum)) << (1 * 8); if (sum >= 0) ge |= 1 << 1; } while(0);
    do { var sum; sum = ((T0 >> 16) - (T1 >> 16)); res |= (/* (uint32_t) */(sum)) << (2 * 8); if (sum >= 0) ge |= 1 << 2; } while(0);
    do { var sum; sum = ((T0 >> 24) - (T1 >> 24)); res |= (/* (uint32_t) */(sum)) << (3 * 8); if (sum >= 0) ge |= 1 << 3; } while(0);
    cpu_single_env.GE = ge;
    T0 = res;
    
}
function op_ssubaddx_T0_T1()
{
    var res = 0;
    var ge = 0;
    do { var sum; sum = ((T0) + (T1)); res |= (/* (uint32_t) */(sum)) << (0 * 16); if (sum >= 0) ge |= 3 << (0 * 2); } while(0);
    do { var sum; sum = ((T0 >> 16) - (T1 >> 16)); res |= (/* (uint32_t) */(sum)) << (1 * 16); if (sum >= 0) ge |= 3 << (1 * 2); } while(0);
    cpu_single_env.GE = ge;
    T0 = res;
    
}
function op_saddsubx_T0_T1()
{
    var res = 0;
    var ge = 0;
    do { var sum; sum = ((T0) - (T1)); res |= (/* (uint32_t) */(sum)) << (0 * 16); if (sum >= 0) ge |= 3 << (0 * 2); } while(0);
    do { var sum; sum = ((T0 >> 16) + (T1 >> 16)); res |= (/* (uint32_t) */(sum)) << (1 * 16); if (sum >= 0) ge |= 3 << (1 * 2); } while(0);
    cpu_single_env.GE = ge;
    T0 = res;
    
}
function op_uadd16_T0_T1()
{
    var res = 0;
    var ge = 0;
    do { var sum; sum = /* (uint32_t) */(T0) + /* (uint32_t) */(T1); res |= (/* (uint32_t) */(sum)) << (0 * 16); if ((sum >> 16) == 0) ge |= 3 << (0 * 2); } while(0);
    do { var sum; sum = /* (uint32_t) */(T0 >> 16) + /* (uint32_t) */(T1 >> 16); res |= (/* (uint32_t) */(sum)) << (1 * 16); if ((sum >> 16) == 0) ge |= 3 << (1 * 2); } while(0);
    cpu_single_env.GE = ge;
    T0 = res;
    
}
function op_uadd8_T0_T1()
{
    var res = 0;
    var ge = 0;
    do { var sum; sum = /* (uint32_t) */(T0) + /* (uint32_t) */(T1); res |= (/* (uint32_t) */(sum)) << (0 * 8); if ((sum >> 8) == 0) ge |= 3 << (0 * 2); } while(0);
    do { var sum; sum = /* (uint32_t) */(T0 >>> 8) + /* (uint32_t) */(T1 >>> 8); res |= (/* (uint32_t) */(sum)) << (1 * 8); if ((sum >> 8) == 0) ge |= 3 << (1 * 2); } while(0);
    do { var sum; sum = /* (uint32_t) */(T0 >>> 16) + /* (uint32_t) */(T1 >>> 16); res |= (/* (uint32_t) */(sum)) << (2 * 8); if ((sum >> 8) == 0) ge |= 3 << (2 * 2); } while(0);
    do { var sum; sum = /* (uint32_t) */(T0 >>> 24) + /* (uint32_t) */(T1 >>> 24); res |= (/* (uint32_t) */(sum)) << (3 * 8); if ((sum >> 8) == 0) ge |= 3 << (3 * 2); } while(0);
    cpu_single_env.GE = ge;
    T0 = res;
    
}
function op_usub16_T0_T1()
{
    var res = 0;
    var ge = 0;
    do { var sum; sum = /* (uint32_t) */(T0) - /* (uint32_t) */(T1); res |= (/* (uint32_t) */(sum)) << (0 * 16); if ((sum >> 16) == 0) ge |= 3 << (0 * 2); } while(0);
    do { var sum; sum = /* (uint32_t) */(T0 >>> 16) - /* (uint32_t) */(T1 >>> 16); res |= (/* (uint32_t) */(sum)) << (1 * 16); if ((sum >> 16) == 0) ge |= 3 << (1 * 2); } while(0);
    cpu_single_env.GE = ge;
    T0 = res;
    
}
function op_usub8_T0_T1()
{
    var res = 0;
    var ge = 0;
    do { var sum; sum = /* (uint32_t) */(T0) - /* (uint32_t) */(T1); res |= (/* (uint32_t) */(sum)) << (0 * 8); if ((sum >> 8) == 0) ge |= 3 << (0 * 2); } while(0);
    do { var sum; sum = /* (uint32_t) */(T0 >>> 8) - /* (uint32_t) */(T1 >>> 8); res |= (/* (uint32_t) */(sum)) << (1 * 8); if ((sum >> 8) == 0) ge |= 3 << (1 * 2); } while(0);
    do { var sum; sum = /* (uint32_t) */(T0 >>> 16) - /* (uint32_t) */(T1 >>> 16); res |= (/* (uint32_t) */(sum)) << (2 * 8); if ((sum >> 8) == 0) ge |= 3 << (2 * 2); } while(0);
    do { var sum; sum = /* (uint32_t) */(T0 >>> 24) - /* (uint32_t) */(T1 >>> 24); res |= (/* (uint32_t) */(sum)) << (3 * 8); if ((sum >> 8) == 0) ge |= 3 << (3 * 2); } while(0);
    cpu_single_env.GE = ge;
    T0 = res;
    
}
function op_usubaddx_T0_T1()
{
    var res = 0;
    var ge = 0;
    do { var sum; sum = /* (uint32_t) */(T0) + /* (uint32_t) */(T1); res |= (/* (uint32_t) */(sum)) << (0 * 16); if ((sum >> 16) == 0) ge |= 3 << (0 * 2); } while(0);
    do { var sum; sum = /* (uint32_t) */(T0 >> 16) - /* (uint32_t) */(T1 >> 16); res |= (/* (uint32_t) */(sum)) << (1 * 16); if ((sum >> 16) == 0) ge |= 3 << (1 * 2); } while(0);
    cpu_single_env.GE = ge;
    T0 = res;
    
}
function op_uaddsubx_T0_T1()
{
    var res = 0;
    var ge = 0;
    do { var sum; sum = /* (uint32_t) */(T0) - /* (uint32_t) */(T1); res |= (/* (uint32_t) */(sum)) << (0 * 16); if ((sum >> 16) == 0) ge |= 3 << (0 * 2); } while(0);
    do { var sum; sum = /* (uint32_t) */(T0 >> 16) + /* (uint32_t) */(T1 >> 16); res |= (/* (uint32_t) */(sum)) << (1 * 16); if ((sum >> 16) == 0) ge |= 3 << (1 * 2); } while(0);
    cpu_single_env.GE = ge;
    T0 = res;
    
}
function op_shadd16_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0) + /* (int32_t) */(T1)) >> 1)) << (0 * 16);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0 >> 16) + /* (int32_t) */(T1 >> 16)) >> 1)) << (1 * 16);
    do{}while(0);
    T0 = res;
    
}
function op_shadd8_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0) + /* (int32_t) */(T1)) >> 1)) << (0 * 8);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0 >> 8) + /* (int32_t) */(T1 >> 8)) >> 1)) << (1 * 8);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0 >> 16) + /* (int32_t) */(T1 >> 16)) >> 1)) << (2 * 8);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0 >> 24) + /* (int32_t) */(T1 >> 24)) >> 1)) << (3 * 8);
    do{}while(0);
    T0 = res;
    
}
function op_shsub16_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0) - /* (int32_t) */(T1)) >> 1)) << (0 * 16);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0 >> 16) - /* (int32_t) */(T1 >> 16)) >> 1)) << (1 * 16);
    do{}while(0);
    T0 = res;
    
}
function op_shsub8_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0) - /* (int32_t) */(T1)) >> 1)) << (0 * 8);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0 >> 8) - /* (int32_t) */(T1 >> 8)) >> 1)) << (1 * 8);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0 >> 16) - /* (int32_t) */(T1 >> 16)) >> 1)) << (2 * 8);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0 >> 24) - /* (int32_t) */(T1 >> 24)) >> 1)) << (3 * 8);
    do{}while(0);
    T0 = res;
    
}
function op_shsubaddx_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0) + /* (int32_t) */(T1)) >> 1)) << (0 * 16);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0 >> 16) - /* (int32_t) */(T1 >> 16)) >> 1)) << (1 * 16);
    do{}while(0);
    T0 = res;
    
}
function op_shaddsubx_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0) - /* (int32_t) */(T1)) >> 1)) << (0 * 16);
    res |= (/* (uint32_t) */((/* (int32_t) */(T0 >> 16) + /* (int32_t) */(T1 >> 16)) >> 1)) << (1 * 16);
    do{}while(0);
    T0 = res;
    
}
function op_uhadd16_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0) + /* (uint32_t) */(T1)) >> 1)) << (0 * 16);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0 >> 16) + /* (uint32_t) */(T1 >> 16)) >> 1)) << (1 * 16);
    do{}while(0);
    T0 = res;
    
}
function op_uhadd8_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0) + /* (uint32_t) */(T1)) >> 1)) << (0 * 8);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0 >> 8) + /* (uint32_t) */(T1 >> 8)) >> 1)) << (1 * 8);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0 >> 16) + /* (uint32_t) */(T1 >> 16)) >> 1)) << (2 * 8);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0 >> 24) + /* (uint32_t) */(T1 >> 24)) >> 1)) << (3 * 8);
    do{}while(0);
    T0 = res;
    
}
function op_uhsub16_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0) - /* (uint32_t) */(T1)) >> 1)) << (0 * 16);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0 >> 16) - /* (uint32_t) */(T1 >> 16)) >> 1)) << (1 * 16);
    do{}while(0);
    T0 = res;
    
}
function op_uhsub8_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0) - /* (uint32_t) */(T1)) >> 1)) << (0 * 8);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0 >> 8) - /* (uint32_t) */(T1 >> 8)) >> 1)) << (1 * 8);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0 >> 16) - /* (uint32_t) */(T1 >> 16)) >> 1)) << (2 * 8);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0 >> 24) - /* (uint32_t) */(T1 >> 24)) >> 1)) << (3 * 8);
    do{}while(0);
    T0 = res;
    
}
function op_uhsubaddx_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0) + /* (uint32_t) */(T1)) >> 1)) << (0 * 16);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0 >> 16) - /* (uint32_t) */(T1 >> 16)) >> 1)) << (1 * 16);
    do{}while(0);
    T0 = res;
    
}
function op_uhaddsubx_T0_T1()
{
    var res = 0;
    do{}while(0);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0) - /* (uint32_t) */(T1)) >> 1)) << (0 * 16);
    res |= (/* (uint32_t) */((/* (uint32_t) */(T0 >> 16) + /* (uint32_t) */(T1 >> 16)) >> 1)) << (1 * 16);
    do{}while(0);
    T0 = res;
    
}
function op_pkhtb_T0_T1()
{
    T0 = (T0 & 0xffff0000) | (T1 & 0xffff);
}
function op_pkhbt_T0_T1()
{
    T0 = (T0 & 0xffff) | (T1 & 0xffff0000);
}
function op_rev_T0()
{
    T0 = ((T0 & 0xff000000) >> 24)
        | ((T0 & 0x00ff0000) >> 8)
        | ((T0 & 0x0000ff00) << 8)
        | ((T0 & 0x000000ff) << 24);
}
function op_revh_T0()
{
    T0 = (T0 >> 16) | (T0 << 16);
}
function op_rev16_T0()
{
    T0 = ((T0 & 0xff000000) >> 8)
        | ((T0 & 0x00ff0000) << 8)
        | ((T0 & 0x0000ff00) >> 8)
        | ((T0 & 0x000000ff) << 8);
}
function op_revsh_T0()
{
    T0 = ( ((T0 & 0x0000ff00) >> 8)
                   | ((T0 & 0x000000ff) << 8));
}
function op_rbit_T0()
{
    T0 = ((T0 & 0xff000000) >> 24)
        | ((T0 & 0x00ff0000) >> 8)
        | ((T0 & 0x0000ff00) << 8)
        | ((T0 & 0x000000ff) << 24);
    T0 = ((T0 & 0xf0f0f0f0) >> 4)
        | ((T0 & 0x0f0f0f0f) << 4);
    T0 = ((T0 & 0x88888888) >> 3)
        | ((T0 & 0x44444444) >> 1)
        | ((T0 & 0x22222222) << 1)
        | ((T0 & 0x11111111) << 3);
}
function op_swap_half_T1()
{
    T1 = (T1 >> 16) | (T1 << 16);
    
}
function op_mul_dual_T0_T1()
{
    var low;
    var high;
    low = /* (int32_t) */T0 * /* (int32_t) */T1;
    high = ((/* (int32_t) */T0) >> 16) * ((/* (int32_t) */T1) >> 16);
    T0 = low;
    T1 = high;
}
function op_sel_T0_T1()
{
    var mask;
    var flags;
    flags = cpu_single_env.GE;
    mask = 0;
    if (flags & 1)
        mask |= 0xff;
    if (flags & 2)
        mask |= 0xff00;
    if (flags & 4)
        mask |= 0xff0000;
    if (flags & 8)
        mask |= 0xff000000;
    T0 = (T0 & mask) | (T1 & ~mask);
    
}
function op_roundqd_T0_T1()
{
    T0 = T1 + (/* (uint32_t) */T0 >> 31);
}
function do_ssat(val, shift)
{
    var top;
    var mask;
    console.log("do_ssat FIX me!!");
    shift = (param1);
    top = val >> shift;
    mask = (1 << shift) - 1;
    if (top > 0) {
        cpu_single_env.QF = 1;
        return mask;
    } else if (top < -1) {
        cpu_single_env.QF = 1;
        return ~mask;
    }
    return val;
}
function do_usat(val, shift)
{
    var max;
    console.log("do_ssat FIX me!!");
    shift = (param1);
    max = (1 << shift) - 1;
    if (val < 0) {
        cpu_single_env.QF = 1;
        return 0;
    } else if (val > max) {
        cpu_single_env.QF = 1;
        return max;
    }
    return val;
}
function op_ssat_T1(param1)
{
    T0 = do_ssat(T0, param1);
    
}
function op_ssat16_T1(param1)
{
    var res;
    res = do_ssat(T0, param1);
    res |= do_ssat((/* (int32_t) */T0) >> 16, param1) << 16;
    T0 = res;
    
}
function op_usat_T1(param1)
{
    T0 = do_usat(T0, param1);
    
}
function op_usat16_T1(param1)
{
    var res;
    res = do_usat(T0, (param1));
    res |= do_usat((/* (int32_t) */T0) >> 16, (param1)) << 16;
    T0 = res;
    
}
function op_add16_T1_T2()
{
    var mask;
    mask = (T0 & T1) & 0x8000;
    T0 ^= ~0x8000;
    T1 ^= ~0x8000;
    T0 = (T0 + T1) ^ mask;
}
function do_usad(a, b)
{
    if (a > b)
        return a - b;
    else
        return b - a;
}
function op_usad8_T0_T1()
{
    var sum;
    sum = do_usad(T0, T1);
    sum += do_usad(T0 >> 8, T1 >> 8);
    sum += do_usad(T0 >> 16, T1 >>16);
    sum += do_usad(T0 >> 24, T1 >> 24);
    T0 = sum;
}
function op_bfi_T1_T0(param1)
{
    var shift = ((param1));
    //var mask = ((&__op_param2));
    var bits;
    bits = (T1 << shift) & mask;
    T1 = (T0 & ~mask) | bits;
}
function op_ubfx_T1(param1)
{
    var shift = ((param1));
    //var mask = ((&__op_param2));
    T1 >>= shift;
    T1 &= mask;
}
function op_sbfx_T1()
{
    var shift = ((param1));
    //var width = ((&__op_param2));
    var val;
    val = T1 << (32 - (shift + width));
    T1 = val >> (32 - width);
}
function op_movtop_T0_im(param1)
{
    T0 = (T0 & 0xffff) | ((param1));
}
function op_jmp_T0_im()
{
    cpu_single_env.regs[15] = (param1) + (T0 << 1);
}
function op_set_condexec(param1)
{
    cpu_single_env.condexec_bits = param1;
}
function op_sdivl_T0_T1()
{
  var num;
  var den;
  num = T0;
  den = T1;
  if (den == 0)
    T0 = 0;
  else
    T0 = num / den;
  
}
function op_udivl_T0_T1()
{
  var /* uint32_t */ num;
  var /* uint32_t */den;
  num = T0;
  den = T1;
  if (den == 0)
    T0 = 0;
  else
    T0 = num / den;
  
}
function op_movl_T1_r13_banked(param1)
{
    T1 = helper_get_r13_banked(cpu_single_env, (param1));
}
function op_movl_r13_T1_banked(param1)
{
    helper_set_r13_banked(cpu_single_env, (param1), T1);
}
function op_v7m_mrs_T0(param1)
{
    T0 = helper_v7m_mrs(cpu_single_env, (param1));
}
function op_v7m_msr_T0(param1)
{
    helper_v7m_msr(cpu_single_env, (param1), T0);
}

function op_movl_T0_sp(param1)
{
    if ((param1) == cpu_single_env.v7m.current_sp)
        T0 = cpu_single_env.regs[13];
    else
        T0 = cpu_single_env.v7m.other_sp;
    
}
function arm_feature(/* CPUARMState * */env, /* int */ feature)
{
    if(env.features & (1 << feature)) 
        return 1;
    else
        return 0;
}

/* CPUARMState */
function CPUARMState(){
    /*
		R0-R7 Are known as the low registers.
		R8-R12 Are the high registers.
		R13 is the stack pointer.
		R14 is the link register.
		R15 is the program counter.
		CPSR is the program status register.
		SPSR is the saved program status register.
     */
    /* Regs for current mode. */
    this.regs = new Uint32Array(16);
    for(i=0;
            i<16;
            i++)this.regs[i]=0;
    this.tregs = new Uint32Array(3);
    
    /* Frequently accessed CPSR bits are stored separately for efficiently.
       This contains all the other bits.  Use cpsr_{read,write} to access
       the whole CPSR. */
    
    this.uncached_cpsr = 0;
    this.spsr = 0;

    /* Banked registers.  */
    this.banked_spsr = new Uint32Array(6);
    this.banked_r13 = new Uint32Array(6);
    this.banked_r14 = new Uint32Array(6); 

    /* These hold r8-r12.  */
    this.usr_regs = new Uint32Array(5);
    this.fiq_regs = new Uint32Array(5);

    /* cpsr flag cache for faster execution */
    this.CF = 0;             // 0 or 1 
    this.VF = 0;             // V is the bit 31. All other bits are undefined 
    this.NZF = 0;            // N is bit 31. Z is computed from NZF 
    this.QF = 0;             // 0 or 1 
    this.GE = 0;         // cpsr[19:16] 
    this.thumb = 0;         // cprs[5]. 0 = arm mode, 1 = thumb mode. 
    this.condexec_bits = 0;  // IT bits.  cpsr[15:10,26:25].  
    /* System control coprocessor (cp15) */
    function cp15() {
        this.c0_cpuid = 0;
        this.c0_cachetype = 0;
        this.c0_c1 = new Uint32Array(8); // Feature registers. 
        this.c0_c2 = new Uint32Array(8); // Instruction set registers.  
        this.c1_sys = 0;// System control register.  
        this.c1_coproc = 0; // Coprocessor access register.  
        this.c1_xscaleauxcr = 0; // XScale auxiliary control register.  
        this.c2_base0 = 0; // MMU translation table base 0.  
        this.c2_base1 = 0; // MMU translation table base 1.  
        this.c2_mask = 0; // MMU translation table base mask. 
        this.c2_data = 0; // MPU data cachable bits.  
        this.c2_insn = 0; // MPU instruction cachable bits.  
        this.c3 = 0; // MMU domain access control register MPU write buffer control.  
        this.c5_insn = 0; // Fault status registers.  
        this.c5_data = 0;
        this.c6_region = new Uint32Array(8); // MPU base/size registers.  
        this.c6_insn = 0; // Fault address registers.  
        this.c6_data = 0;
        this.c9_insn = 0; // Cache lockdown registers.  
        this.c9_data = 0;
        this.c13_fcse = 0; // FCSE PID. 
        this.c13_context = 0; // Context ID.  
        this.c13_tls1 = 0; // User RW Thread register.  
        this.c13_tls2 = 0; // User RO Thread register.  
        this.c13_tls3 = 0; // Privileged Thread register.  
        this.c15_cpar = 0; // XScale Coprocessor Access Register 
        this.c15_ticonfig = 0; // TI925T configuration byte.  
        this.c15_i_max = 0; // Maximum D-cache dirty line index.  
        this.c15_i_min = 0; // Minimum D-cache dirty line index. 
        this.c15_threadid = 0; // TI debugger thread-ID. 
    } //} cp15;
    
    this.cp15 = new cp15();
    /*
    struct {
        uint32_t other_sp;
        uint32_t vecbase;
        uint32_t basepri;
        uint32_t control;
        int current_sp;
        int exception;
        int pending_exception;
        void *nvic;
    } v7m;
     */
    /* Coprocessor IO used by peripherals */
    /*
    struct {
        ARMReadCPFunc *cp_read;
        ARMWriteCPFunc *cp_write;
        void *opaque;
    } cp[15];
     */
    /* Internal CPU feature flags.  */
    this.features = 0;
    
    /* Callback for vectored interrupt controller.  */
    /*
    int (*get_irq_vector)(struct CPUARMState *);
    void *irq_opaque;
     */
    /* exception/interrupt handling */
    
    //jmp_buf jmp_env;
    this.exception_index = 0;
    this.interrupt_request = 0;
    this.halted = 0;
     
    /* VFP coprocessor state.  */
    function vfpfunc() {
        this.regs = new Array(32);

        this.xregs = new Uint32Array(16);
        // We store these fpcsr fields separately for convenience.  
        this.vec_len = 0;
        this.vec_stride = 0;

        // Temporary variables if we don't have spare fp regs. 
        this.tmp0s = 0;
        this.tmp1s = 0;
        this.tmp0d = 0;
        this.tmp1d = 0;
        // scratch space when Tn are not sufficient.  
        this.scratch = new Uint32Array(8);

        this.fp_status = 0;
    }
    this.vfp = new vfpfunc();

    //uint32_t mmon_addr;


    /* iwMMXt coprocessor state.  */
    /*
    struct {
        uint64_t regs[16];
        uint64_t val;

        uint32_t cregs[16];
    } iwmmxt;
     */

    //this.current_tb = new TranslationBlock();
    //unsigned long mem_write_pc; 
    //target_ulong mem_write_vaddr; 
    //CPUTLBEntry tlb_table[2][(1 << 8)];  / how would i do this array from object.. like i have the object..
    /*
    var x, i;
    for(x=0;x < 2;x++) {
        this.tlb_table[x] = new CPUTLBEntry();
        for(i=0; i < (1 << 8);i++)
            this.tlb_table[x][i] = new CPUTLBEntry();
    }
    */
    //struct TranslationBlock *tb_jmp_cache[(1 << 12)]; 
    this.tb_jmp_cache = new Array(1 << 12);
    /*
    var target_ulong breakpoints = new Float32Array(32);
    var nb_breakpoints; 
    var singlestep_enabled;
    struct { 
        target_ulong vaddr; 
        target_phys_addr_t addend; 
    } watchpoint[32]; 
    (
    var nb_watchpoints; 
    */
    this.cpu_index = 0;
    this.cpu_model_str = "";

    /* These fields after the common ones so they are preserved on reset.  */
    this.ram_size = 0;
    this.kernel_filename ="";
    this.kernel_cmdline = "";
    this.initrd_filename = "";
    this.board_id = 0;
    this.loader_start = 0;
}
//} CPUARMState;

/* MMU code */
function cpu_mmu_index (/* CPUARMState * */ env)
{
    return (env.uncached_cpsr & (0x1f)) == ARM_CPU_MODE_USR ? 1 : 0;
}

function ldl_user(/* target_ulong */ ptr)
{
    var index;
    var res;
    var /* target_ulong*/ addr;
    var /*unsigned long*/ physaddr;
    var mmu_idx;

    addr = ptr;
    index = (addr >> 10) & ((1 << 8) - 1);
    mmu_idx = 1;
    /*
    if (__builtin_expect(cpu_single_env.tlb_table[mmu_idx][index].addr_read !=
                         (addr & (~((1 << 10) - 1) | (4 - 1))), 0)) {
        res = __ldl_mmu(addr, mmu_idx);
    } else {
        physaddr = addr + cpu_single_env.tlb_table[mmu_idx][index].addend;
        res = ldl_le_p((uint8_t *)(long)(((uint8_t *)physaddr)));
    }
    */
    return res;
}

function helper_get_cp15(env, insn)
{
    var op1;
    var op2;
    var crm;

    op1 = (insn >> 21) & 7;
    op2 = (insn >> 5) & 7;
    crm = insn & 0xf;
    switch ((insn >> 16) & 0xf) {
    case 0: /* ID codes.  */
        switch (op1) {
        case 0:
            switch (crm) {
            case 0:
                switch (op2) {
                case 0: /* Device ID.  */
                    return env.cp15.c0_cpuid;
                case 1: /* Cache Type.  */
		    return env.cp15.c0_cachetype;
                case 2: /* TCM status.  */
                    return 0;
                case 3: /* TLB type register.  */
                    return 0; /* No lockable TLB entries.  */
                case 5: /* CPU ID */
                    if (ARM_CPUID(env) == ARM_CPUID_CORTEXA9) {
                        return env.cpu_index | 0x80000900;
                    } else {
                        return env.cpu_index;
                    }
                default:
                    cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
                }
            case 1:
                if (!arm_feature(env, ARM_FEATURE_V6))
                    cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
                return env.cp15.c0_c1[op2];
            case 2:
                if (!arm_feature(env, ARM_FEATURE_V6))
                    cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
                return env.cp15.c0_c2[op2];
            case 3: case 4: case 5: case 6: case 7:
                return 0;
            default:
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            }
        case 1:
            /* These registers aren't documented on arm11 cores.  However
               Linux looks at them anyway.  */
            if (!arm_feature(env, ARM_FEATURE_V6))
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            if (crm != 0)
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            if (!arm_feature(env, ARM_FEATURE_V7))
                return 0;

            switch (op2) {
            case 0:
                return env.cp15.c0_ccsid[env.cp15.c0_cssel];
            case 1:
                return env.cp15.c0_clid;
            case 7:
                return 0;
            }
            cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
        case 2:
            if (op2 != 0 || crm != 0)
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            return env.cp15.c0_cssel;
        default:
            cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
        }
    case 1: /* System configuration.  */
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            op2 = 0;
        switch (op2) {
        case 0: /* Control register.  */
            return env.cp15.c1_sys;
        case 1: /* Auxiliary control register.  */
            if (arm_feature(env, ARM_FEATURE_XSCALE))
                return env.cp15.c1_xscaleauxcr;
            if (!arm_feature(env, ARM_FEATURE_AUXCR))
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            switch (ARM_CPUID(env)) {
            case ARM_CPUID_ARM1026:
                return 1;
            case ARM_CPUID_ARM1136:
            case ARM_CPUID_ARM1136_R2:
                return 7;
            case ARM_CPUID_ARM11MPCORE:
                return 1;
            case ARM_CPUID_CORTEXA8:
                return 2;
            case ARM_CPUID_CORTEXA9:
                return 0;
            default:
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            }
        case 2: /* Coprocessor access register.  */
            if (arm_feature(env, ARM_FEATURE_XSCALE))
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            return env.cp15.c1_coproc;
        default:
            cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
        }
    case 2: /* MMU Page table control / MPU cache control.  */
        if (arm_feature(env, ARM_FEATURE_MPU)) {
            switch (op2) {
            case 0:
                return env.cp15.c2_data;
                break;
            case 1:
                return env.cp15.c2_insn;
                break;
            default:
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            }
        } else {
	    switch (op2) {
	    case 0:
		return env.cp15.c2_base0;
	    case 1:
		return env.cp15.c2_base1;
	    case 2:
                return env.cp15.c2_control;
	    default:
		cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
	    }
	}
    case 3: /* MMU Domain access control / MPU write buffer control.  */
        return env.cp15.c3;
    case 4: /* Reserved.  */
        cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
    case 5: /* MMU Fault status / MPU access permission.  */
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            op2 = 0;
        switch (op2) {
        case 0:
            if (arm_feature(env, ARM_FEATURE_MPU))
                return simple_mpu_ap_bits(env.cp15.c5_data);
            return env.cp15.c5_data;
        case 1:
            if (arm_feature(env, ARM_FEATURE_MPU))
                return simple_mpu_ap_bits(env.cp15.c5_data);
            return env.cp15.c5_insn;
        case 2:
            if (!arm_feature(env, ARM_FEATURE_MPU))
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            return env.cp15.c5_data;
        case 3:
            if (!arm_feature(env, ARM_FEATURE_MPU))
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            return env.cp15.c5_insn;
        default:
            cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
        }
    case 6: /* MMU Fault address.  */
        if (arm_feature(env, ARM_FEATURE_MPU)) {
            if (crm >= 8)
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            return env.cp15.c6_region[crm];
        } else {
            if (arm_feature(env, ARM_FEATURE_OMAPCP))
                op2 = 0;
	    switch (op2) {
	    case 0:
		return env.cp15.c6_data;
	    case 1:
		if (arm_feature(env, ARM_FEATURE_V6)) {
		    /* Watchpoint Fault Adrress.  */
		    return 0; /* Not implemented.  */
		} else {
		    /* Instruction Fault Adrress.  */
		    /* Arm9 doesn't have an IFAR, but implementing it anyway
		       shouldn't do any harm.  */
		    return env.cp15.c6_insn;
		}
	    case 2:
		if (arm_feature(env, ARM_FEATURE_V6)) {
		    /* Instruction Fault Adrress.  */
		    return env.cp15.c6_insn;
		} else {
		    cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
		}
	    default:
		cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
	    }
        }
    case 7: /* Cache control.  */
        /* FIXME: Should only clear Z flag if destination is r15.  */
        env.ZF = 0;
        return 0;
    case 8: /* MMU TLB control.  */
        cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
    case 9: /* Cache lockdown.  */
        switch (op1) {
        case 0: /* L1 cache.  */
	    if (arm_feature(env, ARM_FEATURE_OMAPCP))
		return 0;
            switch (op2) {
            case 0:
                return env.cp15.c9_data;
            case 1:
                return env.cp15.c9_insn;
            default:
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            }
        case 1: /* L2 cache */
            if (crm != 0)
                cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
            /* L2 Lockdown and Auxiliary control.  */
            return 0;
        default:
            cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
        }
    case 10: /* MMU TLB lockdown.  */
        /* ??? TLB lockdown not implemented.  */
        return 0;
    case 11: /* TCM DMA control.  */
    case 12: /* Reserved.  */
        cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
    case 13: /* Process ID.  */
        switch (op2) {
        case 0:
            return env.cp15.c13_fcse;
        case 1:
            return env.cp15.c13_context;
        default:
            cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
        }
    case 14: /* Reserved.  */
        cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
    case 15: /* Implementation specific.  */
        if (arm_feature(env, ARM_FEATURE_XSCALE)) {
            if (op2 == 0 && crm == 1)
                return env.cp15.c15_cpar;

            cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
        }
        if (arm_feature(env, ARM_FEATURE_OMAPCP)) {
            switch (crm) {
            case 0:
                return 0;
            case 1: /* Read TI925T configuration.  */
                return env.cp15.c15_ticonfig;
            case 2: /* Read I_max.  */
                return env.cp15.c15_i_max;
            case 3: /* Read I_min.  */
                return env.cp15.c15_i_min;
            case 4: /* Read thread-ID.  */
                return env.cp15.c15_threadid;
            case 8: /* TI925T_status */
                return 0;
            }
            /* TODO: Peripheral port remap register:
             * On OMAP2 mcr p15, 0, rn, c15, c2, 4 sets up the interrupt
             * controller base address at $rn & ~0xfff and map size of
             * 0x200 << ($rn & 0xfff), when MMU is off.  */
            cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
        }
        return 0;
    }
//bad_reg:
    /* ??? For debugging only.  Should raise illegal instruction exception.  */
    cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
    return 0;
}


function cpu_abort(env, str, str2, str3)
{
   throw new Error("CPU_ABORT: " + sprintf(str, str2,str3));
}

/* Map CPU modes onto saved register banks.  */
function bank_number (mode)
{
    switch (mode) {
    case ARM_CPU_MODE_USR:
    case ARM_CPU_MODE_SYS:
        return 0;
    case ARM_CPU_MODE_SVC:
        return 1;
    case ARM_CPU_MODE_ABT:
        return 2;
    case ARM_CPU_MODE_UND:
        return 3;
    case ARM_CPU_MODE_IRQ:
        return 4;
    case ARM_CPU_MODE_FIQ:
        return 5;
    }
    cpu_abort(cpu_single_env, "Bad mode %x\n", mode);
    return -1;
}

function switch_mode(/* CPUState */ env, /* int */ mode)
{
    if (mode != ARM_CPU_MODE_USR)
        cpu_abort(env, "Tried to switch out of user mode\n");
}

function /* uint32_t*/ cpsr_read(/*CPUARMState * */ env)
{
    var ZF;
    ZF = (env.NZF == 0);
    return env.uncached_cpsr | (env.NZF & 0x80000000) | (ZF << 30) |
        (env.CF << 29) | ((env.VF & 0x80000000) >> 3) | (env.QF << 27)
        | (env.thumb << 5) | ((env.condexec_bits & 3) << 25)
        | ((env.condexec_bits & 0xfc) << 8)
        | (env.GE << 16);
}

function cpsr_write(/* CPUARMState * */ env, /* uint32_t */ val, /* uint32_t */ mask)
{
    /* NOTE: N = 1 and Z = 1 cannot be stored currently */
    if (mask & CPSR_NZCV) {
        env.NZF = (val & 0xc0000000) ^ 0x40000000;
        env.CF = (val >> 29) & 1;
        env.VF = (val << 3) & 0x80000000;
    }
    if (mask & CPSR_Q)
        env.QF = ((val & CPSR_Q) != 0);
    if (mask & CPSR_T)
        env.thumb = ((val & CPSR_T) != 0);
    if (mask & CPSR_IT_0_1) {
        env.condexec_bits &= ~3;
        env.condexec_bits |= (val >> 25) & 3;
    }
    if (mask & CPSR_IT_2_7) {
        env.condexec_bits &= 3;
        env.condexec_bits |= (val >> 8) & 0xfc;
    }
    if (mask & CPSR_GE) {
        env.GE = (val >> 16) & 0xf;
    }

    if ((env.uncached_cpsr ^ val) & mask & CPSR_M) {
        switch_mode(env, val & CPSR_M);
    }
    mask &= ~CACHED_CPSR_BITS;
    env.uncached_cpsr = (env.uncached_cpsr & ~mask) | (val & mask);
}

function ldl_code(/* target_ulong */ ptr)
{
    /*
    int index;
    int res;
    target_ulong addr;
    unsigned long physaddr;
    int mmu_idx;
     */
/*
    var index;
    var res;
    var addr;
    var physaddr;
    var mmu_idx;

    addr = ptr;
    index = (addr >> 10) & ((1 << 8) - 1); // get bits 11->17
    mmu_idx = (cpu_mmu_index(cpu_single_env));
  
    if (__builtin_expect(cpu_single_cpu_single_env.tlb_table[mmu_idx][index].addr_code !=
                         (addr & (~((1 << 10) - 1) | (4 - 1))), 0)) {
        res = __:q!(addr, mmu_idx);

    } else {
        physaddr = addr + cpu_single_cpu_single_env.tlb_table[mmu_idx][index].addend;
        res = ldl_le_p((uint8_t *)(long)(((uint8_t *)physaddr)));
    }
     */
    return ld32_phys(ptr);
}
var gen_labels = new Array(512);
var nb_gen_labels = 0;
var gen_opc_buf = new Uint16Array(512);
var gen_opparam_buf = new Uint32Array(512 * 3);
var gen_opparam_ptr = new Array();
var gen_opc_ptr = new Array(); // TODO: should be set somewhere to where it is in gen_opc_buf 
//var code_gen_ptr = 0;

function dump_ops()
{
    var c, n, i, y;

    for(y=0; y < gen_opc_ptr.length; y++) {
        c = gen_opc_ptr[y];
        n = op_nb_args[c];
        console.log(op_str[c]);
        for(i = 0; i < n; i++) {
            console.log(" 0x" + gen_opparam_ptr[i]);
        }
        if (c == op_end)
            break;
    }
}

function op_end()
{
    
}
/* int  */ function gen_new_label()
{
    if(nb_gen_labels == 511) {
        nb_gen_labels = 0;
    }
    return nb_gen_labels++;
}

/* void  */ function gen_set_label(n, tc_ptr)
{
    console.log("gen_set_label + " + n + " tc_ptr " + tc_ptr);
    gen_labels[n] = (gen_opc_ptr.length - tc_ptr) - 1; // does this make sense tho?
}
/* void  */ function gen_op_movl_T0_r0()
{
    gen_opc_ptr.push({func:op_movl_T0_r0});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r0()
{
    gen_opc_ptr.push({func:op_movl_T1_r0});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r0()
{
    gen_opc_ptr.push({func:op_movl_T2_r0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r0_T0()
{
    gen_opc_ptr.push({func:op_movl_r0_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r0_T1()
{
    gen_opc_ptr.push({func:op_movl_r0_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r1()
{
    gen_opc_ptr.push({func:op_movl_T0_r1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r1()
{
    gen_opc_ptr.push({func:op_movl_T1_r1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r1()
{
    gen_opc_ptr.push({func:op_movl_T2_r1});
}

/** function XXX **/
/* void  */ function gen_op_movl_r1_T0()
{
    gen_opc_ptr.push({func:op_movl_r1_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r1_T1()
{
    gen_opc_ptr.push({func:op_movl_r1_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r2()
{
    gen_opc_ptr.push({func:op_movl_T0_r2});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r2()
{
    gen_opc_ptr.push({func:op_movl_T1_r2});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r2()
{
    gen_opc_ptr.push({func:op_movl_T2_r2});
}

/** function XXX **/
/* void  */ function gen_op_movl_r2_T0()
{
    gen_opc_ptr.push({func:op_movl_r2_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r2_T1()
{
    gen_opc_ptr.push({func:op_movl_r2_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r3()
{
    gen_opc_ptr.push({func:op_movl_T0_r3});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r3()
{
    gen_opc_ptr.push({func:op_movl_T1_r3});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r3()
{
    gen_opc_ptr.push({func:op_movl_T2_r3});
}

/** function XXX **/
/* void  */ function gen_op_movl_r3_T0()
{
    gen_opc_ptr.push({func:op_movl_r3_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r3_T1()
{
    gen_opc_ptr.push({func:op_movl_r3_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r4()
{
    gen_opc_ptr.push({func:op_movl_T0_r4});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r4()
{
    gen_opc_ptr.push({func:op_movl_T1_r4});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r4()
{
    gen_opc_ptr.push({func:op_movl_T2_r4});
}

/** function XXX **/
/* void  */ function gen_op_movl_r4_T0()
{
    gen_opc_ptr.push({func:op_movl_r4_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r4_T1()
{
    gen_opc_ptr.push({func:op_movl_r4_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r5()
{
    gen_opc_ptr.push({func:op_movl_T0_r5});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r5()
{
    gen_opc_ptr.push({func:op_movl_T1_r5});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r5()
{
    gen_opc_ptr.push({func:op_movl_T2_r5});
}

/** function XXX **/
/* void  */ function gen_op_movl_r5_T0()
{
    gen_opc_ptr.push({func:op_movl_r5_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r5_T1()
{
    gen_opc_ptr.push({func:op_movl_r5_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r6()
{
    gen_opc_ptr.push({func:op_movl_T0_r6});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r6()
{
    gen_opc_ptr.push({func:op_movl_T1_r6});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r6()
{
    gen_opc_ptr.push({func:op_movl_T2_r6});
}

/** function XXX **/
/* void  */ function gen_op_movl_r6_T0()
{
    gen_opc_ptr.push({func:op_movl_r6_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r6_T1()
{
    gen_opc_ptr.push({func:op_movl_r6_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r7()
{
    gen_opc_ptr.push({func:op_movl_T0_r7});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r7()
{
    gen_opc_ptr.push({func:op_movl_T1_r7});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r7()
{
    gen_opc_ptr.push({func:op_movl_T2_r7});
}

/** function XXX **/
/* void  */ function gen_op_movl_r7_T0()
{
    gen_opc_ptr.push({func:op_movl_r7_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r7_T1()
{
    gen_opc_ptr.push({func:op_movl_r7_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r8()
{
    gen_opc_ptr.push({func:op_movl_T0_r8});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r8()
{
    gen_opc_ptr.push({func:op_movl_T1_r8});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r8()
{
    gen_opc_ptr.push({func:op_movl_T2_r8});
}

/** function XXX **/
/* void  */ function gen_op_movl_r8_T0()
{
    gen_opc_ptr.push({func:op_movl_r8_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r8_T1()
{
    gen_opc_ptr.push({func:op_movl_r8_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r9()
{
    gen_opc_ptr.push({func:op_movl_T0_r9});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r9()
{
    gen_opc_ptr.push({func:op_movl_T1_r9});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r9()
{
    gen_opc_ptr.push({func:op_movl_T2_r9});
}

/** function XXX **/
/* void  */ function gen_op_movl_r9_T0()
{
    gen_opc_ptr.push({func:op_movl_r9_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r9_T1()
{
    gen_opc_ptr.push({func:op_movl_r9_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r10()
{
    gen_opc_ptr.push({func:op_movl_T0_r10});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r10()
{
    gen_opc_ptr.push({func:op_movl_T1_r10});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r10()
{
    gen_opc_ptr.push({func:op_movl_T2_r10});
}

/** function XXX **/
/* void  */ function gen_op_movl_r10_T0()
{
    gen_opc_ptr.push({func:op_movl_r10_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r10_T1()
{
    gen_opc_ptr.push({func:op_movl_r10_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r11()
{
    gen_opc_ptr.push({func:op_movl_T0_r11});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r11()
{
    gen_opc_ptr.push({func:op_movl_T1_r11});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r11()
{
    gen_opc_ptr.push({func:op_movl_T2_r11});
}

/** function XXX **/
/* void  */ function gen_op_movl_r11_T0()
{
    gen_opc_ptr.push({func:op_movl_r11_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r11_T1()
{
    gen_opc_ptr.push({func:op_movl_r11_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r12()
{
    gen_opc_ptr.push({func:op_movl_T0_r12});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r12()
{
    gen_opc_ptr.push({func:op_movl_T1_r12});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r12()
{
    gen_opc_ptr.push({func:op_movl_T2_r12});
}

/** function XXX **/
/* void  */ function gen_op_movl_r12_T0()
{
    gen_opc_ptr.push({func:op_movl_r12_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r12_T1()
{
    gen_opc_ptr.push({func:op_movl_r12_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r13()
{
    gen_opc_ptr.push({func:op_movl_T0_r13});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r13()
{
    gen_opc_ptr.push({func:op_movl_T1_r13});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r13()
{
    gen_opc_ptr.push({func:op_movl_T2_r13});
}

/** function XXX **/
/* void  */ function gen_op_movl_r13_T0()
{
    gen_opc_ptr.push({func:op_movl_r13_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r13_T1()
{
    gen_opc_ptr.push({func:op_movl_r13_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r14()
{
    gen_opc_ptr.push({func:op_movl_T0_r14});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r14()
{
    gen_opc_ptr.push({func:op_movl_T1_r14});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r14()
{
    gen_opc_ptr.push({func:op_movl_T2_r14});
}

/** function XXX **/
/* void  */ function gen_op_movl_r14_T0()
{
    gen_opc_ptr.push({func:op_movl_r14_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r14_T1()
{
    gen_opc_ptr.push({func:op_movl_r14_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_r15()
{
    gen_opc_ptr.push({func:op_movl_T0_r15});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r15()
{
    gen_opc_ptr.push({func:op_movl_T1_r15});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_r15()
{
    gen_opc_ptr.push({func:op_movl_T2_r15});
}

/** function XXX **/
/* void  */ function gen_op_movl_r15_T0()
{
    gen_opc_ptr.push({func:op_movl_r15_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_r15_T1()
{
    gen_opc_ptr.push({func:op_movl_r15_T1});
}

/** function XXX **/
/* void  */ function gen_op_bx_T0()
{
    gen_opc_ptr.push({func:op_bx_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_0()
{
    gen_opc_ptr.push({func:op_movl_T0_0});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_im(param1)
{
    console.log("gen_op_movl_T0_im 0x" + param1.toString(16));
    gen_opc_ptr.push({func: op_movl_T0_im, param: param1 });
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_im(param1)
{
    ////gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_T1_im, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_mov_CF_T1()
{
    gen_opc_ptr.push({func:op_mov_CF_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_T2_im, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_addl_T1_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_addl_T1_im, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_addl_T1_T2()
{
    gen_opc_ptr.push({func:op_addl_T1_T2});
}

/** function XXX **/
/* void  */ function gen_op_subl_T1_T2()
{
    gen_opc_ptr.push({func:op_subl_T1_T2});
}

/** function XXX **/
/* void  */ function gen_op_addl_T0_T1()
{
    gen_opc_ptr.push({func:op_addl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_addl_T0_T1_cc()
{
    gen_opc_ptr.push({func:op_addl_T0_T1_cc});
}

/** function XXX **/
/* void  */ function gen_op_adcl_T0_T1()
{
    gen_opc_ptr.push({func:op_adcl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_adcl_T0_T1_cc()
{
    gen_opc_ptr.push({func:op_adcl_T0_T1_cc});
}

/** function XXX **/
/* void  */ function gen_op_subl_T0_T1()
{
    gen_opc_ptr.push({func:op_subl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_subl_T0_T1_cc()
{
    gen_opc_ptr.push({func:op_subl_T0_T1_cc});
}

/** function XXX **/
/* void  */ function gen_op_sbcl_T0_T1()
{
    gen_opc_ptr.push({func:op_sbcl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_sbcl_T0_T1_cc()
{
    gen_opc_ptr.push({func:op_sbcl_T0_T1_cc});
}

/** function XXX **/
/* void  */ function gen_op_rsbl_T0_T1()
{
    gen_opc_ptr.push({func:op_rsbl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_rsbl_T0_T1_cc()
{
    gen_opc_ptr.push({func:op_rsbl_T0_T1_cc});
}

/** function XXX **/
/* void  */ function gen_op_rscl_T0_T1()
{
    gen_opc_ptr.push({func:op_rscl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_rscl_T0_T1_cc()
{
    gen_opc_ptr.push({func:op_rscl_T0_T1_cc});
}

/** function XXX **/
/* void  */ function gen_op_andl_T0_T1()
{
    gen_opc_ptr.push({func:op_andl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_xorl_T0_T1()
{
    gen_opc_ptr.push({func:op_xorl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_orl_T0_T1()
{
    gen_opc_ptr.push({func:op_orl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_bicl_T0_T1()
{
    gen_opc_ptr.push({func:op_bicl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_notl_T0()
{
    gen_opc_ptr.push({func:op_notl_T0});
}

/** function XXX **/
/* void  */ function gen_op_notl_T1()
{
    gen_opc_ptr.push({func:op_notl_T1});
}

/** function XXX **/
/* void  */ function gen_op_logic_T0_cc()
{
    gen_opc_ptr.push({func:op_logic_T0_cc});
}

/** function XXX **/
/* void  */ function gen_op_logic_T1_cc()
{
    gen_opc_ptr.push({func:op_logic_T1_cc});
}

/** function XXX **/
/* void  */ function gen_op_test_eq(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_eq, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_ne(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_ne, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_cs(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_cs, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_cc(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_cc, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_mi(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_mi, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_test_pl(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_pl, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_vs(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_vs, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_vc(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_vc, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_hi(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_hi, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_ls(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_ls, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_ge(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_ge, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_lt(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_lt, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_gt(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_gt, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_le(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_le, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_test_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_test_T0, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_testn_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_testn_T0, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_goto_tb0(param1)
{
    console.log("gen_op_goto_tb0 param 0x" + param1.toString(16));
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_goto_tb0, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_goto_tb1(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_goto_tb1, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_exit_tb()
{
    gen_opc_ptr.push({func:op_exit_tb});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_spsr()
{
    gen_opc_ptr.push({func:op_movl_T0_spsr});
}

/** function XXX **/
/* void  */ function gen_op_movl_spsr_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_spsr_T0, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_mul_T0_T1()
{
    gen_opc_ptr.push({func:op_mul_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_mull_T0_T1()
{
    gen_opc_ptr.push({func:op_mull_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_imull_T0_T1()
{
    gen_opc_ptr.push({func:op_imull_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_imulw_T0_T1()
{
    gen_opc_ptr.push({func:op_imulw_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_addq_T0_T1(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_addq_T0_T1, param: param1, param2: param2});
}

/** function XXX **/
/* void  */ function gen_op_addq_lo_T0_T1(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_addq_lo_T0_T1, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_addq_T0_T1_dual(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_addq_T0_T1_dual, param: param1, param2: param2});
}

/** function XXX **/
/* void  */ function gen_op_subq_T0_T1_dual(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_subq_T0_T1_dual, param: param1, param2: param2});
}

/** function XXX **/
/* void  */ function gen_op_logicq_cc()
{
    gen_opc_ptr.push({func:op_logicq_cc});
}

/** function XXX **/
/* void  */ function gen_op_ldub_raw()
{
    gen_opc_ptr.push({func:op_ldub_raw});
}

/** function XXX **/
/* void  */ function gen_op_ldsb_raw()
{
    gen_opc_ptr.push({func:op_ldsb_raw});
}

/** function XXX **/
/* void  */ function gen_op_lduw_raw()
{
    gen_opc_ptr.push({func:op_lduw_raw});
}

/** function XXX **/
/* void  */ function gen_op_ldsw_raw()
{
    gen_opc_ptr.push({func:op_ldsw_raw});
}

/** function XXX **/
/* void  */ function gen_op_ldl_raw()
{
    gen_opc_ptr.push({func:op_ldl_raw});
}

/** function XXX **/
/* void  */ function gen_op_stb_raw()
{
    gen_opc_ptr.push({func:op_stb_raw});
}

/** function XXX **/
/* void  */ function gen_op_stw_raw()
{
    gen_opc_ptr.push({func:op_stw_raw});
}

/** function XXX **/
/* void  */ function gen_op_stl_raw()
{
    gen_opc_ptr.push({func:op_stl_raw});
}

/** function XXX **/
/* void  */ function gen_op_vfp_lds_raw()
{
    gen_opc_ptr.push({func:op_vfp_lds_raw});
}

/** function XXX **/
/* void  */ function gen_op_vfp_sts_raw()
{
    gen_opc_ptr.push({func:op_vfp_sts_raw});
}

/** function XXX **/
/* void  */ function gen_op_vfp_ldd_raw()
{
    gen_opc_ptr.push({func:op_vfp_ldd_raw});
}

/** function XXX **/
/* void  */ function gen_op_vfp_std_raw()
{
    gen_opc_ptr.push({func:op_vfp_std_raw});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_ldb_raw()
{
    gen_opc_ptr.push({func:op_iwmmxt_ldb_raw});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_stb_raw()
{
    gen_opc_ptr.push({func:op_iwmmxt_stb_raw});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_ldw_raw()
{
    gen_opc_ptr.push({func:op_iwmmxt_ldw_raw});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_stw_raw()
{
    gen_opc_ptr.push({func:op_iwmmxt_stw_raw});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_ldl_raw()
{
    gen_opc_ptr.push({func:op_iwmmxt_ldl_raw});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_stl_raw()
{
    gen_opc_ptr.push({func:op_iwmmxt_stl_raw});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_ldq_raw()
{
    gen_opc_ptr.push({func:op_iwmmxt_ldq_raw});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_stq_raw()
{
    gen_opc_ptr.push({func:op_iwmmxt_stq_raw});
}

/** function XXX **/
/* void  */ function gen_op_shll_T0_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_shll_T0_im, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_shll_T1_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_shll_T1_im, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_shrl_T1_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_shrl_T1_im, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_shrl_T1_0()
{
    gen_opc_ptr.push({func:op_shrl_T1_0});
}

/** function XXX **/
/* void  */ function gen_op_sarl_T1_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_sarl_T1_im, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_sarl_T1_0()
{
    gen_opc_ptr.push({func:op_sarl_T1_0});
}

/** function XXX **/
/* void  */ function gen_op_rorl_T1_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_rorl_T1_im, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_rrxl_T1()
{
    gen_opc_ptr.push({func:op_rrxl_T1});
}

/** function XXX **/
/* void  */ function gen_op_shll_T1_im_cc(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_shll_T1_im_cc, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_shrl_T1_im_cc(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_shrl_T1_im_cc, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_shrl_T1_0_cc()
{
    gen_opc_ptr.push({func:op_shrl_T1_0_cc});
}

/** function XXX **/
/* void  */ function gen_op_sarl_T1_im_cc(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_sarl_T1_im_cc, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_sarl_T1_0_cc()
{
    gen_opc_ptr.push({func:op_sarl_T1_0_cc});
}

/** function XXX **/
/* void  */ function gen_op_rorl_T1_im_cc(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_rorl_T1_im_cc, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_rrxl_T1_cc()
{
    gen_opc_ptr.push({func:op_rrxl_T1_cc});
}

/** function XXX **/
/* void  */ function gen_op_shll_T2_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_shll_T2_im, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_shrl_T2_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_shrl_T2_im, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_shrl_T2_0()
{
    gen_opc_ptr.push({func:op_shrl_T2_0});
}

/** function XXX **/
/* void  */ function gen_op_sarl_T2_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_sarl_T2_im, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_sarl_T2_0()
{
    gen_opc_ptr.push({func:op_sarl_T2_0});
}

/** function XXX **/
/* void  */ function gen_op_rorl_T2_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_rorl_T2_im, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_rrxl_T2()
{
    gen_opc_ptr.push({func:op_rrxl_T2});
}

/** function XXX **/
/* void  */ function gen_op_shll_T1_T0()
{
    gen_opc_ptr.push({func:op_shll_T1_T0});
}

/** function XXX **/
/* void  */ function gen_op_shrl_T1_T0()
{
    gen_opc_ptr.push({func:op_shrl_T1_T0});
}

/** function XXX **/
/* void  */ function gen_op_sarl_T1_T0()
{
    gen_opc_ptr.push({func:op_sarl_T1_T0});
}

/** function XXX **/
/* void  */ function gen_op_rorl_T1_T0()
{
    gen_opc_ptr.push({func:op_rorl_T1_T0});
}

/** function XXX **/
/* void  */ function gen_op_shll_T1_T0_cc()
{
    gen_opc_ptr.push({func:op_shll_T1_T0_cc});
}

/** function XXX **/
/* void  */ function gen_op_shrl_T1_T0_cc()
{
    gen_opc_ptr.push({func:op_shrl_T1_T0_cc});
}

/** function XXX **/
/* void  */ function gen_op_sarl_T1_T0_cc()
{
    gen_opc_ptr.push({func:op_sarl_T1_T0_cc});
}

/** function XXX **/
/* void  */ function gen_op_rorl_T1_T0_cc()
{
    gen_opc_ptr.push({func:op_rorl_T1_T0_cc});
}

/** function XXX **/
/* void  */ function gen_op_clz_T0()
{
    gen_opc_ptr.push({func:op_clz_T0});
}

/** function XXX **/
/* void  */ function gen_op_sarl_T0_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_sarl_T0_im});
}

/** function XXX **/
/* void  */ function gen_op_sxth_T0()
{
    gen_opc_ptr.push({func:op_sxth_T0});
}

/** function XXX **/
/* void  */ function gen_op_sxth_T1()
{
    gen_opc_ptr.push({func:op_sxth_T1});
}

/** function XXX **/
/* void  */ function gen_op_sxtb_T1()
{
    gen_opc_ptr.push({func:op_sxtb_T1});
}

/** function XXX **/
/* void  */ function gen_op_uxtb_T1()
{
    gen_opc_ptr.push({func:op_uxtb_T1});
}

/** function XXX **/
/* void  */ function gen_op_uxth_T1()
{
    gen_opc_ptr.push({func:op_uxth_T1});
}

/** function XXX **/
/* void  */ function gen_op_sxtb16_T1()
{
    gen_opc_ptr.push({func:op_sxtb16_T1});
}

/** function XXX **/
/* void  */ function gen_op_uxtb16_T1()
{
    gen_opc_ptr.push({func:op_uxtb16_T1});
}

/** function XXX **/
/* void  */ function gen_op_addl_T0_T1_setq()
{
    gen_opc_ptr.push({func:op_addl_T0_T1_setq});
}

/** function XXX **/
/* void  */ function gen_op_addl_T0_T1_saturate()
{
    gen_opc_ptr.push({func:op_addl_T0_T1_saturate});
}

/** function XXX **/
/* void  */ function gen_op_subl_T0_T1_saturate()
{
    gen_opc_ptr.push({func:op_subl_T0_T1_saturate});
}

/** function XXX **/
/* void  */ function gen_op_double_T1_saturate()
{
    gen_opc_ptr.push({func:op_double_T1_saturate});
}

/** function XXX **/
/* void  */ function gen_op_addl_T0_T1_usaturate()
{
    gen_opc_ptr.push({func:op_addl_T0_T1_usaturate});
}

/** function XXX **/
/* void  */ function gen_op_subl_T0_T1_usaturate()
{
    gen_opc_ptr.push({func:op_subl_T0_T1_usaturate});
}

/** function XXX **/
/* void  */ function gen_op_shll_T0_im_thumb_cc(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_shll_T0_im_thumb_cc, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_shll_T0_im_thumb(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_shll_T0_im_thumb, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_shrl_T0_im_thumb_cc(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_shrl_T0_im_thumb_cc, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_shrl_T0_im_thumb(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_shrl_T0_im_thumb, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_sarl_T0_im_thumb_cc(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_sarl_T0_im_thumb_cc, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_sarl_T0_im_thumb(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_sarl_T0_im_thumb, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_negs()
{
    gen_opc_ptr.push({func:op_vfp_negs});
}

/** function XXX **/
/* void  */ function gen_op_vfp_negd()
{
    gen_opc_ptr.push({func:op_vfp_negd});
}

/** function XXX **/
/* void  */ function gen_op_vfp_F1_ld0s()
{
    gen_opc_ptr.push({func:op_vfp_F1_ld0s});
}

/** function XXX **/
/* void  */ function gen_op_vfp_F1_ld0d()
{
    gen_opc_ptr.push({func:op_vfp_F1_ld0d});
}

/** function XXX **/
/* void  */ function gen_op_vfp_getreg_F0d(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_getreg_F0d, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_getreg_F0s(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_getreg_F0s, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_getreg_F1d(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_getreg_F1d, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_getreg_F1s(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_getreg_F1s, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_setreg_F0d(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_setreg_F0d, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_setreg_F0s(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_setreg_F0s, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_movl_T0_fpscr_flags()
{
    gen_opc_ptr.push({func:op_vfp_movl_T0_fpscr_flags});
}

/** function XXX **/
/* void  */ function gen_op_vfp_movl_T0_xreg(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_movl_T0_xreg, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_movl_xreg_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_movl_xreg_T0, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_mrs()
{
    gen_opc_ptr.push({func:op_vfp_mrs});
}

/** function XXX **/
/* void  */ function gen_op_vfp_msr()
{
    gen_opc_ptr.push({func:op_vfp_msr});
}

/** function XXX **/
/* void  */ function gen_op_vfp_mrrd()
{
    gen_opc_ptr.push({func:op_vfp_mrrd});
}

/** function XXX **/
/* void  */ function gen_op_vfp_mdrr()
{
    gen_opc_ptr.push({func:op_vfp_mdrr});
}

/** function XXX **/
/* void  */ function gen_op_vfp_fconstd(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_fconstd, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_fconsts(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_fconsts, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_signbit_T1_T0()
{
    gen_opc_ptr.push({func:op_signbit_T1_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_user(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_T0_user, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_movl_user_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_user_T0, param: param1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_T1()
{
    gen_opc_ptr.push({func:op_movl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_T2()
{
    gen_opc_ptr.push({func:op_movl_T0_T2});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_T0()
{
    gen_opc_ptr.push({func:op_movl_T1_T0});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_T2()
{
    gen_opc_ptr.push({func:op_movl_T1_T2});
}

/** function XXX **/
/* void  */ function gen_op_movl_T2_T0()
{
    gen_opc_ptr.push({func:op_movl_T2_T0});
}

/** function XXX **/
/* void  */ function gen_op_qadd16_T0_T1()
{
    gen_opc_ptr.push({func:op_qadd16_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_qadd8_T0_T1()
{
    gen_opc_ptr.push({func:op_qadd8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_qsub16_T0_T1()
{
    gen_opc_ptr.push({func:op_qsub16_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_qsub8_T0_T1()
{
    gen_opc_ptr.push({func:op_qsub8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_qsubaddx_T0_T1()
{
    gen_opc_ptr.push({func:op_qsubaddx_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_qaddsubx_T0_T1()
{
    gen_opc_ptr.push({func:op_qaddsubx_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uqadd16_T0_T1()
{
    gen_opc_ptr.push({func:op_uqadd16_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uqadd8_T0_T1()
{
    gen_opc_ptr.push({func:op_uqadd8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uqsub16_T0_T1()
{
    gen_opc_ptr.push({func:op_uqsub16_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uqsub8_T0_T1()
{
    gen_opc_ptr.push({func:op_uqsub8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uqsubaddx_T0_T1()
{
    gen_opc_ptr.push({func:op_uqsubaddx_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uqaddsubx_T0_T1()
{
    gen_opc_ptr.push({func:op_uqaddsubx_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_sadd16_T0_T1()
{
    gen_opc_ptr.push({func:op_sadd16_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_sadd8_T0_T1()
{
    gen_opc_ptr.push({func:op_sadd8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_ssub16_T0_T1()
{
    gen_opc_ptr.push({func:op_ssub16_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_ssub8_T0_T1()
{
    gen_opc_ptr.push({func:op_ssub8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_ssubaddx_T0_T1()
{
    gen_opc_ptr.push({func:op_ssubaddx_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_saddsubx_T0_T1()
{
    gen_opc_ptr.push({func:op_saddsubx_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uadd16_T0_T1()
{
    gen_opc_ptr.push({func:op_uadd16_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uadd8_T0_T1()
{
    gen_opc_ptr.push({func:op_uadd8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_usub16_T0_T1()
{
    gen_opc_ptr.push({func:op_usub16_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_usub8_T0_T1()
{
    gen_opc_ptr.push({func:op_usub8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_usubaddx_T0_T1()
{
    gen_opc_ptr.push({func:op_usubaddx_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uaddsubx_T0_T1()
{
    gen_opc_ptr.push({func:op_uaddsubx_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_shadd16_T0_T1()
{
    gen_opc_ptr.push({func:op_shadd16_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_shadd8_T0_T1()
{
    gen_opc_ptr.push({func:op_shadd8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_shsub16_T0_T1()
{
    gen_opc_ptr.push({func:op_shsub16_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_shsub8_T0_T1()
{
    gen_opc_ptr.push({func:op_shsub8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_shsubaddx_T0_T1()
{
    gen_opc_ptr.push({func:op_shsubaddx_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_shaddsubx_T0_T1()
{
    gen_opc_ptr.push({func:op_shaddsubx_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uhadd16_T0_T1()
{
    gen_opc_ptr.push({func:op_uhadd16_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uhadd8_T0_T1()
{
    gen_opc_ptr.push({func:op_uhadd8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uhsub16_T0_T1()
{
    gen_opc_ptr.push({func:op_uhsub16_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uhsub8_T0_T1()
{
    gen_opc_ptr.push({func:op_uhsub8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uhsubaddx_T0_T1()
{
    gen_opc_ptr.push({func:op_uhsubaddx_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_uhaddsubx_T0_T1()
{
    gen_opc_ptr.push({func:op_uhaddsubx_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_pkhtb_T0_T1()
{
    gen_opc_ptr.push({func:op_pkhtb_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_pkhbt_T0_T1()
{
    gen_opc_ptr.push({func:op_pkhbt_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_rev_T0()
{
    gen_opc_ptr.push({func:op_rev_T0});
}

/** function XXX **/
/* void  */ function gen_op_revh_T0()
{
    gen_opc_ptr.push({func:op_revh_T0});
}

/** function XXX **/
/* void  */ function gen_op_rev16_T0()
{
    gen_opc_ptr.push({func:op_rev16_T0});
}

/** function XXX **/
/* void  */ function gen_op_revsh_T0()
{
    gen_opc_ptr.push({func:op_revsh_T0});
}

/** function XXX **/
/* void  */ function gen_op_rbit_T0()
{
    gen_opc_ptr.push({func:op_rbit_T0});
}

/** function XXX **/
/* void  */ function gen_op_swap_half_T1()
{
    gen_opc_ptr.push({func:op_swap_half_T1});
}

/** function XXX **/
/* void  */ function gen_op_mul_dual_T0_T1()
{
    gen_opc_ptr.push({func:op_mul_dual_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_sel_T0_T1()
{
    gen_opc_ptr.push({func:op_sel_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_roundqd_T0_T1()
{
    gen_opc_ptr.push({func:op_roundqd_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_ssat_T1(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_ssat_T1, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_ssat16_T1(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_ssat16_T1, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_usat_T1(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_usat_T1, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_usat16_T1(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_usat16_T1, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_add16_T1_T2()
{
    gen_opc_ptr.push({func:op_add16_T1_T2});
}

/** function XXX **/
/* void  */ function gen_op_usad8_T0_T1()
{
    gen_opc_ptr.push({func:op_usad8_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_bfi_T1_T0(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_bfi_T1_T0, param:param1, param2: param2});
}

/** function XXX **/
/* void  */ function gen_op_ubfx_T1(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_ubfx_T1, param:param1, param2:param2});
}

/** function XXX **/
/* void  */ function gen_op_sbfx_T1(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_sbfx_T1, param:param1, param2:param2});
}

/** function XXX **/
/* void  */ function gen_op_movtop_T0_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movtop_T0_im, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_jmp_T0_im(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_jmp_T0_im, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_set_condexec(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_set_condexec, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_sdivl_T0_T1()
{
    gen_opc_ptr.push({func:op_sdivl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_udivl_T0_T1()
{
    gen_opc_ptr.push({func:op_udivl_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_sp(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_T0_sp, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_neon_getreg_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_neon_getreg_T0, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_neon_getreg_T1(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_neon_getreg_T1, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_neon_getreg_T2(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_neon_getreg_T2, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_neon_setreg_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_neon_setreg_T0, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_neon_setreg_T1(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_neon_setreg_T1, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_neon_setreg_T2(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_neon_setreg_T2, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_neon_hadd_s8()
{
    gen_opc_ptr.push({func:op_neon_hadd_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_hadd_u8()
{
    gen_opc_ptr.push({func:op_neon_hadd_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_hadd_s16()
{
    gen_opc_ptr.push({func:op_neon_hadd_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_hadd_u16()
{
    gen_opc_ptr.push({func:op_neon_hadd_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_hadd_s32()
{
    gen_opc_ptr.push({func:op_neon_hadd_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_hadd_u32()
{
    gen_opc_ptr.push({func:op_neon_hadd_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_rhadd_s8()
{
    gen_opc_ptr.push({func:op_neon_rhadd_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_rhadd_u8()
{
    gen_opc_ptr.push({func:op_neon_rhadd_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_rhadd_s16()
{
    gen_opc_ptr.push({func:op_neon_rhadd_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_rhadd_u16()
{
    gen_opc_ptr.push({func:op_neon_rhadd_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_rhadd_s32()
{
    gen_opc_ptr.push({func:op_neon_rhadd_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_rhadd_u32()
{
    gen_opc_ptr.push({func:op_neon_rhadd_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_hsub_s8()
{
    gen_opc_ptr.push({func:op_neon_hsub_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_hsub_u8()
{
    gen_opc_ptr.push({func:op_neon_hsub_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_hsub_s16()
{
    gen_opc_ptr.push({func:op_neon_hsub_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_hsub_u16()
{
    gen_opc_ptr.push({func:op_neon_hsub_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_hsub_s32()
{
    gen_opc_ptr.push({func:op_neon_hsub_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_hsub_u32()
{
    gen_opc_ptr.push({func:op_neon_hsub_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_bsl()
{
    gen_opc_ptr.push({func:op_neon_bsl});
}

/** function XXX **/
/* void  */ function gen_op_neon_bit()
{
    gen_opc_ptr.push({func:op_neon_bit});
}

/** function XXX **/
/* void  */ function gen_op_neon_bif()
{
    gen_opc_ptr.push({func:op_neon_bif});
}

/** function XXX **/
/* void  */ function gen_op_neon_qadd_u8()
{
    gen_opc_ptr.push({func:op_neon_qadd_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_qadd_u16()
{
    gen_opc_ptr.push({func:op_neon_qadd_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_qadd_s8()
{
    gen_opc_ptr.push({func:op_neon_qadd_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_qadd_s16()
{
    gen_opc_ptr.push({func:op_neon_qadd_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_qsub_u8()
{
    gen_opc_ptr.push({func:op_neon_qsub_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_qsub_u16()
{
    gen_opc_ptr.push({func:op_neon_qsub_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_qsub_s8()
{
    gen_opc_ptr.push({func:op_neon_qsub_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_qsub_s16()
{
    gen_opc_ptr.push({func:op_neon_qsub_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_cgt_s8()
{
    gen_opc_ptr.push({func:op_neon_cgt_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_cgt_u8()
{
    gen_opc_ptr.push({func:op_neon_cgt_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_cgt_s16()
{
    gen_opc_ptr.push({func:op_neon_cgt_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_cgt_u16()
{
    gen_opc_ptr.push({func:op_neon_cgt_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_cgt_s32()
{
    gen_opc_ptr.push({func:op_neon_cgt_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_cgt_u32()
{
    gen_opc_ptr.push({func:op_neon_cgt_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_cge_s8()
{
    gen_opc_ptr.push({func:op_neon_cge_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_cge_u8()
{
    gen_opc_ptr.push({func:op_neon_cge_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_cge_s16()
{
    gen_opc_ptr.push({func:op_neon_cge_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_cge_u16()
{
    gen_opc_ptr.push({func:op_neon_cge_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_cge_s32()
{
    gen_opc_ptr.push({func:op_neon_cge_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_cge_u32()
{
    gen_opc_ptr.push({func:op_neon_cge_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_shl_s8()
{
    gen_opc_ptr.push({func:op_neon_shl_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_shl_u8()
{
    gen_opc_ptr.push({func:op_neon_shl_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_shl_s16()
{
    gen_opc_ptr.push({func:op_neon_shl_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_shl_u16()
{
    gen_opc_ptr.push({func:op_neon_shl_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_shl_s32()
{
    gen_opc_ptr.push({func:op_neon_shl_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_shl_u32()
{
    gen_opc_ptr.push({func:op_neon_shl_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_shl_u64()
{
    gen_opc_ptr.push({func:op_neon_shl_u64});
}

/** function XXX **/
/* void  */ function gen_op_neon_shl_s64()
{
    gen_opc_ptr.push({func:op_neon_shl_s64});
}

/** function XXX **/
/* void  */ function gen_op_neon_rshl_s8()
{
    gen_opc_ptr.push({func:op_neon_rshl_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_rshl_u8()
{
    gen_opc_ptr.push({func:op_neon_rshl_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_rshl_s16()
{
    gen_opc_ptr.push({func:op_neon_rshl_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_rshl_u16()
{
    gen_opc_ptr.push({func:op_neon_rshl_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_rshl_s32()
{
    gen_opc_ptr.push({func:op_neon_rshl_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_rshl_u32()
{
    gen_opc_ptr.push({func:op_neon_rshl_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_rshl_u64()
{
    gen_opc_ptr.push({func:op_neon_rshl_u64});
}

/** function XXX **/
/* void  */ function gen_op_neon_rshl_s64()
{
    gen_opc_ptr.push({func:op_neon_rshl_s64});
}

/** function XXX **/
/* void  */ function gen_op_neon_qshl_s8()
{
    gen_opc_ptr.push({func:op_neon_qshl_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_qshl_s16()
{
    gen_opc_ptr.push({func:op_neon_qshl_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_qshl_s32()
{
    gen_opc_ptr.push({func:op_neon_qshl_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_qshl_s64()
{
    gen_opc_ptr.push({func:op_neon_qshl_s64});
}

/** function XXX **/
/* void  */ function gen_op_neon_qshl_u8()
{
    gen_opc_ptr.push({func:op_neon_qshl_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_qshl_u16()
{
    gen_opc_ptr.push({func:op_neon_qshl_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_qshl_u32()
{
    gen_opc_ptr.push({func:op_neon_qshl_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_qshl_u64()
{
    gen_opc_ptr.push({func:op_neon_qshl_u64});
}

/** function XXX **/
/* void  */ function gen_op_neon_qrshl_s8()
{
    gen_opc_ptr.push({func:op_neon_qrshl_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_qrshl_s16()
{
    gen_opc_ptr.push({func:op_neon_qrshl_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_qrshl_s32()
{
    gen_opc_ptr.push({func:op_neon_qrshl_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_qrshl_u8()
{
    gen_opc_ptr.push({func:op_neon_qrshl_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_qrshl_u16()
{
    gen_opc_ptr.push({func:op_neon_qrshl_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_qrshl_u32()
{
    gen_opc_ptr.push({func:op_neon_qrshl_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_max_s8()
{
    gen_opc_ptr.push({func:op_neon_max_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_max_u8()
{
    gen_opc_ptr.push({func:op_neon_max_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_max_s16()
{
    gen_opc_ptr.push({func:op_neon_max_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_max_u16()
{
    gen_opc_ptr.push({func:op_neon_max_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_max_s32()
{
    gen_opc_ptr.push({func:op_neon_max_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_max_u32()
{
    gen_opc_ptr.push({func:op_neon_max_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_pmax_s8()
{
    gen_opc_ptr.push({func:op_neon_pmax_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_pmax_u8()
{
    gen_opc_ptr.push({func:op_neon_pmax_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_pmax_s16()
{
    gen_opc_ptr.push({func:op_neon_pmax_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_pmax_u16()
{
    gen_opc_ptr.push({func:op_neon_pmax_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_min_s8()
{
    gen_opc_ptr.push({func:op_neon_min_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_min_u8()
{
    gen_opc_ptr.push({func:op_neon_min_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_min_s16()
{
    gen_opc_ptr.push({func:op_neon_min_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_min_u16()
{
    gen_opc_ptr.push({func:op_neon_min_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_min_s32()
{
    gen_opc_ptr.push({func:op_neon_min_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_min_u32()
{
    gen_opc_ptr.push({func:op_neon_min_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_pmin_s8()
{
    gen_opc_ptr.push({func:op_neon_pmin_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_pmin_u8()
{
    gen_opc_ptr.push({func:op_neon_pmin_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_pmin_s16()
{
    gen_opc_ptr.push({func:op_neon_pmin_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_pmin_u16()
{
    gen_opc_ptr.push({func:op_neon_pmin_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_abd_s8()
{
    gen_opc_ptr.push({func:op_neon_abd_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_abd_u8()
{
    gen_opc_ptr.push({func:op_neon_abd_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_abd_s16()
{
    gen_opc_ptr.push({func:op_neon_abd_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_abd_u16()
{
    gen_opc_ptr.push({func:op_neon_abd_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_abd_s32()
{
    gen_opc_ptr.push({func:op_neon_abd_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_abd_u32()
{
    gen_opc_ptr.push({func:op_neon_abd_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_add_u8()
{
    gen_opc_ptr.push({func:op_neon_add_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_add_u16()
{
    gen_opc_ptr.push({func:op_neon_add_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_padd_u8()
{
    gen_opc_ptr.push({func:op_neon_padd_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_padd_u16()
{
    gen_opc_ptr.push({func:op_neon_padd_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_sub_u8()
{
    gen_opc_ptr.push({func:op_neon_sub_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_sub_u16()
{
    gen_opc_ptr.push({func:op_neon_sub_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_rsb_u8()
{
    gen_opc_ptr.push({func:op_neon_rsb_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_rsb_u16()
{
    gen_opc_ptr.push({func:op_neon_rsb_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_mul_u8()
{
    gen_opc_ptr.push({func:op_neon_mul_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_mul_u16()
{
    gen_opc_ptr.push({func:op_neon_mul_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_tst_u8()
{
    gen_opc_ptr.push({func:op_neon_tst_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_tst_u16()
{
    gen_opc_ptr.push({func:op_neon_tst_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_tst_u32()
{
    gen_opc_ptr.push({func:op_neon_tst_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_ceq_u8()
{
    gen_opc_ptr.push({func:op_neon_ceq_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_ceq_u16()
{
    gen_opc_ptr.push({func:op_neon_ceq_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_ceq_u32()
{
    gen_opc_ptr.push({func:op_neon_ceq_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_qdmulh_s16()
{
    gen_opc_ptr.push({func:op_neon_qdmulh_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_qrdmulh_s16()
{
    gen_opc_ptr.push({func:op_neon_qrdmulh_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_qdmulh_s32()
{
    gen_opc_ptr.push({func:op_neon_qdmulh_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_qrdmulh_s32()
{
    gen_opc_ptr.push({func:op_neon_qrdmulh_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_u8()
{
    gen_opc_ptr.push({func:op_neon_narrow_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_sat_u8()
{
    gen_opc_ptr.push({func:op_neon_narrow_sat_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_sat_s8()
{
    gen_opc_ptr.push({func:op_neon_narrow_sat_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_u16()
{
    gen_opc_ptr.push({func:op_neon_narrow_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_sat_u16()
{
    gen_opc_ptr.push({func:op_neon_narrow_sat_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_sat_s16()
{
    gen_opc_ptr.push({func:op_neon_narrow_sat_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_sat_u32()
{
    gen_opc_ptr.push({func:op_neon_narrow_sat_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_sat_s32()
{
    gen_opc_ptr.push({func:op_neon_narrow_sat_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_high_u8()
{
    gen_opc_ptr.push({func:op_neon_narrow_high_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_high_u16()
{
    gen_opc_ptr.push({func:op_neon_narrow_high_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_high_round_u8()
{
    gen_opc_ptr.push({func:op_neon_narrow_high_round_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_high_round_u16()
{
    gen_opc_ptr.push({func:op_neon_narrow_high_round_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_narrow_high_round_u32()
{
    gen_opc_ptr.push({func:op_neon_narrow_high_round_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_widen_s8()
{
    gen_opc_ptr.push({func:op_neon_widen_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_widen_u8()
{
    gen_opc_ptr.push({func:op_neon_widen_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_widen_s16()
{
    gen_opc_ptr.push({func:op_neon_widen_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_widen_u16()
{
    gen_opc_ptr.push({func:op_neon_widen_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_widen_s32()
{
    gen_opc_ptr.push({func:op_neon_widen_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_widen_high_u8()
{
    gen_opc_ptr.push({func:op_neon_widen_high_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_widen_high_u16()
{
    gen_opc_ptr.push({func:op_neon_widen_high_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_shll_u16(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_neon_shll_u16, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_neon_shll_u64(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_neon_shll_u64, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_neon_addl_u16()
{
    gen_opc_ptr.push({func:op_neon_addl_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_addl_u32()
{
    gen_opc_ptr.push({func:op_neon_addl_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_addl_u64()
{
    gen_opc_ptr.push({func:op_neon_addl_u64});
}

/** function XXX **/
/* void  */ function gen_op_neon_subl_u16()
{
    gen_opc_ptr.push({func:op_neon_subl_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_subl_u32()
{
    gen_opc_ptr.push({func:op_neon_subl_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_subl_u64()
{
    gen_opc_ptr.push({func:op_neon_subl_u64});
}

/** function XXX **/
/* void  */ function gen_op_neon_abdl_u16()
{
    gen_opc_ptr.push({func:op_neon_abdl_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_abdl_s16()
{
    gen_opc_ptr.push({func:op_neon_abdl_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_abdl_u32()
{
    gen_opc_ptr.push({func:op_neon_abdl_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_abdl_s32()
{
    gen_opc_ptr.push({func:op_neon_abdl_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_abdl_u64()
{
    gen_opc_ptr.push({func:op_neon_abdl_u64});
}

/** function XXX **/
/* void  */ function gen_op_neon_abdl_s64()
{
    gen_opc_ptr.push({func:op_neon_abdl_s64});
}

/** function XXX **/
/* void  */ function gen_op_neon_mull_u8()
{
    gen_opc_ptr.push({func:op_neon_mull_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_mull_s8()
{
    gen_opc_ptr.push({func:op_neon_mull_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_mull_u16()
{
    gen_opc_ptr.push({func:op_neon_mull_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_mull_s16()
{
    gen_opc_ptr.push({func:op_neon_mull_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_addl_saturate_s32()
{
    gen_opc_ptr.push({func:op_neon_addl_saturate_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_addl_saturate_s64()
{
    gen_opc_ptr.push({func:op_neon_addl_saturate_s64});
}

/** function XXX **/
/* void  */ function gen_op_neon_addl_saturate_u64()
{
    gen_opc_ptr.push({func:op_neon_addl_saturate_u64});
}

/** function XXX **/
/* void  */ function gen_op_neon_subl_saturate_s64()
{
    gen_opc_ptr.push({func:op_neon_subl_saturate_s64});
}

/** function XXX **/
/* void  */ function gen_op_neon_subl_saturate_u64()
{
    gen_opc_ptr.push({func:op_neon_subl_saturate_u64});
}

/** function XXX **/
/* void  */ function gen_op_neon_negl_u16()
{
    gen_opc_ptr.push({func:op_neon_negl_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_negl_u32()
{
    gen_opc_ptr.push({func:op_neon_negl_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_negl_u64()
{
    gen_opc_ptr.push({func:op_neon_negl_u64});
}

/** function XXX **/
/* void  */ function gen_op_neon_dup_low16()
{
    gen_opc_ptr.push({func:op_neon_dup_low16});
}

/** function XXX **/
/* void  */ function gen_op_neon_dup_high16()
{
    gen_opc_ptr.push({func:op_neon_dup_high16});
}

/** function XXX **/
/* void  */ function gen_op_neon_extract(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_neon_extract, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_neon_paddl_s8()
{
    gen_opc_ptr.push({func:op_neon_paddl_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_paddl_u8()
{
    gen_opc_ptr.push({func:op_neon_paddl_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_paddl_s16()
{
    gen_opc_ptr.push({func:op_neon_paddl_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_paddl_u16()
{
    gen_opc_ptr.push({func:op_neon_paddl_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_paddl_s32()
{
    gen_opc_ptr.push({func:op_neon_paddl_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_paddl_u32()
{
    gen_opc_ptr.push({func:op_neon_paddl_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_clz_u8()
{
    gen_opc_ptr.push({func:op_neon_clz_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_clz_u16()
{
    gen_opc_ptr.push({func:op_neon_clz_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_cls_s8()
{
    gen_opc_ptr.push({func:op_neon_cls_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_cls_s16()
{
    gen_opc_ptr.push({func:op_neon_cls_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_cls_s32()
{
    gen_opc_ptr.push({func:op_neon_cls_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_cnt_u8()
{
    gen_opc_ptr.push({func:op_neon_cnt_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_qabs_s8()
{
    gen_opc_ptr.push({func:op_neon_qabs_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_qneg_s8()
{
    gen_opc_ptr.push({func:op_neon_qneg_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_qabs_s16()
{
    gen_opc_ptr.push({func:op_neon_qabs_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_qneg_s16()
{
    gen_opc_ptr.push({func:op_neon_qneg_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_qabs_s32()
{
    gen_opc_ptr.push({func:op_neon_qabs_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_qneg_s32()
{
    gen_opc_ptr.push({func:op_neon_qneg_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_abs_s8()
{
    gen_opc_ptr.push({func:op_neon_abs_s8});
}

/** function XXX **/
/* void  */ function gen_op_neon_abs_s16()
{
    gen_opc_ptr.push({func:op_neon_abs_s16});
}

/** function XXX **/
/* void  */ function gen_op_neon_abs_s32()
{
    gen_opc_ptr.push({func:op_neon_abs_s32});
}

/** function XXX **/
/* void  */ function gen_op_neon_trn_u8()
{
    gen_opc_ptr.push({func:op_neon_trn_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_trn_u16()
{
    gen_opc_ptr.push({func:op_neon_trn_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_unzip_u8()
{
    gen_opc_ptr.push({func:op_neon_unzip_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_zip_u8()
{
    gen_opc_ptr.push({func:op_neon_zip_u8});
}

/** function XXX **/
/* void  */ function gen_op_neon_zip_u16()
{
    gen_opc_ptr.push({func:op_neon_zip_u16});
}

/** function XXX **/
/* void  */ function gen_op_neon_dup_u8(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_neon_dup_u8, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_neon_insert_elt(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_neon_insert_elt, param:param1, param2:param2});
}

/** function XXX **/
/* void  */ function gen_op_neon_extract_elt(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_neon_extract_elt, param:param1, param2: param2});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_movl_T0_T1_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_movl_T0_T1_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_movl_wRn_T0_T1(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_movl_wRn_T0_T1, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_movq_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_movq_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_orq_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_orq_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_andq_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_andq_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_xorq_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_xorq_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_maddsq_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_maddsq_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_madduq_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_madduq_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_sadb_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_sadb_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_sadw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_sadw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addl_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_addl_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_mulsw_M0_wRn(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_iwmmxt_mulsw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_muluw_M0_wRn(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_iwmmxt_muluw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_macsw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_macsw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_macuw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_macuw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addsq_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_addsq_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_adduq_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_adduq_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_movq_wRn_M0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_movq_wRn_M0, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_movl_wCx_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_movl_wCx_T0, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_movl_T0_wCx(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_movl_T0_wCx, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_movl_T1_wCx(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_movl_T1_wCx, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_set_mup()
{
    gen_opc_ptr.push({func:op_iwmmxt_set_mup});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_set_cup()
{
    gen_opc_ptr.push({func:op_iwmmxt_set_cup});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_setpsr_nz()
{
    gen_opc_ptr.push({func:op_iwmmxt_setpsr_nz});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_negq_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_negq_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpacklb_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_unpacklb_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpacklw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_unpacklw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpackll_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_unpackll_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpacklub_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_unpacklub_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpackluw_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_unpackluw_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpacklul_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_unpacklul_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpacklsb_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_unpacklsb_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpacklsw_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_unpacklsw_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpacklsl_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_unpacklsl_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpackhb_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_unpackhb_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpackhw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_unpackhw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpackhl_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_unpackhl_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpackhub_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_unpackhub_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpackhuw_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_unpackhuw_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpackhul_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_unpackhul_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpackhsb_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_unpackhsb_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpackhsw_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_unpackhsw_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_unpackhsl_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_unpackhsl_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_cmpeqb_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_cmpeqb_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_cmpeqw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_cmpeqw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_cmpeql_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_cmpeql_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_cmpgtsb_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_cmpgtsb_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_cmpgtsw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_cmpgtsw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_cmpgtsl_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_cmpgtsl_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_cmpgtub_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_cmpgtub_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_cmpgtuw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_cmpgtuw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_cmpgtul_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_cmpgtul_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_minsb_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_minsb_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_minsw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_minsw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_minsl_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_minsl_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_minub_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_minub_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_minuw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_minuw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_minul_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_minul_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_maxsb_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_maxsb_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_maxsw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_maxsw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_maxsl_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_maxsl_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_maxub_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_maxub_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_maxuw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_maxuw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_maxul_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_maxul_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_subnb_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_subnb_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_subnw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_subnw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_subnl_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_subnl_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addnb_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_addnb_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addnw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_addnw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addnl_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_addnl_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_subub_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_subub_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_subuw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_subuw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_subul_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_subul_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addub_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_addub_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_adduw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_adduw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addul_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_addul_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_subsb_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_subsb_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_subsw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_subsw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_subsl_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_subsl_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addsb_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_addsb_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addsw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_addsw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addsl_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_addsl_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_avgb_M0_wRn(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_iwmmxt_avgb_M0_wRn, param:param1, param2:param2});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_avgw_M0_wRn(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_iwmmxt_avgw_M0_wRn, param:param1, param2:param2});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_msadb_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_msadb_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_align_M0_T0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_align_M0_T0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_insr_M0_T0_T1(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_insr_M0_T0_T1, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_extrsb_T0_M0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_extrsb_T0_M0, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_extrsw_T0_M0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_extrsw_T0_M0, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_extru_T0_M0_T1(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_extru_T0_M0_T1, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_bcstb_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_bcstb_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_bcstw_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_bcstw_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_bcstl_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_bcstl_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addcb_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_addcb_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addcw_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_addcw_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_addcl_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_addcl_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_msbb_T0_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_msbb_T0_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_msbw_T0_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_msbw_T0_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_msbl_T0_M0()
{
    gen_opc_ptr.push({func:op_iwmmxt_msbl_T0_M0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_srlw_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_srlw_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_srll_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_srll_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_srlq_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_srlq_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_sllw_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_sllw_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_slll_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_slll_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_sllq_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_sllq_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_sraw_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_sraw_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_sral_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_sral_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_sraq_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_sraq_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_rorw_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_rorw_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_rorl_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_rorl_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_rorq_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_rorq_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_shufh_M0_T0()
{
    gen_opc_ptr.push({func:op_iwmmxt_shufh_M0_T0});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_packuw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_packuw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_packul_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_packul_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_packuq_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_packuq_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_packsw_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_packsw_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_packsl_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_packsl_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_packsq_M0_wRn(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_iwmmxt_packsq_M0_wRn, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_muladdsl_M0_T0_T1()
{
    gen_opc_ptr.push({func:op_iwmmxt_muladdsl_M0_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_muladdsw_M0_T0_T1()
{
    gen_opc_ptr.push({func:op_iwmmxt_muladdsw_M0_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_muladdswl_M0_T0_T1()
{
    gen_opc_ptr.push({func:op_iwmmxt_muladdswl_M0_T0_T1});
}

/** function XXX **/
/* void  */ function gen_op_neon_tbl(param1, param2)
{
    //gen_opparam_ptr.push(param1);
    //gen_opparam_ptr.push(param2);
    gen_opc_ptr.push({func:op_neon_tbl, param:param1, param2:param2});
}

/** function XXX **/
/* void  */ function gen_op_neon_rsqrte_f32()
{
    gen_opc_ptr.push({func:op_neon_rsqrte_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_recpe_f32()
{
    gen_opc_ptr.push({func:op_neon_recpe_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_rsqrte_u32()
{
    gen_opc_ptr.push({func:op_neon_rsqrte_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_recpe_u32()
{
    gen_opc_ptr.push({func:op_neon_recpe_u32});
}

/** function XXX **/
/* void  */ function gen_op_neon_acgt_f32()
{
    gen_opc_ptr.push({func:op_neon_acgt_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_acge_f32()
{
    gen_opc_ptr.push({func:op_neon_acge_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_cgt_f32()
{
    gen_opc_ptr.push({func:op_neon_cgt_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_cge_f32()
{
    gen_opc_ptr.push({func:op_neon_cge_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_ceq_f32()
{
    gen_opc_ptr.push({func:op_neon_ceq_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_min_f32()
{
    gen_opc_ptr.push({func:op_neon_min_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_max_f32()
{
    gen_opc_ptr.push({func:op_neon_max_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_rsqrts_f32()
{
    gen_opc_ptr.push({func:op_neon_rsqrts_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_recps_f32()
{
    gen_opc_ptr.push({func:op_neon_recps_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_mul_p8()
{
    gen_opc_ptr.push({func:op_neon_mul_p8});
}

/** function XXX **/
/* void  */ function gen_op_neon_mul_f32()
{
    gen_opc_ptr.push({func:op_neon_mul_f32});
}

/** function XXX **/
/* void  */ function gen_op_vfp_muls()
{
    gen_opc_ptr.push({func:op_vfp_muls});
}

/** function XXX **/
/* void  */ function gen_op_neon_rsb_f32()
{
    gen_opc_ptr.push({func:op_neon_rsb_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_sub_f32()
{
    gen_opc_ptr.push({func:op_neon_sub_f32});
}

/** function XXX **/
/* void  */ function gen_op_neon_abd_f32()
{
    gen_opc_ptr.push({func:op_neon_abd_f32});
}

/** function XXX **/
/* void  */ function gen_op_vfp_subs()
{
    gen_opc_ptr.push({func:op_vfp_subs});
}

/** function XXX **/
/* void  */ function gen_op_neon_add_f32()
{
    gen_opc_ptr.push({func:op_neon_add_f32});
}

/** function XXX **/
/* void  */ function gen_op_vfp_adds()
{
    gen_opc_ptr.push({func:op_vfp_adds});
}

/** function XXX **/
/* void  */ function gen_op_v7m_msr_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_v7m_msr_T0, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_v7m_mrs_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_v7m_mrs_T0, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_movl_r13_T1_banked(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_r13_T1_banked, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T1_r13_banked(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_T1_r13_banked, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_cp15(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_T0_cp15, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_movl_cp15_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_cp15_T0, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_cp(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_T0_cp, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_movl_cp_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_cp_T0, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_movl_fpscr_T0()
{
    gen_opc_ptr.push({func:op_vfp_movl_fpscr_T0});
}

/** function XXX **/
/* void  */ function gen_op_vfp_movl_T0_fpscr()
{
    gen_opc_ptr.push({func:op_vfp_movl_T0_fpscr});
}

/** function XXX **/
/* void  */ function gen_op_vfp_touls(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_touls, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_touhs(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_touhs, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_touizs()
{
    gen_opc_ptr.push({func:op_vfp_touizs});
}

/** function XXX **/
/* void  */ function gen_op_vfp_ultos(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_ultos, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_uhtos(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_uhtos, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_uitos()
{
    gen_opc_ptr.push({func:op_vfp_uitos, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_tosls(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_tosls, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_toshs(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_toshs, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_tosizs()
{
    gen_opc_ptr.push({func:op_vfp_tosizs});
}

/** function XXX **/
/* void  */ function gen_op_vfp_sltos(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_sltos, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_shtos(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_shtos, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_sitos()
{
    gen_opc_ptr.push({func:op_vfp_sitos});
}

/** function XXX **/
/* void  */ function gen_op_vfp_tould(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_tould, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_touhd(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_touhd, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_touizd()
{
    gen_opc_ptr.push({func:op_vfp_touizd});
}

/** function XXX **/
/* void  */ function gen_op_vfp_ultod(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_ultod, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_uhtod(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_uhtod, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_uitod()
{
    gen_opc_ptr.push({func:op_vfp_uitod});
}

/** function XXX **/
/* void  */ function gen_op_vfp_tosld(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_tosld, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_toshd(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_toshd, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_tosizd()
{
    gen_opc_ptr.push({func:op_vfp_tosizd});
}

/** function XXX **/
/* void  */ function gen_op_vfp_sltod(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_sltod, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_shtod(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_vfp_shtod, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_vfp_sitod()
{
    gen_opc_ptr.push({func:op_vfp_sitod});
}

/** function XXX **/
/* void  */ function gen_op_vfp_fcvtsd()
{
    gen_opc_ptr.push({func:op_vfp_fcvtsd});
}

/** function XXX **/
/* void  */ function gen_op_vfp_fcvtds()
{
    gen_opc_ptr.push({func:op_vfp_fcvtds});
}

/** function XXX **/
/* void  */ function gen_op_vfp_tosid()
{
    gen_opc_ptr.push({func:op_vfp_tosid});
}

/** function XXX **/
/* void  */ function gen_op_vfp_tosis()
{
    gen_opc_ptr.push({func:op_vfp_tosis});
}

/** function XXX **/
/* void  */ function gen_op_vfp_touid()
{
    gen_opc_ptr.push({func:op_vfp_touid});
}

/** function XXX **/
/* void  */ function gen_op_vfp_touis()
{
    gen_opc_ptr.push({func:op_vfp_touis});
}

/** function XXX **/
/* void  */ function gen_op_vfp_cmped()
{
    gen_opc_ptr.push({func:op_vfp_cmped});
}

/** function XXX **/
/* void  */ function gen_op_vfp_cmpes()
{
    gen_opc_ptr.push({func:op_vfp_cmpes});
}

/** function XXX **/
/* void  */ function gen_op_vfp_cmpd()
{
    gen_opc_ptr.push({func:op_vfp_cmpd});
}

/** function XXX **/
/* void  */ function gen_op_vfp_cmps()
{
    gen_opc_ptr.push({func:op_vfp_cmps});
}

/** function XXX **/
/* void  */ function gen_op_vfp_sqrtd()
{
    gen_opc_ptr.push({func:op_vfp_sqrtd});
}

/** function XXX **/
/* void  */ function gen_op_vfp_sqrts()
{
    gen_opc_ptr.push({func:op_vfp_sqrts});
}

/** function XXX **/
/* void  */ function gen_op_vfp_absd()
{
    gen_opc_ptr.push({func:op_vfp_absd});
}

/** function XXX **/
/* void  */ function gen_op_vfp_abss()
{
    gen_opc_ptr.push({func:op_vfp_abss});
}

/** function XXX **/
/* void  */ function gen_op_vfp_divd()
{
    gen_opc_ptr.push({func:op_vfp_divd});
}

/** function XXX **/
/* void  */ function gen_op_vfp_divs()
{
    gen_opc_ptr.push({func:op_vfp_divs});
}

/** function XXX **/
/* void  */ function gen_op_vfp_muld()
{
    gen_opc_ptr.push({func:op_vfp_muld});
}

/** function XXX **/
/* void  */ function gen_op_vfp_subd()
{
    gen_opc_ptr.push({func:op_vfp_subd});
}

/** function XXX **/
/* void  */ function gen_op_vfp_addd()
{
    gen_opc_ptr.push({func:op_vfp_addd});
}

/** function XXX **/
/* void  */ function gen_op_exception_exit()
{
    gen_opc_ptr.push({func:op_exception_exit});
}

/** function XXX **/
/* void  */ function gen_op_bkpt()
{
    gen_opc_ptr.push({func:op_bkpt});
}

/** function XXX **/
/* void  */ function gen_op_wfi()
{
    gen_opc_ptr.push({func:op_wfi});
}

/** function XXX **/
/* void  */ function gen_op_debug()
{
    gen_opc_ptr.push({func:op_debug});
}

/** function XXX **/
/* void  */ function gen_op_undef_insn()
{
    gen_opc_ptr.push({func:op_undef_insn});
}

/** function XXX **/
/* void  */ function gen_op_swi()
{
    gen_opc_ptr.push({func:op_swi});
}

/** function XXX **/
/* void  */ function gen_op_clrex()
{
    gen_opc_ptr.push({func:op_clrex});
}

/** function XXX **/
/* void  */ function gen_op_swpl_raw()
{
    gen_opc_ptr.push({func:op_swpl_raw});
}

/** function XXX **/
/* void  */ function gen_op_swpb_raw()
{
    gen_opc_ptr.push({func:op_swpb_raw});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_stq_kernel()
{
    gen_opc_ptr.push({func:op_iwmmxt_stq_kernel});
}

/** function XXX **/
/* void  */ function gen_op_vfp_std_kernel()
{
    gen_opc_ptr.push({func:op_vfp_std_kernel});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_stq_user()
{
    gen_opc_ptr.push({func:op_iwmmxt_stq_user});
}

/** function XXX **/
/* void  */ function gen_op_vfp_std_user()
{
    gen_opc_ptr.push({func:op_vfp_std_user});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_ldq_kernel()
{
    gen_opc_ptr.push({func:op_iwmmxt_ldq_kernel});
}

/** function XXX **/
/* void  */ function gen_op_vfp_ldd_kernel()
{
    gen_opc_ptr.push({func:op_vfp_ldd_kernel});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_ldq_user()
{
    gen_opc_ptr.push({func:op_iwmmxt_ldq_user});
}

/** function XXX **/
/* void  */ function gen_op_vfp_ldd_user()
{
    gen_opc_ptr.push({func:op_vfp_ldd_user});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_stl_kernel()
{
    gen_opc_ptr.push({func:op_iwmmxt_stl_kernel});
}

/** function XXX **/
/* void  */ function gen_op_vfp_sts_kernel()
{
    gen_opc_ptr.push({func:op_vfp_sts_kernel});
}

/** function XXX **/
/* void  */ function gen_op_stl_kernel()
{
    gen_opc_ptr.push({func:op_stl_kernel});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_stl_user()
{
    gen_opc_ptr.push({func:op_iwmmxt_stl_user});
}

/** function XXX **/
/* void  */ function gen_op_vfp_sts_user()
{
    gen_opc_ptr.push({func:op_vfp_sts_user});
}

/** function XXX **/
/* void  */ function gen_op_stl_user()
{
    gen_opc_ptr.push({func:op_stl_user});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_ldl_kernel()
{
    gen_opc_ptr.push({func:op_iwmmxt_ldl_kernel});
}

/** function XXX **/
/* void  */ function gen_op_vfp_lds_kernel()
{
    gen_opc_ptr.push({func:op_vfp_lds_kernel});
}

/** function XXX **/
/* void  */ function gen_op_swpl_kernel()
{
    gen_opc_ptr.push({func:op_swpl_kernel});
}

/** function XXX **/
/* void  */ function gen_op_ldl_kernel()
{
    gen_opc_ptr.push({func:op_ldl_kernel});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_ldl_user()
{
    gen_opc_ptr.push({func:op_iwmmxt_ldl_user});
}

/** function XXX **/
/* void  */ function gen_op_vfp_lds_user()
{
    gen_opc_ptr.push({func:op_vfp_lds_user});
}

/** function XXX **/
/* void  */ function gen_op_swpl_user()
{
    gen_opc_ptr.push({func:op_swpl_user});
}

/** function XXX **/
/* void  */ function gen_op_ldl_user()
{
    gen_opc_ptr.push({func:op_ldl_user});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_stw_kernel()
{
    gen_opc_ptr.push({func:op_iwmmxt_stw_kernel});
}

/** function XXX **/
/* void  */ function gen_op_stw_kernel()
{
    gen_opc_ptr.push({func:op_stw_kernel});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_stw_user()
{
    gen_opc_ptr.push({func:op_iwmmxt_stw_user});
}

/** function XXX **/
/* void  */ function gen_op_stw_user()
{
    gen_opc_ptr.push({func:op_stw_user});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_ldw_kernel()
{
    gen_opc_ptr.push({func:op_iwmmxt_ldw_kernel});
}

/** function XXX **/
/* void  */ function gen_op_lduw_kernel()
{
    gen_opc_ptr.push({func:op_lduw_kernel});
}

/** function XXX **/
/* void  */ function gen_op_ldsw_kernel()
{
    gen_opc_ptr.push({func:op_ldsw_kernel});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_ldw_user()
{
    gen_opc_ptr.push({func:op_iwmmxt_ldw_user});
}

/** function XXX **/
/* void  */ function gen_op_lduw_user()
{
    gen_opc_ptr.push({func:op_lduw_user});
}

/** function XXX **/
/* void  */ function gen_op_ldsw_user()
{
    gen_opc_ptr.push({func:op_ldsw_user});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_stb_kernel()
{
    gen_opc_ptr.push({func:op_iwmmxt_stb_kernel});
}

/** function XXX **/
/* void  */ function gen_op_stb_kernel()
{
    gen_opc_ptr.push({func:op_stb_kernel});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_stb_user()
{
    gen_opc_ptr.push({func:op_iwmmxt_stb_user});
}

/** function XXX **/
/* void  */ function gen_op_stb_user()
{
    gen_opc_ptr.push({func:op_stb_user});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_ldb_kernel()
{
    gen_opc_ptr.push({func:op_iwmmxt_ldb_kernel});
}

/** function XXX **/
/* void  */ function gen_op_swpb_kernel()
{
    gen_opc_ptr.push({func:op_swpb_kernel});
}

/** function XXX **/
/* void  */ function gen_op_ldub_kernel()
{
    gen_opc_ptr.push({func:op_ldub_kernel});
}

/** function XXX **/
/* void  */ function gen_op_ldsb_kernel()
{
    gen_opc_ptr.push({func:op_ldsb_kernel});
}

/** function XXX **/
/* void  */ function gen_op_iwmmxt_ldb_user()
{
    gen_opc_ptr.push({func:op_iwmmxt_ldb_user});
}

/** function XXX **/
/* void  */ function gen_op_swpb_user()
{
    gen_opc_ptr.push({func:op_swpb_user});
}

/** function XXX **/
/* void  */ function gen_op_ldub_user()
{
    gen_opc_ptr.push({func:op_ldub_user});
}

/** function XXX **/
/* void  */ function gen_op_ldsb_user()
{
    gen_opc_ptr.push({func:op_ldsb_user});
}

/** function XXX **/
/* void  */ function gen_op_stqex_kernel()
{
    gen_opc_ptr.push({func:op_stqex_kernel});
}

/** function XXX **/
/* void  */ function gen_op_stlex_kernel()
{
    gen_opc_ptr.push({func:op_stlex_kernel});
}

/** function XXX **/
/* void  */ function gen_op_stwex_kernel()
{
    gen_opc_ptr.push({func:op_stwex_kernel});
}

/** function XXX **/
/* void  */ function gen_op_stbex_kernel()
{
    gen_opc_ptr.push({func:op_stbex_kernel});
}

/** function XXX **/
/* void  */ function gen_op_stqex_user()
{
    gen_opc_ptr.push({func:op_stqex_user});
}

/** function XXX **/
/* void  */ function gen_op_stlex_user()
{
    gen_opc_ptr.push({func:op_stlex_user});
}

/** function XXX **/
/* void  */ function gen_op_stwex_user()
{
    gen_opc_ptr.push({func:op_stwex_user});
}

/** function XXX **/
/* void  */ function gen_op_stbex_user()
{
    gen_opc_ptr.push({func:op_stbex_user});
}

/** function XXX **/
/* void  */ function gen_op_stqex_raw()
{
    gen_opc_ptr.push({func:op_stqex_raw});
}

/** function XXX **/
/* void  */ function gen_op_stlex_raw()
{
    gen_opc_ptr.push({func:op_stlex_raw});
}

/** function XXX **/
/* void  */ function gen_op_stwex_raw()
{
    gen_opc_ptr.push({func:op_stwex_raw});
}

/** function XXX **/
/* void  */ function gen_op_stbex_raw()
{
    gen_opc_ptr.push({func:op_stbex_raw});
}

/** function XXX **/
/* void  */ function gen_op_ldqex_kernel()
{
    gen_opc_ptr.push({func:op_ldqex_kernel});
}

/** function XXX **/
/* void  */ function gen_op_ldlex_kernel()
{
    gen_opc_ptr.push({func:op_ldlex_kernel});
}

/** function XXX **/
/* void  */ function gen_op_ldwex_kernel()
{
    gen_opc_ptr.push({func:op_ldwex_kernel});
}

/** function XXX **/
/* void  */ function gen_op_ldbex_kernel()
{
    gen_opc_ptr.push({func:op_ldbex_kernel});
}

/** function XXX **/
/* void  */ function gen_op_ldqex_user()
{
    gen_opc_ptr.push({func:op_ldqex_user});
}

/** function XXX **/
/* void  */ function gen_op_ldlex_user()
{
    gen_opc_ptr.push({func:op_ldlex_user});
}

/** function XXX **/
/* void  */ function gen_op_ldwex_user()
{
    gen_opc_ptr.push({func:op_ldwex_user});
}

/** function XXX **/
/* void  */ function gen_op_ldbex_user()
{
    gen_opc_ptr.push({func:op_ldbex_user});
}

/** function XXX **/
/* void  */ function gen_op_ldqex_raw()
{
    gen_opc_ptr.push({func:op_ldqex_raw});
}

/** function XXX **/
/* void  */ function gen_op_ldlex_raw()
{
    gen_opc_ptr.push({func:op_ldlex_raw});
}

/** function XXX **/
/* void  */ function gen_op_ldwex_raw()
{
    gen_opc_ptr.push({func:op_ldwex_raw});
}

/** function XXX **/
/* void  */ function gen_op_ldbex_raw()
{
    gen_opc_ptr.push({func:op_ldbex_raw});
}

/** function XXX **/
/* void  */ function gen_op_movl_cpsr_T0(param1)
{
    //gen_opparam_ptr.push(param1);
    gen_opc_ptr.push({func:op_movl_cpsr_T0, param:param1});
}

/** function XXX **/
/* void  */ function gen_op_movl_T0_cpsr()
{
    gen_opc_ptr.push({func:op_movl_T0_cpsr});
}

/** function XXX **/
/* void  */ function gen_bx(/* DisasContext * */ s)
{
  s.is_jmp = DISAS_UPDATE;
  gen_op_bx_T0();
}
/** function XXX **/
/* void  */ function gen_movl_TN_reg(/* DisasContext * */s, /* int */ reg, /* int */ t)
{
    var val;

    if (reg == 15) {
        /* normaly, since we updated PC, we need only to add one insn */
        if (s.thumb)
            val = /* (long)*/ s.pc + 2;
        else
            val =  s.pc + 4;
        gen_op_movl_TN_im[t](val);
    } else {
        gen_op_movl_TN_reg[t][reg]();
    }
}

/** function XXX **/
/* void  */ function gen_movl_T0_reg(/* DisasContext * */ s, /* int */ reg)
{
    gen_movl_TN_reg(s, reg, 0);
}

/** function XXX **/
/* void  */ function gen_movl_T1_reg(/* DisasContext * */ s, /* int */ reg)
{
    gen_movl_TN_reg(s, reg, 1);
}

/** function XXX **/
/* void  */ function gen_movl_T2_reg(/* DisasContext * */ s, /* int */ reg)
{
    gen_movl_TN_reg(s, reg, 2);
}

var gen_op_movl_reg_TN = [
    [
        gen_op_movl_r0_T0,
        gen_op_movl_r1_T0,
        gen_op_movl_r2_T0,
        gen_op_movl_r3_T0,
        gen_op_movl_r4_T0,
        gen_op_movl_r5_T0,
        gen_op_movl_r6_T0,
        gen_op_movl_r7_T0,
        gen_op_movl_r8_T0,
        gen_op_movl_r9_T0,
        gen_op_movl_r10_T0,
        gen_op_movl_r11_T0,
        gen_op_movl_r12_T0,
        gen_op_movl_r13_T0,
        gen_op_movl_r14_T0,
        gen_op_movl_r15_T0,
    ],
    [
        gen_op_movl_r0_T1,
        gen_op_movl_r1_T1,
        gen_op_movl_r2_T1,
        gen_op_movl_r3_T1,
        gen_op_movl_r4_T1,
        gen_op_movl_r5_T1,
        gen_op_movl_r6_T1,
        gen_op_movl_r7_T1,
        gen_op_movl_r8_T1,
        gen_op_movl_r9_T1,
        gen_op_movl_r10_T1,
        gen_op_movl_r11_T1,
        gen_op_movl_r12_T1,
        gen_op_movl_r13_T1,
        gen_op_movl_r14_T1,
        gen_op_movl_r15_T1,
    ]
];

var gen_test_cc = [
    gen_op_test_eq,
    gen_op_test_ne,
    gen_op_test_cs,
    gen_op_test_cc,
    gen_op_test_mi,
    gen_op_test_pl,
    gen_op_test_vs,
    gen_op_test_vc,
    gen_op_test_hi,
    gen_op_test_ls,
    gen_op_test_ge,
    gen_op_test_lt,
    gen_op_test_gt,
    gen_op_test_le,
];


/** function XXX **/
/* void  */ function gen_movl_reg_TN(/* DisasContext * */ s, /* int */ reg, /* int */ t)
{
    gen_op_movl_reg_TN[t][reg]();
    if (reg == 15) {
        s.is_jmp = DISAS_NEXT;
    }
}

/** function XXX **/
/* void  */ function gen_movl_reg_T0(/* DisasContext * */ s, /* int */ reg)
{
    gen_movl_reg_TN(s, reg, 0);
}

/** function XXX **/
/* void  */ function gen_movl_reg_T1(/* DisasContext * */ s, /* int */ reg)
{
    gen_movl_reg_TN(s, reg, 1);
}

/* Force a TB lookup after an instruction that changes the CPU state.  */
/** function XXX **/
/* void  */ function gen_lookup_tb(/*DisasContext * */ s)
{
    gen_op_movl_T0_im(s.pc);
    gen_movl_reg_T0(s, 15);
    s.is_jmp = DISAS_UPDATE;
}

/** function XXX **/
/* void  */ function gen_add_data_offset(/* DisasContext * */ s, /* unsigned int */ insn)
{
    var val, rm, shift, shiftop;

    if (!(insn & (1 << 25))) {
        /* immediate */
        val = insn & 0xfff;
        if (!(insn & (1 << 23)))
            val = -val;
        if (val != 0)
            gen_op_addl_T1_im(val);
    } else {
        /* shift/register */
        rm = (insn) & 0xf;
        shift = (insn >> 7) & 0x1f;
        gen_movl_T2_reg(s, rm);
        shiftop = (insn >> 5) & 3;
        if (shift != 0) {
            gen_shift_T2_im[shiftop](shift);
        } else if (shiftop != 0) {
            gen_shift_T2_0[shiftop]();
        }
        if (!(insn & (1 << 23)))
            gen_op_subl_T1_T2();
        else
            gen_op_addl_T1_T2();
    }
}

/** function XXX **/
/* void  */ function gen_add_datah_offset(/* DisasContext * */ s, /* unsigned int */ insn,
                                        /* int */ extra)
{
    var val, rm;

    if (insn & (1 << 22)) {
        /* immediate */
        val = (insn & 0xf) | ((insn >> 4) & 0xf0);
        if (!(insn & (1 << 23)))
            val = -val;
        val += extra;
        if (val != 0)
            gen_op_addl_T1_im(val);
    } else {
        /* register */
        if (extra)
            gen_op_addl_T1_im(extra);
        rm = (insn) & 0xf;
        gen_movl_T2_reg(s, rm);
        if (!(insn & (1 << 23)))
            gen_op_subl_T1_T2();
        else
            gen_op_addl_T1_T2();
    }
}
/** function XXX **/
/* void  */ function gen_vfp_add(/* int */ dp) { if (dp) gen_op_vfp_addd(); else gen_op_vfp_adds(); }
/** function XXX **/
/* void  */ function gen_vfp_sub(/* int */ dp) { if (dp) gen_op_vfp_subd(); else gen_op_vfp_subs(); }
/** function XXX **/
/* void  */ function gen_vfp_mul(/* int */ dp) { if (dp) gen_op_vfp_muld(); else gen_op_vfp_muls(); }
/** function XXX **/
/* void  */ function gen_vfp_div(/* int */ dp) { if (dp) gen_op_vfp_divd(); else gen_op_vfp_divs(); }
/** function XXX **/
/* void  */ function gen_vfp_neg(/* int */ dp) { if (dp) gen_op_vfp_negd(); else gen_op_vfp_negs(); }
/** function XXX **/
/* void  */ function gen_vfp_abs(/* int */ dp) { if (dp) gen_op_vfp_absd(); else gen_op_vfp_abss(); }
/** function XXX **/
/* void  */ function gen_vfp_sqrt(/* int */ dp) { if (dp) gen_op_vfp_sqrtd(); else gen_op_vfp_sqrts(); }
/** function XXX **/
/* void  */ function gen_vfp_cmp(/* int */ dp) { if (dp) gen_op_vfp_cmpd(); else gen_op_vfp_cmps(); }
/** function XXX **/
/* void  */ function gen_vfp_cmpe(/* int */ dp) { if (dp) gen_op_vfp_cmped(); else gen_op_vfp_cmpes(); }
/** function XXX **/
/* void  */ function gen_vfp_F1_ld0(/* int */ dp) { if (dp) gen_op_vfp_F1_ld0d(); else gen_op_vfp_F1_ld0s(); }
/** function XXX **/
/* void  */ function gen_vfp_uito(/* int */ dp) { if (dp) gen_op_vfp_uitod(); else gen_op_vfp_uitos(); }
/** function XXX **/
/* void  */ function gen_vfp_sito(/* int */ dp) { if (dp) gen_op_vfp_sitod(); else gen_op_vfp_sitos(); }
/** function XXX **/
/* void  */ function gen_vfp_toui(/* int */ dp) { if (dp) gen_op_vfp_touid(); else gen_op_vfp_touis(); }
/** function XXX **/
/* void  */ function gen_vfp_touiz(/* int */ dp) { if (dp) gen_op_vfp_touizd(); else gen_op_vfp_touizs(); }
/** function XXX **/
/* void  */ function gen_vfp_tosi(/* int */ dp) { if (dp) gen_op_vfp_tosid(); else gen_op_vfp_tosis(); }
/** function XXX **/
/* void  */ function gen_vfp_tosiz(/* int */ dp) { if (dp) gen_op_vfp_tosizd(); else gen_op_vfp_tosizs(); }
/** function XXX **/
/* void  */ function gen_vfp_tosh(/* int */ dp, /* int */ arg) { if (dp) gen_op_vfp_toshd(arg); else gen_op_vfp_toshs(arg); }
/** function XXX **/
/* void  */ function gen_vfp_tosl(/* int */ dp, /* int */ arg) { if (dp) gen_op_vfp_tosld(arg); else gen_op_vfp_tosls(arg); }
/** function XXX **/
/* void  */ function gen_vfp_touh(/* int */ dp, /* int */ arg) { if (dp) gen_op_vfp_touhd(arg); else gen_op_vfp_touhs(arg); }
/** function XXX **/
/* void  */ function gen_vfp_toul(/* int */ dp, /* int */ arg) { if (dp) gen_op_vfp_tould(arg); else gen_op_vfp_touls(arg); }
/** function XXX **/
/* void  */ function gen_vfp_shto(/* int */ dp, /* int */ arg) { if (dp) gen_op_vfp_shtod(arg); else gen_op_vfp_shtos(arg); }
/** function XXX **/
/* void  */ function gen_vfp_slto(/* int */ dp, /* int */ arg) { if (dp) gen_op_vfp_sltod(arg); else gen_op_vfp_sltos(arg); }
/** function XXX **/
/* void  */ function gen_vfp_uhto(/* int */ dp, /* int */ arg) { if (dp) gen_op_vfp_uhtod(arg); else gen_op_vfp_uhtos(arg); }
/** function XXX **/
/* void  */ function gen_vfp_ulto(/* int */ dp, /* int */ arg) { if (dp) gen_op_vfp_ultod(arg); else gen_op_vfp_ultos(arg); }



/** function XXX **/
/* void  */ function gen_vfp_fconst(/* int */ dp, /* uint32_t */ val)
{
    if (dp)
        gen_op_vfp_fconstd(val);
    else
        gen_op_vfp_fconsts(val);
}

/** function XXX **/
/* void  */ function gen_vfp_ld(/* DisasContext * */ s, /* int */ dp)
{
    if (dp)
        do { s.is_mem = 1; if ((s.user)) gen_op_vfp_ldd_user(); else gen_op_vfp_ldd_kernel(); } while (0);
    else
        do { s.is_mem = 1; if ((s.user)) gen_op_vfp_lds_user(); else gen_op_vfp_lds_kernel(); } while (0);
}

/** function XXX **/
/* void  */ function gen_vfp_st(/* DisasContext * */ s, /* int */ dp)
{
    if (dp)
        do { s.is_mem = 1; if ((s.user)) gen_op_vfp_std_user(); else gen_op_vfp_std_kernel(); } while (0);
    else
        do { s.is_mem = 1; if ((s.user)) gen_op_vfp_sts_user(); else gen_op_vfp_sts_kernel(); } while (0);
}

/** function XXX **/
/* void  */ function gen_mov_F0_vreg(/* int */ dp, /* int */ reg)
{
    if (dp)
        gen_op_vfp_getreg_F0d(vfp_reg_offset(dp, reg));
    else
        gen_op_vfp_getreg_F0s(vfp_reg_offset(dp, reg));
}

/** function XXX **/
/* void  */ function gen_mov_F1_vreg(/* int */ dp, /* int */ reg)
{
    if (dp)
        gen_op_vfp_getreg_F1d(vfp_reg_offset(dp, reg));
    else
        gen_op_vfp_getreg_F1s(vfp_reg_offset(dp, reg));
}

/** function XXX **/
/* void  */ function gen_mov_vreg_F0(/* int */ dp, /* int */ reg)
{
    if (dp)
        gen_op_vfp_setreg_F0d(vfp_reg_offset(dp, reg));
    else
        gen_op_vfp_setreg_F0s(vfp_reg_offset(dp, reg));
}



/** function XXX **/
/* int  */ function gen_iwmmxt_address(/* DisasContext * */ s, /* uint32_t */ insn)
{
    var rd;
    var/* uint32_t */ offset;

    rd = (insn >> 16) & 0xf;
    gen_movl_T1_reg(s, rd);

    offset = (insn & 0xff) << ((insn >> 7) & 2);
    if (insn & (1 << 24)) {
        /* Pre indexed */
        if (insn & (1 << 23))
            gen_op_addl_T1_im(offset);
        else
            gen_op_addl_T1_im(-offset);

        if (insn & (1 << 21))
            gen_movl_reg_T1(s, rd);
    } else if (insn & (1 << 21)) {
        /* Post indexed */
        if (insn & (1 << 23))
            gen_op_movl_T0_im(offset);
        else
            gen_op_movl_T0_im(- offset);
        gen_op_addl_T0_T1();
        gen_movl_reg_T0(s, rd);
    } else if (!(insn & (1 << 23)))
        return 1;
    return 0;
}

/** function XXX **/
/* int  */ function gen_iwmmxt_shift(/* uint32_t */ insn, /* uint32_t */ mask)
{
    var rd = (insn >> 0) & 0xf;

    if (insn & (1 << 8))
        if (rd < 8 || rd > 11)
            return 1;
        else
            gen_op_iwmmxt_movl_T0_wCx(rd);
    else
        gen_op_iwmmxt_movl_T0_T1_wRn(rd);

    gen_op_movl_T1_im(mask);
    gen_op_andl_T0_T1();
    return 0;
}

/* Disassemble an iwMMXt instruction.  Returns nonzero if an error occured
   (ie. an undefined instruction).  */
function disas_iwmmxt_insn(/* CPUARMState * */ env, /* DisasContext * */ s, /* uint32_t */ insn)
{
    var rd, wrd;
    var rdhi, rdlo, rd0, rd1, i;

    if ((insn & 0x0e000e00) == 0x0c000000) {
        if ((insn & 0x0fe00ff0) == 0x0c400000) {
            wrd = insn & 0xf;
            rdlo = (insn >> 12) & 0xf;
            rdhi = (insn >> 16) & 0xf;
            if (insn & (1 << 20)) { /* TMRRC */
                gen_op_iwmmxt_movl_T0_T1_wRn(wrd);
                gen_movl_reg_T0(s, rdlo);
                gen_movl_reg_T1(s, rdhi);
            } else { /* TMCRR */
                gen_movl_T0_reg(s, rdlo);
                gen_movl_T1_reg(s, rdhi);
                gen_op_iwmmxt_movl_wRn_T0_T1(wrd);
                gen_op_iwmmxt_set_mup();
            }
            return 0;
        }

        wrd = (insn >> 12) & 0xf;
        if (gen_iwmmxt_address(s, insn))
            return 1;
        if (insn & (1 << 20)) {
            if ((insn >> 28) == 0xf) { /* WLDRW wCx */
                do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                gen_op_iwmmxt_movl_wCx_T0(wrd);
            } else {
                if (insn & (1 << 8))
                    if (insn & (1 << 22)) /* WLDRD */
                        do { s.is_mem = 1; if ((s.user)) gen_op_iwmmxt_ldq_user(); else gen_op_iwmmxt_ldq_kernel(); } while (0);
                    else /* WLDRW wRd */
                        do { s.is_mem = 1; if ((s.user)) gen_op_iwmmxt_ldl_user(); else gen_op_iwmmxt_ldl_kernel(); } while (0);
                else
                    if (insn & (1 << 22)) /* WLDRH */
                        do { s.is_mem = 1; if ((s.user)) gen_op_iwmmxt_ldw_user(); else gen_op_iwmmxt_ldw_kernel(); } while (0);
                    else /* WLDRB */
                        do { s.is_mem = 1; if ((s.user)) gen_op_iwmmxt_ldb_user(); else gen_op_iwmmxt_ldb_kernel(); } while (0);
                gen_op_iwmmxt_movq_wRn_M0(wrd);
            }
        } else {
            if ((insn >> 28) == 0xf) { /* WSTRW wCx */
                gen_op_iwmmxt_movl_T0_wCx(wrd);
                do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
            } else {
                gen_op_iwmmxt_movq_M0_wRn(wrd);
                if (insn & (1 << 8))
                    if (insn & (1 << 22)) /* WSTRD */
                        do { s.is_mem = 1; if ((s.user)) gen_op_iwmmxt_stq_user(); else gen_op_iwmmxt_stq_kernel(); } while (0);
                    else /* WSTRW wRd */
                        do { s.is_mem = 1; if ((s.user)) gen_op_iwmmxt_stl_user(); else gen_op_iwmmxt_stl_kernel(); } while (0);
                else
                    if (insn & (1 << 22)) /* WSTRH */
                        do { s.is_mem = 1; if ((s.user)) gen_op_iwmmxt_ldw_user(); else gen_op_iwmmxt_ldw_kernel(); } while (0);
                    else /* WSTRB */
                        do { s.is_mem = 1; if ((s.user)) gen_op_iwmmxt_stb_user(); else gen_op_iwmmxt_stb_kernel(); } while (0);
            }
        }
        return 0;
    }

    if ((insn & 0x0f000000) != 0x0e000000)
        return 1;

    switch (((insn >> 12) & 0xf00) | ((insn >> 4) & 0xff)) {
    case 0x000: /* WOR */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 0) & 0xf;
        rd1 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        gen_op_iwmmxt_orq_M0_wRn(rd1);
        gen_op_iwmmxt_setpsr_nz();
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x011: /* TMCR */
        if (insn & 0xf)
            return 1;
        rd = (insn >> 12) & 0xf;
        wrd = (insn >> 16) & 0xf;
        switch (wrd) {
        case 0:
        case 3:
            break;
        case 1:
            gen_op_iwmmxt_set_cup();
            /* Fall through.  */
        case 2:
            gen_op_iwmmxt_movl_T0_wCx(wrd);
            gen_movl_T1_reg(s, rd);
            gen_op_bicl_T0_T1();
            gen_op_iwmmxt_movl_wCx_T0(wrd);
            break;
        case 8:
        case 9:
        case 10:
        case 11:
            gen_op_iwmmxt_set_cup();
            gen_movl_reg_T0(s, rd);
            gen_op_iwmmxt_movl_wCx_T0(wrd);
            break;
        default:
            return 1;
        }
        break;
    case 0x100: /* WXOR */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 0) & 0xf;
        rd1 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        gen_op_iwmmxt_xorq_M0_wRn(rd1);
        gen_op_iwmmxt_setpsr_nz();
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x111: /* TMRC */
        if (insn & 0xf)
            return 1;
        rd = (insn >> 12) & 0xf;
        wrd = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movl_T0_wCx(wrd);
        gen_movl_reg_T0(s, rd);
        break;
    case 0x300: /* WANDN */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 0) & 0xf;
        rd1 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        gen_op_iwmmxt_negq_M0();
        gen_op_iwmmxt_andq_M0_wRn(rd1);
        gen_op_iwmmxt_setpsr_nz();
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x200: /* WAND */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 0) & 0xf;
        rd1 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        gen_op_iwmmxt_andq_M0_wRn(rd1);
        gen_op_iwmmxt_setpsr_nz();
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x810: case 0xa10: /* WMADD */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 0) & 0xf;
        rd1 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        if (insn & (1 << 21))
            gen_op_iwmmxt_maddsq_M0_wRn(rd1);
        else
            gen_op_iwmmxt_madduq_M0_wRn(rd1);
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        break;
    case 0x10e: case 0x50e: case 0x90e: case 0xd0e: /* WUNPCKIL */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 22) & 3) {
        case 0:
            gen_op_iwmmxt_unpacklb_M0_wRn(rd1);
            break;
        case 1:
            gen_op_iwmmxt_unpacklw_M0_wRn(rd1);
            break;
        case 2:
            gen_op_iwmmxt_unpackll_M0_wRn(rd1);
            break;
        case 3:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x10c: case 0x50c: case 0x90c: case 0xd0c: /* WUNPCKIH */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 22) & 3) {
        case 0:
            gen_op_iwmmxt_unpackhb_M0_wRn(rd1);
            break;
        case 1:
            gen_op_iwmmxt_unpackhw_M0_wRn(rd1);
            break;
        case 2:
            gen_op_iwmmxt_unpackhl_M0_wRn(rd1);
            break;
        case 3:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x012: case 0x112: case 0x412: case 0x512: /* WSAD */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        if (insn & (1 << 22))
            gen_op_iwmmxt_sadw_M0_wRn(rd1);
        else
            gen_op_iwmmxt_sadb_M0_wRn(rd1);
        if (!(insn & (1 << 20)))
            gen_op_iwmmxt_addl_M0_wRn(wrd);
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        break;
    case 0x010: case 0x110: case 0x210: case 0x310: /* WMUL */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        if (insn & (1 << 21))
            gen_op_iwmmxt_mulsw_M0_wRn(rd1, (insn & (1 << 20)) ? 16 : 0);
        else
            gen_op_iwmmxt_muluw_M0_wRn(rd1, (insn & (1 << 20)) ? 16 : 0);
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        break;
    case 0x410: case 0x510: case 0x610: case 0x710: /* WMAC */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        if (insn & (1 << 21))
            gen_op_iwmmxt_macsw_M0_wRn(rd1);
        else
            gen_op_iwmmxt_macuw_M0_wRn(rd1);
        if (!(insn & (1 << 20))) {
            if (insn & (1 << 21))
                gen_op_iwmmxt_addsq_M0_wRn(wrd);
            else
                gen_op_iwmmxt_adduq_M0_wRn(wrd);
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        break;
    case 0x006: case 0x406: case 0x806: case 0xc06: /* WCMPEQ */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 22) & 3) {
        case 0:
            gen_op_iwmmxt_cmpeqb_M0_wRn(rd1);
            break;
        case 1:
            gen_op_iwmmxt_cmpeqw_M0_wRn(rd1);
            break;
        case 2:
            gen_op_iwmmxt_cmpeql_M0_wRn(rd1);
            break;
        case 3:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x800: case 0x900: case 0xc00: case 0xd00: /* WAVG2 */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        if (insn & (1 << 22))
            gen_op_iwmmxt_avgw_M0_wRn(rd1, (insn >> 20) & 1);
        else
            gen_op_iwmmxt_avgb_M0_wRn(rd1, (insn >> 20) & 1);
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x802: case 0x902: case 0xa02: case 0xb02: /* WALIGNR */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        gen_op_iwmmxt_movl_T0_wCx(8 + ((insn >> 20) & 3));
        gen_op_movl_T1_im(7);
        gen_op_andl_T0_T1();
        gen_op_iwmmxt_align_M0_T0_wRn(rd1);
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        break;
    case 0x601: case 0x605: case 0x609: case 0x60d: /* TINSR */
        rd = (insn >> 12) & 0xf;
        wrd = (insn >> 16) & 0xf;
        gen_movl_T0_reg(s, rd);
        gen_op_iwmmxt_movq_M0_wRn(wrd);
        switch ((insn >> 6) & 3) {
        case 0:
            gen_op_movl_T1_im(0xff);
            gen_op_iwmmxt_insr_M0_T0_T1((insn & 7) << 3);
            break;
        case 1:
            gen_op_movl_T1_im(0xffff);
            gen_op_iwmmxt_insr_M0_T0_T1((insn & 3) << 4);
            break;
        case 2:
            gen_op_movl_T1_im(0xffffffff);
            gen_op_iwmmxt_insr_M0_T0_T1((insn & 1) << 5);
            break;
        case 3:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        break;
    case 0x107: case 0x507: case 0x907: case 0xd07: /* TEXTRM */
        rd = (insn >> 12) & 0xf;
        wrd = (insn >> 16) & 0xf;
        if (rd == 15)
            return 1;
        gen_op_iwmmxt_movq_M0_wRn(wrd);
        switch ((insn >> 22) & 3) {
        case 0:
            if (insn & 8)
                gen_op_iwmmxt_extrsb_T0_M0((insn & 7) << 3);
            else {
                gen_op_movl_T1_im(0xff);
                gen_op_iwmmxt_extru_T0_M0_T1((insn & 7) << 3);
            }
            break;
        case 1:
            if (insn & 8)
                gen_op_iwmmxt_extrsw_T0_M0((insn & 3) << 4);
            else {
                gen_op_movl_T1_im(0xffff);
                gen_op_iwmmxt_extru_T0_M0_T1((insn & 3) << 4);
            }
            break;
        case 2:
            gen_op_movl_T1_im(0xffffffff);
            gen_op_iwmmxt_extru_T0_M0_T1((insn & 1) << 5);
            break;
        case 3:
            return 1;
        }
        gen_op_movl_reg_TN[0][rd]();
        break;
    case 0x117: case 0x517: case 0x917: case 0xd17: /* TEXTRC */
        if ((insn & 0x000ff008) != 0x0003f000)
            return 1;
        gen_op_iwmmxt_movl_T1_wCx(3);
        switch ((insn >> 22) & 3) {
        case 0:
            gen_op_shrl_T1_im(((insn & 7) << 2) + 0);
            break;
        case 1:
            gen_op_shrl_T1_im(((insn & 3) << 3) + 4);
            break;
        case 2:
            gen_op_shrl_T1_im(((insn & 1) << 4) + 12);
            break;
        case 3:
            return 1;
        }
        gen_op_shll_T1_im(28);
        gen_op_movl_T0_T1();
        gen_op_movl_cpsr_T0(0xf0000000);
        break;
    case 0x401: case 0x405: case 0x409: case 0x40d: /* TBCST */
        rd = (insn >> 12) & 0xf;
        wrd = (insn >> 16) & 0xf;
        gen_movl_T0_reg(s, rd);
        switch ((insn >> 6) & 3) {
        case 0:
            gen_op_iwmmxt_bcstb_M0_T0();
            break;
        case 1:
            gen_op_iwmmxt_bcstw_M0_T0();
            break;
        case 2:
            gen_op_iwmmxt_bcstl_M0_T0();
            break;
        case 3:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        break;
    case 0x113: case 0x513: case 0x913: case 0xd13: /* TANDC */
        if ((insn & 0x000ff00f) != 0x0003f000)
            return 1;
        gen_op_iwmmxt_movl_T1_wCx(3);
        switch ((insn >> 22) & 3) {
        case 0:
            for (i = 0; i < 7; i ++) {
                gen_op_shll_T1_im(4);
                gen_op_andl_T0_T1();
            }
            break;
        case 1:
            for (i = 0; i < 3; i ++) {
                gen_op_shll_T1_im(8);
                gen_op_andl_T0_T1();
            }
            break;
        case 2:
            gen_op_shll_T1_im(16);
            gen_op_andl_T0_T1();
            break;
        case 3:
            return 1;
        }
        gen_op_movl_cpsr_T0(0xf0000000);
        break;
    case 0x01c: case 0x41c: case 0x81c: case 0xc1c: /* WACC */
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 22) & 3) {
        case 0:
            gen_op_iwmmxt_addcb_M0();
            break;
        case 1:
            gen_op_iwmmxt_addcw_M0();
            break;
        case 2:
            gen_op_iwmmxt_addcl_M0();
            break;
        case 3:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        break;
    case 0x115: case 0x515: case 0x915: case 0xd15: /* TORC */
        if ((insn & 0x000ff00f) != 0x0003f000)
            return 1;
        gen_op_iwmmxt_movl_T1_wCx(3);
        switch ((insn >> 22) & 3) {
        case 0:
            for (i = 0; i < 7; i ++) {
                gen_op_shll_T1_im(4);
                gen_op_orl_T0_T1();
            }
            break;
        case 1:
            for (i = 0; i < 3; i ++) {
                gen_op_shll_T1_im(8);
                gen_op_orl_T0_T1();
            }
            break;
        case 2:
            gen_op_shll_T1_im(16);
            gen_op_orl_T0_T1();
            break;
        case 3:
            return 1;
        }
        gen_op_movl_T1_im(0xf0000000);
        gen_op_andl_T0_T1();
        gen_op_movl_cpsr_T0(0xf0000000);
        break;
    case 0x103: case 0x503: case 0x903: case 0xd03: /* TMOVMSK */
        rd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        if ((insn & 0xf) != 0)
            return 1;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 22) & 3) {
        case 0:
            gen_op_iwmmxt_msbb_T0_M0();
            break;
        case 1:
            gen_op_iwmmxt_msbw_T0_M0();
            break;
        case 2:
            gen_op_iwmmxt_msbl_T0_M0();
            break;
        case 3:
            return 1;
        }
        gen_movl_reg_T0(s, rd);
        break;
    case 0x106: case 0x306: case 0x506: case 0x706: /* WCMPGT */
    case 0x906: case 0xb06: case 0xd06: case 0xf06:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 22) & 3) {
        case 0:
            if (insn & (1 << 21))
                gen_op_iwmmxt_cmpgtsb_M0_wRn(rd1);
            else
                gen_op_iwmmxt_cmpgtub_M0_wRn(rd1);
            break;
        case 1:
            if (insn & (1 << 21))
                gen_op_iwmmxt_cmpgtsw_M0_wRn(rd1);
            else
                gen_op_iwmmxt_cmpgtuw_M0_wRn(rd1);
            break;
        case 2:
            if (insn & (1 << 21))
                gen_op_iwmmxt_cmpgtsl_M0_wRn(rd1);
            else
                gen_op_iwmmxt_cmpgtul_M0_wRn(rd1);
            break;
        case 3:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x00e: case 0x20e: case 0x40e: case 0x60e: /* WUNPCKEL */
    case 0x80e: case 0xa0e: case 0xc0e: case 0xe0e:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 22) & 3) {
        case 0:
            if (insn & (1 << 21))
                gen_op_iwmmxt_unpacklsb_M0();
            else
                gen_op_iwmmxt_unpacklub_M0();
            break;
        case 1:
            if (insn & (1 << 21))
                gen_op_iwmmxt_unpacklsw_M0();
            else
                gen_op_iwmmxt_unpackluw_M0();
            break;
        case 2:
            if (insn & (1 << 21))
                gen_op_iwmmxt_unpacklsl_M0();
            else
                gen_op_iwmmxt_unpacklul_M0();
            break;
        case 3:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x00c: case 0x20c: case 0x40c: case 0x60c: /* WUNPCKEH */
    case 0x80c: case 0xa0c: case 0xc0c: case 0xe0c:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 22) & 3) {
        case 0:
            if (insn & (1 << 21))
                gen_op_iwmmxt_unpackhsb_M0();
            else
                gen_op_iwmmxt_unpackhub_M0();
            break;
        case 1:
            if (insn & (1 << 21))
                gen_op_iwmmxt_unpackhsw_M0();
            else
                gen_op_iwmmxt_unpackhuw_M0();
            break;
        case 2:
            if (insn & (1 << 21))
                gen_op_iwmmxt_unpackhsl_M0();
            else
                gen_op_iwmmxt_unpackhul_M0();
            break;
        case 3:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x204: case 0x604: case 0xa04: case 0xe04: /* WSRL */
    case 0x214: case 0x614: case 0xa14: case 0xe14:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        if (gen_iwmmxt_shift(insn, 0xff))
            return 1;
        switch ((insn >> 22) & 3) {
        case 0:
            return 1;
        case 1:
            gen_op_iwmmxt_srlw_M0_T0();
            break;
        case 2:
            gen_op_iwmmxt_srll_M0_T0();
            break;
        case 3:
            gen_op_iwmmxt_srlq_M0_T0();
            break;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x004: case 0x404: case 0x804: case 0xc04: /* WSRA */
    case 0x014: case 0x414: case 0x814: case 0xc14:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        if (gen_iwmmxt_shift(insn, 0xff))
            return 1;
        switch ((insn >> 22) & 3) {
        case 0:
            return 1;
        case 1:
            gen_op_iwmmxt_sraw_M0_T0();
            break;
        case 2:
            gen_op_iwmmxt_sral_M0_T0();
            break;
        case 3:
            gen_op_iwmmxt_sraq_M0_T0();
            break;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x104: case 0x504: case 0x904: case 0xd04: /* WSLL */
    case 0x114: case 0x514: case 0x914: case 0xd14:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        if (gen_iwmmxt_shift(insn, 0xff))
            return 1;
        switch ((insn >> 22) & 3) {
        case 0:
            return 1;
        case 1:
            gen_op_iwmmxt_sllw_M0_T0();
            break;
        case 2:
            gen_op_iwmmxt_slll_M0_T0();
            break;
        case 3:
            gen_op_iwmmxt_sllq_M0_T0();
            break;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x304: case 0x704: case 0xb04: case 0xf04: /* WROR */
    case 0x314: case 0x714: case 0xb14: case 0xf14:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 22) & 3) {
        case 0:
            return 1;
        case 1:
            if (gen_iwmmxt_shift(insn, 0xf))
                return 1;
            gen_op_iwmmxt_rorw_M0_T0();
            break;
        case 2:
            if (gen_iwmmxt_shift(insn, 0x1f))
                return 1;
            gen_op_iwmmxt_rorl_M0_T0();
            break;
        case 3:
            if (gen_iwmmxt_shift(insn, 0x3f))
                return 1;
            gen_op_iwmmxt_rorq_M0_T0();
            break;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x116: case 0x316: case 0x516: case 0x716: /* WMIN */
    case 0x916: case 0xb16: case 0xd16: case 0xf16:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 22) & 3) {
        case 0:
            if (insn & (1 << 21))
                gen_op_iwmmxt_minsb_M0_wRn(rd1);
            else
                gen_op_iwmmxt_minub_M0_wRn(rd1);
            break;
        case 1:
            if (insn & (1 << 21))
                gen_op_iwmmxt_minsw_M0_wRn(rd1);
            else
                gen_op_iwmmxt_minuw_M0_wRn(rd1);
            break;
        case 2:
            if (insn & (1 << 21))
                gen_op_iwmmxt_minsl_M0_wRn(rd1);
            else
                gen_op_iwmmxt_minul_M0_wRn(rd1);
            break;
        case 3:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        break;
    case 0x016: case 0x216: case 0x416: case 0x616: /* WMAX */
    case 0x816: case 0xa16: case 0xc16: case 0xe16:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 22) & 3) {
        case 0:
            if (insn & (1 << 21))
                gen_op_iwmmxt_maxsb_M0_wRn(rd1);
            else
                gen_op_iwmmxt_maxub_M0_wRn(rd1);
            break;
        case 1:
            if (insn & (1 << 21))
                gen_op_iwmmxt_maxsw_M0_wRn(rd1);
            else
                gen_op_iwmmxt_maxuw_M0_wRn(rd1);
            break;
        case 2:
            if (insn & (1 << 21))
                gen_op_iwmmxt_maxsl_M0_wRn(rd1);
            else
                gen_op_iwmmxt_maxul_M0_wRn(rd1);
            break;
        case 3:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        break;
    case 0x002: case 0x102: case 0x202: case 0x302: /* WALIGNI */
    case 0x402: case 0x502: case 0x602: case 0x702:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        gen_op_movl_T0_im((insn >> 20) & 3);
        gen_op_iwmmxt_align_M0_T0_wRn(rd1);
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        break;
    case 0x01a: case 0x11a: case 0x21a: case 0x31a: /* WSUB */
    case 0x41a: case 0x51a: case 0x61a: case 0x71a:
    case 0x81a: case 0x91a: case 0xa1a: case 0xb1a:
    case 0xc1a: case 0xd1a: case 0xe1a: case 0xf1a:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 20) & 0xf) {
        case 0x0:
            gen_op_iwmmxt_subnb_M0_wRn(rd1);
            break;
        case 0x1:
            gen_op_iwmmxt_subub_M0_wRn(rd1);
            break;
        case 0x3:
            gen_op_iwmmxt_subsb_M0_wRn(rd1);
            break;
        case 0x4:
            gen_op_iwmmxt_subnw_M0_wRn(rd1);
            break;
        case 0x5:
            gen_op_iwmmxt_subuw_M0_wRn(rd1);
            break;
        case 0x7:
            gen_op_iwmmxt_subsw_M0_wRn(rd1);
            break;
        case 0x8:
            gen_op_iwmmxt_subnl_M0_wRn(rd1);
            break;
        case 0x9:
            gen_op_iwmmxt_subul_M0_wRn(rd1);
            break;
        case 0xb:
            gen_op_iwmmxt_subsl_M0_wRn(rd1);
            break;
        default:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x01e: case 0x11e: case 0x21e: case 0x31e: /* WSHUFH */
    case 0x41e: case 0x51e: case 0x61e: case 0x71e:
    case 0x81e: case 0x91e: case 0xa1e: case 0xb1e:
    case 0xc1e: case 0xd1e: case 0xe1e: case 0xf1e:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        gen_op_movl_T0_im(((insn >> 16) & 0xf0) | (insn & 0x0f));
        gen_op_iwmmxt_shufh_M0_T0();
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x018: case 0x118: case 0x218: case 0x318: /* WADD */
    case 0x418: case 0x518: case 0x618: case 0x718:
    case 0x818: case 0x918: case 0xa18: case 0xb18:
    case 0xc18: case 0xd18: case 0xe18: case 0xf18:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        switch ((insn >> 20) & 0xf) {
        case 0x0:
            gen_op_iwmmxt_addnb_M0_wRn(rd1);
            break;
        case 0x1:
            gen_op_iwmmxt_addub_M0_wRn(rd1);
            break;
        case 0x3:
            gen_op_iwmmxt_addsb_M0_wRn(rd1);
            break;
        case 0x4:
            gen_op_iwmmxt_addnw_M0_wRn(rd1);
            break;
        case 0x5:
            gen_op_iwmmxt_adduw_M0_wRn(rd1);
            break;
        case 0x7:
            gen_op_iwmmxt_addsw_M0_wRn(rd1);
            break;
        case 0x8:
            gen_op_iwmmxt_addnl_M0_wRn(rd1);
            break;
        case 0x9:
            gen_op_iwmmxt_addul_M0_wRn(rd1);
            break;
        case 0xb:
            gen_op_iwmmxt_addsl_M0_wRn(rd1);
            break;
        default:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x008: case 0x108: case 0x208: case 0x308: /* WPACK */
    case 0x408: case 0x508: case 0x608: case 0x708:
    case 0x808: case 0x908: case 0xa08: case 0xb08:
    case 0xc08: case 0xd08: case 0xe08: case 0xf08:
        wrd = (insn >> 12) & 0xf;
        rd0 = (insn >> 16) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        gen_op_iwmmxt_movq_M0_wRn(rd0);
        if (!(insn & (1 << 20)))
            return 1;
        switch ((insn >> 22) & 3) {
        case 0:
            return 1;
        case 1:
            if (insn & (1 << 21))
                gen_op_iwmmxt_packsw_M0_wRn(rd1);
            else
                gen_op_iwmmxt_packuw_M0_wRn(rd1);
            break;
        case 2:
            if (insn & (1 << 21))
                gen_op_iwmmxt_packsl_M0_wRn(rd1);
            else
                gen_op_iwmmxt_packul_M0_wRn(rd1);
            break;
        case 3:
            if (insn & (1 << 21))
                gen_op_iwmmxt_packsq_M0_wRn(rd1);
            else
                gen_op_iwmmxt_packuq_M0_wRn(rd1);
            break;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        gen_op_iwmmxt_set_cup();
        break;
    case 0x201: case 0x203: case 0x205: case 0x207:
    case 0x209: case 0x20b: case 0x20d: case 0x20f:
    case 0x211: case 0x213: case 0x215: case 0x217:
    case 0x219: case 0x21b: case 0x21d: case 0x21f:
        wrd = (insn >> 5) & 0xf;
        rd0 = (insn >> 12) & 0xf;
        rd1 = (insn >> 0) & 0xf;
        if (rd0 == 0xf || rd1 == 0xf)
            return 1;
        gen_op_iwmmxt_movq_M0_wRn(wrd);
        switch ((insn >> 16) & 0xf) {
        case 0x0: /* TMIA */
            gen_op_movl_TN_reg[0][rd0]();
            gen_op_movl_TN_reg[1][rd1]();
            gen_op_iwmmxt_muladdsl_M0_T0_T1();
            break;
        case 0x8: /* TMIAPH */
            gen_op_movl_TN_reg[0][rd0]();
            gen_op_movl_TN_reg[1][rd1]();
            gen_op_iwmmxt_muladdsw_M0_T0_T1();
            break;
        case 0xc: case 0xd: case 0xe: case 0xf: /* TMIAxy */
            gen_op_movl_TN_reg[1][rd0]();
            if (insn & (1 << 16))
                gen_op_shrl_T1_im(16);
            gen_op_movl_T0_T1();
            gen_op_movl_TN_reg[1][rd1]();
            if (insn & (1 << 17))
                gen_op_shrl_T1_im(16);
            gen_op_iwmmxt_muladdswl_M0_T0_T1();
            break;
        default:
            return 1;
        }
        gen_op_iwmmxt_movq_wRn_M0(wrd);
        gen_op_iwmmxt_set_mup();
        break;
    default:
        return 1;
    }

    return 0;
}

/* Disassemble an XScale DSP instruction.  Returns nonzero if an error occured
   (ie. an undefined instruction).  */
function disas_dsp_insn(/* CPUARMState * */env, /* DisasContext * */ s, /* uint32_t */ insn)
{
    var acc, rd0, rd1, rdhi, rdlo;

    if ((insn & 0x0ff00f10) == 0x0e200010) {
        /* Multiply with Internal Accumulate Format */
        rd0 = (insn >> 12) & 0xf;
        rd1 = insn & 0xf;
        acc = (insn >> 5) & 7;

        if (acc != 0)
            return 1;

        switch ((insn >> 16) & 0xf) {
        case 0x0: /* MIA */
            gen_op_movl_TN_reg[0][rd0]();
            gen_op_movl_TN_reg[1][rd1]();
            gen_op_iwmmxt_muladdsl_M0_T0_T1();
            break;
        case 0x8: /* MIAPH */
            gen_op_movl_TN_reg[0][rd0]();
            gen_op_movl_TN_reg[1][rd1]();
            gen_op_iwmmxt_muladdsw_M0_T0_T1();
            break;
        case 0xc: /* MIABB */
        case 0xd: /* MIABT */
        case 0xe: /* MIATB */
        case 0xf: /* MIATT */
            gen_op_movl_TN_reg[1][rd0]();
            if (insn & (1 << 16))
                gen_op_shrl_T1_im(16);
            gen_op_movl_T0_T1();
            gen_op_movl_TN_reg[1][rd1]();
            if (insn & (1 << 17))
                gen_op_shrl_T1_im(16);
            gen_op_iwmmxt_muladdswl_M0_T0_T1();
            break;
        default:
            return 1;
        }

        gen_op_iwmmxt_movq_wRn_M0(acc);
        return 0;
    }

    if ((insn & 0x0fe00ff8) == 0x0c400000) {
        /* Internal Accumulator Access Format */
        rdhi = (insn >> 16) & 0xf;
        rdlo = (insn >> 12) & 0xf;
        acc = insn & 7;

        if (acc != 0)
            return 1;

        if (insn & (1 << 20)) { /* MRA */
            gen_op_iwmmxt_movl_T0_T1_wRn(acc);
            gen_op_movl_reg_TN[0][rdlo]();
            gen_op_movl_T0_im((1 << (40 - 32)) - 1);
            gen_op_andl_T0_T1();
            gen_op_movl_reg_TN[0][rdhi]();
        } else { /* MAR */
            gen_op_movl_TN_reg[0][rdlo]();
            gen_op_movl_TN_reg[1][rdhi]();
            gen_op_iwmmxt_movl_wRn_T0_T1(acc);
        }
        return 0;
    }

    return 1;
}

/* Disassemble system coprocessor instruction.  Return nonzero if
   instruction is not defined.  */
function disas_cp_insn(/* CPUARMState * */env, /* DisasContext * */ s, /* uint32_t */ insn)
{
    var /* uint32_t */ rd = (insn >> 12) & 0xf;
    var /* uint32_t */ cp = (insn >> 8) & 0xf;
    if ((s.user)) {
        return 1;
    }

    if (insn & (1 << 20)) {
        if (!env.cp[cp].cp_read)
            return 1;
        gen_op_movl_T0_im(s.pc);
        gen_op_movl_reg_TN[0][15]();
        gen_op_movl_T0_cp(insn);
        gen_movl_reg_T0(s, rd);
    } else {
        if (!env.cp[cp].cp_write)
            return 1;
        gen_op_movl_T0_im(s.pc);
        gen_op_movl_reg_TN[0][15]();
        gen_movl_T0_reg(s, rd);
        gen_op_movl_cp_T0(insn);
    }
    return 0;
}

function cp15_user_ok(/* uint32_t */ insn)
{
    var cpn = (insn >> 16) & 0xf;
    var cpm = insn & 0xf;
    var op = ((insn >> 5) & 7) | ((insn >> 18) & 0x38);

    if (cpn == 13 && cpm == 0) {
        /* TLS register.  */
        if (op == 2 || (op == 3 && (insn & (1 << 20))))
            return 1;
    }
    if (cpn == 7) {
        /* ISB, DSB, DMB.  */
        if ((cpm == 5 && op == 4)
                || (cpm == 10 && (op == 4 || op == 5)))
            return 1;
    }
    return 0;
}

/* Disassemble system coprocessor (cp15) instruction.  Return nonzero if
   instruction is not defined.  */
function disas_cp15_insn(/* CPUARMState * */env, /* DisasContext * */ s, /* uint32_t */ insn)
{
    var /* uint32_t */ rd;

    /* M profile cores use memory mapped registers instead of cp15.  */
    if (arm_feature(env, ARM_FEATURE_M))
        return 1;

    if ((insn & (1 << 25)) == 0) {
        if (insn & (1 << 20)) {
            /* mrrc */
            return 1;
        }
        /* mcrr.  Used for block cache operations, so implement as no-op.  */
        return 0;
    }
    if ((insn & (1 << 4)) == 0) {
        /* cdp */
        return 1;
    }
    if ((s.user) && !cp15_user_ok(insn)) {
        return 1;
    }
    if ((insn & 0x0fff0fff) == 0x0e070f90
        || (insn & 0x0fff0fff) == 0x0e070f58) {
        /* Wait for interrupt.  */
        gen_op_movl_T0_im(s.pc);
        gen_op_movl_reg_TN[0][15]();
        s.is_jmp = 4;
        return 0;
    }
    rd = (insn >>> 12) & 0xf;
    if (insn & (1 << 20)) {
        gen_op_movl_T0_cp15(insn);
        /* If the destination register is r15 then sets condition codes.  */
        if (rd != 15)
            gen_movl_reg_T0(s, rd);
    } else {
        gen_movl_T0_reg(s, rd);
        gen_op_movl_cp15_T0(insn);
        /* Normally we would always end the TB here, but Linux
         * arch/arm/mach-pxa/sleep.S expects two instructions following
         * an MMU enable to execute from cache.  Imitate this behaviour.  */
        if (!arm_feature(env, ARM_FEATURE_XSCALE) ||
                (insn & 0x0fff0fff) != 0x0e010f10)
            gen_lookup_tb(s);
    }
    return 0;
}
/** function XXX **/
/* void  */ function gen_goto_tb(/* DisasContext * */ s, /* int */ n, /* uint32_t */ dest)
{
    var tb;

    tb = s.tb;
    /* check if address is within 512 bytes */
    if ((tb.pc & ~((1 << 10) - 1)) == (dest & ~((1 << 10) - 1))) {
        if (n == 0)
            gen_op_goto_tb0((tb));
        else
            gen_op_goto_tb1((tb));
        gen_op_movl_T0_im(dest);
        gen_op_movl_r15_T0();
        gen_op_movl_T0_im(tb); // + n);
        gen_op_exit_tb();
    } else {
        gen_op_movl_T0_im(dest);
        gen_op_movl_r15_T0();
        gen_op_movl_T0_0();
        gen_op_exit_tb();
    }
}

/** function XXX **/
/* void  */ function gen_jmp (/* DisasContext * */ s, /* uint32_t */ dest)
{
    if (s.singlestep_enabled == 0) {
        /* An indirect jump so that we still trigger the debug exception.  */
        if (s.thumb)
          dest |= 1;
        gen_op_movl_T0_im(dest);
        gen_bx(s);
    } else {
        gen_goto_tb(s, 0, dest);
        s.is_jmp = 3;
    }
}

/** function XXX **/
/* void  */ function gen_mulxy(/* int */ x, /* int */y)
{
    if (x)
        gen_op_sarl_T0_im(16);
    else
        gen_op_sxth_T0();
    if (y)
        gen_op_sarl_T1_im(16);
    else
        gen_op_sxth_T1();
    gen_op_mul_T0_T1();
}

/* Return the mask of PSR bits set by a MSR instruction.  */
function msr_mask(/*CPUARMState * */ env, /* DisasContext * */ s, /* int */ flags, /* int */ spsr) {
    var /* uint32_t */ mask;

    mask = 0;
    if (flags & (1 << 0))
        mask |= 0xff;
    if (flags & (1 << 1))
        mask |= 0xff00;
    if (flags & (1 << 2))
        mask |= 0xff0000;
    if (flags & (1 << 3))
        mask |= 0xff000000;

    /* Mask out undefined bits.  */
    mask &= ~(0xf << 20);
    if (!arm_feature(env, ARM_FEATURE_V6))
        mask &= ~((1 << 9) | (0xf << 16));
    if (!arm_feature(env, ARM_FEATURE_THUMB2))
        mask &= ~((3 << 25) | (0xfc00));
    /* Mask out execution state bits.  */
    if (!spsr)
        mask &= ~((1 << 5) | ((3 << 25) | (0xfc00)) | (1 << 24));
    /* Mask out privileged bits.  */
    if ((s.user))
        mask &= (((1 << 31) | (1 << 30) | (1 << 29) | (1 << 28)) | (1 << 27) | (0xf << 16));
    return mask;
}

/* Returns nonzero if access to the PSR is not permitted.  */
function gen_set_psr_T0(/* DisasContext * */ s, /* uint32_t */ mask, /* int */ spsr)
{
    if (spsr) {
        /* ??? This is also undefined in system mode.  */
        if ((s.user))
            return 1;
        gen_op_movl_spsr_T0(mask);
    } else {
        gen_op_movl_cpsr_T0(mask);
    }
    gen_lookup_tb(s);
    return 0;
}

/* Generate an old-style exception return.  */
function gen_exception_return(/* DisasContext * */ s)
{
    gen_op_movl_reg_TN[0][15]();
    gen_op_movl_T0_spsr();
    gen_op_movl_cpsr_T0(0xffffffff);
    s.is_jmp = 2;
}

/* Generate a v6 exception return.  */
function gen_rfe(/* DisasContext * */ s)
{
    gen_op_movl_cpsr_T0(0xffffffff);
    gen_op_movl_T0_T2();
    gen_op_movl_reg_TN[0][15]();
    s.is_jmp = 2;
}

/** function XXX **/
function gen_neon_add(size)
{
    switch (size) {
    case 0: gen_op_neon_add_u8(); break;
    case 1: gen_op_neon_add_u16(); break;
    case 2: gen_op_addl_T0_T1(); break;
    default: 
        return 1;
    }
    return 0;
}

/* 32-bit pairwise ops end up the same as the elementsise versions.  */
/** function XXX **/
/* void  */ function gen_op_neon_widen_u32()
{
    gen_op_movl_T1_im(0);
}

/** function XXX **/
/* void  */ function gen_neon_get_scalar(/* int */ size, /* int */ reg)
{
    if (size == 1) {
        gen_op_neon_getreg_T0(neon_reg_offset(reg >> 1, reg & 1));
    } else {
        gen_op_neon_getreg_T0(neon_reg_offset(reg >> 2, (reg >> 1) & 1));
        if (reg & 1)
            gen_op_neon_dup_low16();
        else
            gen_op_neon_dup_high16();
    }
}

function gen_neon_unzip(/* int */ reg, /* int */ q, /* int */ tmp, /* int */ size)
{
    var n;

    for (n = 0; n < q + 1; n += 2) {
        gen_op_neon_getreg_T0(neon_reg_offset(reg, n));
        gen_op_neon_getreg_T0(neon_reg_offset(reg, n + n));
        switch (size) {
        case 0: gen_op_neon_unzip_u8(); break;
        case 1: gen_op_neon_zip_u16(); break; /* zip and unzip are the same.  */
        case 2: /* no-op */; break;
        default: abort();
        }
        gen_neon_movl_scratch_T0(tmp + n);
        gen_neon_movl_scratch_T1(tmp + n + 1);
    }
}

/* Translate a NEON load/store element instruction.  Return nonzero if the
   instruction is invalid.  */
function disas_neon_ls_insn(/* CPUARMState * */ env, /* DisasContext * */ s, /* uint32_t */ insn)
{
    var rd, rn, rm;
    var op;
    var nregs;
    var interleave;
    var stride;
    var size;
    var reg;
    var pass;
    var load;
    var shift;
    var /* uint32_t */ mask;
    var n;

    if (!vfp_enabled(env))
      return 1;
    do { if (arm_feature(env, ARM_FEATURE_VFP3)) { rd = (((insn) >> (12)) & 0x0f) | (((insn) >> ((22) - 4)) & 0x10); } else { if (insn & (1 << (22))) return 1; rd = ((insn) >> (12)) & 0x0f; }} while (0);
    rn = (insn >> 16) & 0xf;
    rm = insn & 0xf;
    load = (insn & (1 << 21)) != 0;
    if ((insn & (1 << 23)) == 0) {
        /* Load store all elements.  */
        op = (insn >> 8) & 0xf;
        size = (insn >> 6) & 3;
        if (op > 10 || size == 3)
            return 1;
        nregs = neon_ls_element_type[op].nregs;
        interleave = neon_ls_element_type[op].interleave;
        gen_movl_T1_reg(s, rn);
        stride = (1 << size) * interleave;
        for (reg = 0; reg < nregs; reg++) {
            if (interleave > 2 || (interleave == 2 && nregs == 2)) {
                gen_movl_T1_reg(s, rn);
                gen_op_addl_T1_im((1 << size) * reg);
            } else if (interleave == 2 && nregs == 4 && reg == 2) {
                gen_movl_T1_reg(s, rn);
                gen_op_addl_T1_im(1 << size);
            }
            for (pass = 0; pass < 2; pass++) {
                if (size == 2) {
                    if (load) {
                        do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass));
                    } else {
                        gen_op_neon_getreg_T0(neon_reg_offset(rd, pass));
                        do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                    }
                    gen_op_addl_T1_im(stride);
                } else if (size == 1) {
                    if (load) {
                        do { s.is_mem = 1; if ((s.user)) gen_op_lduw_user(); else gen_op_lduw_kernel(); } while (0);
                        gen_op_addl_T1_im(stride);
                        gen_op_movl_T2_T0();
                        do { s.is_mem = 1; if ((s.user)) gen_op_lduw_user(); else gen_op_lduw_kernel(); } while (0);
                        gen_op_addl_T1_im(stride);
                        gen_op_neon_insert_elt(16, 0xffff);
                        gen_op_neon_setreg_T2(neon_reg_offset(rd, pass));
                    } else {
                        gen_op_neon_getreg_T2(neon_reg_offset(rd, pass));
                        gen_op_movl_T0_T2();
                        do { s.is_mem = 1; if ((s.user)) gen_op_stw_user(); else gen_op_stw_kernel(); } while (0);
                        gen_op_addl_T1_im(stride);
                        gen_op_neon_extract_elt(16, 0xffff0000);
                        do { s.is_mem = 1; if ((s.user)) gen_op_stw_user(); else gen_op_stw_kernel(); } while (0);
                        gen_op_addl_T1_im(stride);
                    }
                } else /* size == 0 */ {
                    if (load) {
                        mask = 0xff;
                        for (n = 0; n < 4; n++) {
                            do { s.is_mem = 1; if ((s.user)) gen_op_ldub_user(); else gen_op_ldub_kernel(); } while (0);
                            gen_op_addl_T1_im(stride);
                            if (n == 0) {
                                gen_op_movl_T2_T0();
                            } else {
                                gen_op_neon_insert_elt(n * 8, ~mask);
                            }
                            mask <<= 8;
                        }
                        gen_op_neon_setreg_T2(neon_reg_offset(rd, pass));
                    } else {
                        gen_op_neon_getreg_T2(neon_reg_offset(rd, pass));
                        mask = 0xff;
                        for (n = 0; n < 4; n++) {
                            if (n == 0) {
                                gen_op_movl_T0_T2();
                            } else {
                                gen_op_neon_extract_elt(n * 8, mask);
                            }
                            do { s.is_mem = 1; if ((s.user)) gen_op_stb_user(); else gen_op_stb_kernel(); } while (0);
                            gen_op_addl_T1_im(stride);
                            mask <<= 8;
                        }
                    }
                }
            }
            rd += neon_ls_element_type[op].spacing;
        }
        stride = nregs * 8;
    } else {
        size = (insn >> 10) & 3;
        if (size == 3) {
            /* Load single element to all lanes.  */
            if (!load)
                return 1;
            size = (insn >> 6) & 3;
            nregs = ((insn >> 8) & 3) + 1;
            stride = (insn & (1 << 5)) ? 2 : 1;
            gen_movl_T1_reg(s, rn);
            for (reg = 0; reg < nregs; reg++) {
                switch (size) {
                case 0:
                    do { s.is_mem = 1; if ((s.user)) gen_op_ldub_user(); else gen_op_ldub_kernel(); } while (0);
                    gen_op_neon_dup_u8(0);
                    break;
                case 1:
                    do { s.is_mem = 1; if ((s.user)) gen_op_lduw_user(); else gen_op_lduw_kernel(); } while (0);
                    gen_op_neon_dup_low16();
                    break;
                case 2:
                    do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                    break;
                case 3:
                    return 1;
                }
                gen_op_addl_T1_im(1 << size);
                gen_op_neon_setreg_T0(neon_reg_offset(rd, 0));
                gen_op_neon_setreg_T0(neon_reg_offset(rd, 1));
                rd += stride;
            }
            stride = (1 << size) * nregs;
        } else {
            /* Single element.  */
            pass = (insn >> 7) & 1;
            switch (size) {
            case 0:
                shift = ((insn >> 5) & 3) * 8;
                mask = 0xff << shift;
                stride = 1;
                break;
            case 1:
                shift = ((insn >> 6) & 1) * 16;
                mask = shift ? 0xffff0000 : 0xffff;
                stride = (insn & (1 << 5)) ? 2 : 1;
                break;
            case 2:
                shift = 0;
                mask = 0xffffffff;
                stride = (insn & (1 << 6)) ? 2 : 1;
                break;
            default:
                abort();
            }
            nregs = ((insn >> 8) & 3) + 1;
            gen_movl_T1_reg(s, rn);
            for (reg = 0; reg < nregs; reg++) {
                if (load) {
                    if (size != 2) {
                        gen_op_neon_getreg_T2(neon_reg_offset(rd, pass));
                    }
                    switch (size) {
                    case 0:
                        do { s.is_mem = 1; if ((s.user)) gen_op_ldub_user(); else gen_op_ldub_kernel(); } while (0);
                        break;
                    case 1:
                        do { s.is_mem = 1; if ((s.user)) gen_op_lduw_user(); else gen_op_lduw_kernel(); } while (0);
                        break;
                    case 2:
                        do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass));
                        break;
                    }
                    if (size != 2) {
                        gen_op_neon_insert_elt(shift, ~mask);
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass));
                    }
                } else { /* Store */
                    if (size == 2) {
                        gen_op_neon_getreg_T0(neon_reg_offset(rd, pass));
                    } else {
                        gen_op_neon_getreg_T2(neon_reg_offset(rd, pass));
                        gen_op_neon_extract_elt(shift, mask);
                    }
                    switch (size) {
                    case 0:
                        do { s.is_mem = 1; if ((s.user)) gen_op_stb_user(); else gen_op_stb_kernel(); } while (0);
                        break;
                    case 1:
                        do { s.is_mem = 1; if ((s.user)) gen_op_stw_user(); else gen_op_stw_kernel(); } while (0);
                        break;
                    case 2:
                        do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                        break;
                    }
                }
                rd += stride;
                gen_op_addl_T1_im(1 << size);
            }
            stride = nregs * (1 << size);
        }
    }
    if (rm != 15) {
        gen_movl_T1_reg(s, rn);
        if (rm == 13) {
            gen_op_addl_T1_im(stride);
        } else {
            gen_movl_T2_reg(s, rm);
            gen_op_addl_T1_T2();
        }
        gen_movl_reg_T1(s, rn);
    }
    return 0;
}

/* Translate a NEON data processing instruction.  Return nonzero if the
   instruction is invalid.
   In general we process vectors in 32-bit chunks.  This means we can reuse
   some of the scalar ops, and hopefully the code generated for 32-bit
   hosts won't be too awful.  The downside is that the few 64-bit operations
   (mainly shifts) get complicated.  */

function disas_neon_data_insn(/* CPUARMState * */ env, /* DisasContext * */ s, /* uint32_t */ insn)
{
    var op;
    var q;
    var rd, rn, rm;
    var size;
    var shift;
    var pass;
    var count;
    var pairwise;
    var u;
    var n;
    var /* uint32_t */ imm;

    if (!vfp_enabled(env))
      return 1;
    q = (insn & (1 << 6)) != 0;
    u = (insn >> 24) & 1;
    do { if (arm_feature(env, ARM_FEATURE_VFP3)) { rd = (((insn) >> (12)) & 0x0f) | (((insn) >> ((22) - 4)) & 0x10); } else { if (insn & (1 << (22))) return 1; rd = ((insn) >> (12)) & 0x0f; }} while (0);
    do { if (arm_feature(env, ARM_FEATURE_VFP3)) { rn = (((insn) >> (16)) & 0x0f) | (((insn) >> ((7) - 4)) & 0x10); } else { if (insn & (1 << (7))) return 1; rn = ((insn) >> (16)) & 0x0f; }} while (0);
    do { if (arm_feature(env, ARM_FEATURE_VFP3)) { rm = (((insn) >> (0)) & 0x0f) | (((insn) >> ((5) - 4)) & 0x10); } else { if (insn & (1 << (5))) return 1; rm = ((insn) >> (0)) & 0x0f; }} while (0);
    size = (insn >> 20) & 3;
    if ((insn & (1 << 23)) == 0) {
        /* Three register same length.  */
        op = ((insn >> 7) & 0x1e) | ((insn >> 4) & 1);
        if (size == 3 && (op == 1 || op == 5 || op == 16)) {
            for (pass = 0; pass < (q ? 2 : 1); pass++) {
                gen_op_neon_getreg_T0(neon_reg_offset(rm, pass * 2));
                gen_op_neon_getreg_T1(neon_reg_offset(rm, pass * 2 + 1));
                gen_neon_movl_scratch_T0(0);
                gen_neon_movl_scratch_T1(1);
                gen_op_neon_getreg_T0(neon_reg_offset(rn, pass * 2));
                gen_op_neon_getreg_T1(neon_reg_offset(rn, pass * 2 + 1));
                switch (op) {
                case 1: /* VQADD */
                    if (u) {
                        gen_op_neon_addl_saturate_u64();
                    } else {
                        gen_op_neon_addl_saturate_s64();
                    }
                    break;
                case 5: /* VQSUB */
                    if (u) {
                        gen_op_neon_subl_saturate_u64();
                    } else {
                        gen_op_neon_subl_saturate_s64();
                    }
                    break;
                case 16:
                    if (u) {
                        gen_op_neon_subl_u64();
                    } else {
                        gen_op_neon_addl_u64();
                    }
                    break;
                default:
                    abort();
                }
                gen_op_neon_setreg_T0(neon_reg_offset(rd, pass * 2));
                gen_op_neon_setreg_T1(neon_reg_offset(rd, pass * 2 + 1));
            }
            return 0;
        }
        switch (op) {
        case 8: /* VSHL */
        case 9: /* VQSHL */
        case 10: /* VRSHL */
        case 11: /* VQSHL */
            /* Shift operations have Rn and Rm reversed.  */
            {
                var tmp;
                tmp = rn;
                rn = rm;
                rm = tmp;
                pairwise = 0;
            }
            break;
        case 20: /* VPMAX */
        case 21: /* VPMIN */
        case 23: /* VPADD */
            pairwise = 1;
            break;
        case 26: /* VPADD (float) */
            pairwise = (u && size < 2);
            break;
        case 30: /* VPMIN/VPMAX (float) */
            pairwise = u;
            break;
        default:
            pairwise = 0;
            break;
        }
        for (pass = 0; pass < (q ? 4 : 2); pass++) {

        if (pairwise) {
            /* Pairwise.  */
            if (q)
                n = (pass & 1) * 2;
            else
                n = 0;
            if (pass < q + 1) {
                gen_op_neon_getreg_T0(neon_reg_offset(rn, n));
                gen_op_neon_getreg_T1(neon_reg_offset(rn, n + 1));
            } else {
                gen_op_neon_getreg_T0(neon_reg_offset(rm, n));
                gen_op_neon_getreg_T1(neon_reg_offset(rm, n + 1));
            }
        } else {
            /* Elementwise.  */
            gen_op_neon_getreg_T0(neon_reg_offset(rn, pass));
            gen_op_neon_getreg_T1(neon_reg_offset(rm, pass));
        }
        switch (op) {
        case 0: /* VHADD */
            do { switch ((size << 1) | u) { case 0: gen_op_neon_hadd_s8(); break; case 1: gen_op_neon_hadd_u8(); break; case 2: gen_op_neon_hadd_s16(); break; case 3: gen_op_neon_hadd_u16(); break; case 4: gen_op_neon_hadd_s32(); break; case 5: gen_op_neon_hadd_u32(); break; default: return 1; }} while (0);
            break;
        case 1: /* VQADD */
            switch (size << 1| u) {
            case 0: gen_op_neon_qadd_s8(); break;
            case 1: gen_op_neon_qadd_u8(); break;
            case 2: gen_op_neon_qadd_s16(); break;
            case 3: gen_op_neon_qadd_u16(); break;
            case 4: gen_op_addl_T0_T1_saturate(); break;
            case 5: gen_op_addl_T0_T1_usaturate(); break;
            default: abort();
            }
            break;
        case 2: /* VRHADD */
            do { switch ((size << 1) | u) { case 0: gen_op_neon_rhadd_s8(); break; case 1: gen_op_neon_rhadd_u8(); break; case 2: gen_op_neon_rhadd_s16(); break; case 3: gen_op_neon_rhadd_u16(); break; case 4: gen_op_neon_rhadd_s32(); break; case 5: gen_op_neon_rhadd_u32(); break; default: return 1; }} while (0);
            break;
        case 3: /* Logic ops.  */
            switch ((u << 2) | size) {
            case 0: /* VAND */
                gen_op_andl_T0_T1();
                break;
            case 1: /* BIC */
                gen_op_bicl_T0_T1();
                break;
            case 2: /* VORR */
                gen_op_orl_T0_T1();
                break;
            case 3: /* VORN */
                gen_op_notl_T1();
                gen_op_orl_T0_T1();
                break;
            case 4: /* VEOR */
                gen_op_xorl_T0_T1();
                break;
            case 5: /* VBSL */
                gen_op_neon_getreg_T2(neon_reg_offset(rd, pass));
                gen_op_neon_bsl();
                break;
            case 6: /* VBIT */
                gen_op_neon_getreg_T2(neon_reg_offset(rd, pass));
                gen_op_neon_bit();
                break;
            case 7: /* VBIF */
                gen_op_neon_getreg_T2(neon_reg_offset(rd, pass));
                gen_op_neon_bif();
                break;
            }
            break;
        case 4: /* VHSUB */
            do { switch ((size << 1) | u) { case 0: gen_op_neon_hsub_s8(); break; case 1: gen_op_neon_hsub_u8(); break; case 2: gen_op_neon_hsub_s16(); break; case 3: gen_op_neon_hsub_u16(); break; case 4: gen_op_neon_hsub_s32(); break; case 5: gen_op_neon_hsub_u32(); break; default: return 1; }} while (0);
            break;
        case 5: /* VQSUB */
            switch ((size << 1) | u) {
            case 0: gen_op_neon_qsub_s8(); break;
            case 1: gen_op_neon_qsub_u8(); break;
            case 2: gen_op_neon_qsub_s16(); break;
            case 3: gen_op_neon_qsub_u16(); break;
            case 4: gen_op_subl_T0_T1_saturate(); break;
            case 5: gen_op_subl_T0_T1_usaturate(); break;
            default: abort();
            }
            break;
        case 6: /* VCGT */
            do { switch ((size << 1) | u) { case 0: gen_op_neon_cgt_s8(); break; case 1: gen_op_neon_cgt_u8(); break; case 2: gen_op_neon_cgt_s16(); break; case 3: gen_op_neon_cgt_u16(); break; case 4: gen_op_neon_cgt_s32(); break; case 5: gen_op_neon_cgt_u32(); break; default: return 1; }} while (0);
            break;
        case 7: /* VCGE */
            do { switch ((size << 1) | u) { case 0: gen_op_neon_cge_s8(); break; case 1: gen_op_neon_cge_u8(); break; case 2: gen_op_neon_cge_s16(); break; case 3: gen_op_neon_cge_u16(); break; case 4: gen_op_neon_cge_s32(); break; case 5: gen_op_neon_cge_u32(); break; default: return 1; }} while (0);
            break;
        case 8: /* VSHL */
            switch ((size << 1) | u) {
            case 0: gen_op_neon_shl_s8(); break;
            case 1: gen_op_neon_shl_u8(); break;
            case 2: gen_op_neon_shl_s16(); break;
            case 3: gen_op_neon_shl_u16(); break;
            case 4: gen_op_neon_shl_s32(); break;
            case 5: gen_op_neon_shl_u32(); break;






            case 6: case 7: cpu_abort(env, "VSHL.64 not implemented");

            }
            break;
        case 9: /* VQSHL */
            switch ((size << 1) | u) {
            case 0: gen_op_neon_qshl_s8(); break;
            case 1: gen_op_neon_qshl_u8(); break;
            case 2: gen_op_neon_qshl_s16(); break;
            case 3: gen_op_neon_qshl_u16(); break;
            case 4: gen_op_neon_qshl_s32(); break;
            case 5: gen_op_neon_qshl_u32(); break;






            case 6: case 7: cpu_abort(env, "VQSHL.64 not implemented");

            }
            break;
        case 10: /* VRSHL */
            switch ((size << 1) | u) {
            case 0: gen_op_neon_rshl_s8(); break;
            case 1: gen_op_neon_rshl_u8(); break;
            case 2: gen_op_neon_rshl_s16(); break;
            case 3: gen_op_neon_rshl_u16(); break;
            case 4: gen_op_neon_rshl_s32(); break;
            case 5: gen_op_neon_rshl_u32(); break;






            case 6: case 7: cpu_abort(env, "VRSHL.64 not implemented");

            }
            break;
        case 11: /* VQRSHL */
            switch ((size << 1) | u) {
            case 0: gen_op_neon_qrshl_s8(); break;
            case 1: gen_op_neon_qrshl_u8(); break;
            case 2: gen_op_neon_qrshl_s16(); break;
            case 3: gen_op_neon_qrshl_u16(); break;
            case 4: gen_op_neon_qrshl_s32(); break;
            case 5: gen_op_neon_qrshl_u32(); break;






            case 6: case 7: cpu_abort(env, "VQRSHL.64 not implemented");

            }
            break;
        case 12: /* VMAX */
            do { switch ((size << 1) | u) { case 0: gen_op_neon_max_s8(); break; case 1: gen_op_neon_max_u8(); break; case 2: gen_op_neon_max_s16(); break; case 3: gen_op_neon_max_u16(); break; case 4: gen_op_neon_max_s32(); break; case 5: gen_op_neon_max_u32(); break; default: return 1; }} while (0);
            break;
        case 13: /* VMIN */
            do { switch ((size << 1) | u) { case 0: gen_op_neon_min_s8(); break; case 1: gen_op_neon_min_u8(); break; case 2: gen_op_neon_min_s16(); break; case 3: gen_op_neon_min_u16(); break; case 4: gen_op_neon_min_s32(); break; case 5: gen_op_neon_min_u32(); break; default: return 1; }} while (0);
            break;
        case 14: /* VABD */
            do { switch ((size << 1) | u) { case 0: gen_op_neon_abd_s8(); break; case 1: gen_op_neon_abd_u8(); break; case 2: gen_op_neon_abd_s16(); break; case 3: gen_op_neon_abd_u16(); break; case 4: gen_op_neon_abd_s32(); break; case 5: gen_op_neon_abd_u32(); break; default: return 1; }} while (0);
            break;
        case 15: /* VABA */
            do { switch ((size << 1) | u) { case 0: gen_op_neon_abd_s8(); break; case 1: gen_op_neon_abd_u8(); break; case 2: gen_op_neon_abd_s16(); break; case 3: gen_op_neon_abd_u16(); break; case 4: gen_op_neon_abd_s32(); break; case 5: gen_op_neon_abd_u32(); break; default: return 1; }} while (0);
            gen_op_neon_getreg_T1(neon_reg_offset(rd, pass));
            gen_neon_add(size);
            break;
        case 16:
            if (!u) { /* VADD */
                if (gen_neon_add(size))
                    return 1;
            } else { /* VSUB */
                switch (size) {
                case 0: gen_op_neon_sub_u8(); break;
                case 1: gen_op_neon_sub_u16(); break;
                case 2: gen_op_subl_T0_T1(); break;
                default: return 1;
                }
            }
            break;
        case 17:
            if (!u) { /* VTST */
                switch (size) {
                case 0: gen_op_neon_tst_u8(); break;
                case 1: gen_op_neon_tst_u16(); break;
                case 2: gen_op_neon_tst_u32(); break;
                default: return 1;
                }
            } else { /* VCEQ */
                switch (size) {
                case 0: gen_op_neon_ceq_u8(); break;
                case 1: gen_op_neon_ceq_u16(); break;
                case 2: gen_op_neon_ceq_u32(); break;
                default: return 1;
                }
            }
            break;
        case 18: /* Multiply.  */
            switch (size) {
            case 0: gen_op_neon_mul_u8(); break;
            case 1: gen_op_neon_mul_u16(); break;
            case 2: gen_op_mul_T0_T1(); break;
            default: return 1;
            }
            gen_op_neon_getreg_T1(neon_reg_offset(rd, pass));
            if (u) { /* VMLS */
                switch (size) {
                case 0: gen_op_neon_rsb_u8(); break;
                case 1: gen_op_neon_rsb_u16(); break;
                case 2: gen_op_rsbl_T0_T1(); break;
                default: return 1;
                }
            } else { /* VMLA */
                gen_neon_add(size);
            }
            break;
        case 19: /* VMUL */
            if (u) { /* polynomial */
                gen_op_neon_mul_p8();
            } else { /* Integer */
                switch (size) {
                case 0: gen_op_neon_mul_u8(); break;
                case 1: gen_op_neon_mul_u16(); break;
                case 2: gen_op_mul_T0_T1(); break;
                default: return 1;
                }
            }
            break;
        case 20: /* VPMAX */
            do { switch ((size << 1) | u) { case 0: gen_op_neon_pmax_s8(); break; case 1: gen_op_neon_pmax_u8(); break; case 2: gen_op_neon_pmax_s16(); break; case 3: gen_op_neon_pmax_u16(); break; case 4: gen_op_neon_max_s32(); break; case 5: gen_op_neon_max_u32(); break; default: return 1; }} while (0);
            break;
        case 21: /* VPMIN */
            do { switch ((size << 1) | u) { case 0: gen_op_neon_pmin_s8(); break; case 1: gen_op_neon_pmin_u8(); break; case 2: gen_op_neon_pmin_s16(); break; case 3: gen_op_neon_pmin_u16(); break; case 4: gen_op_neon_min_s32(); break; case 5: gen_op_neon_min_u32(); break; default: return 1; }} while (0);
            break;
        case 22: /* Hultiply high.  */
            if (!u) { /* VQDMULH */
                switch (size) {
                case 1: gen_op_neon_qdmulh_s16(); break;
                case 2: gen_op_neon_qdmulh_s32(); break;
                default: return 1;
                }
            } else { /* VQRDHMUL */
                switch (size) {
                case 1: gen_op_neon_qrdmulh_s16(); break;
                case 2: gen_op_neon_qrdmulh_s32(); break;
                default: return 1;
                }
            }
            break;
        case 23: /* VPADD */
            if (u)
                return 1;
            switch (size) {
            case 0: gen_op_neon_padd_u8(); break;
            case 1: gen_op_neon_padd_u16(); break;
            case 2: gen_op_addl_T0_T1(); break;
            default: return 1;
            }
            break;
        case 26: /* Floating point arithnetic.  */
            switch ((u << 2) | size) {
            case 0: /* VADD */
                gen_op_neon_add_f32();
                break;
            case 2: /* VSUB */
                gen_op_neon_sub_f32();
                break;
            case 4: /* VPADD */
                gen_op_neon_add_f32();
                break;
            case 6: /* VABD */
                gen_op_neon_abd_f32();
                break;
            default:
                return 1;
            }
            break;
        case 27: /* Float multiply.  */
            gen_op_neon_mul_f32();
            if (!u) {
                gen_op_neon_getreg_T1(neon_reg_offset(rd, pass));
                if (size == 0) {
                    gen_op_neon_add_f32();
                } else {
                    gen_op_neon_rsb_f32();
                }
            }
            break;
        case 28: /* Float compare.  */
            if (!u) {
                gen_op_neon_ceq_f32();
            } else {
                if (size == 0)
                    gen_op_neon_cge_f32();
                else
                    gen_op_neon_cgt_f32();
            }
            break;
        case 29: /* Float compare absolute.  */
            if (!u)
                return 1;
            if (size == 0)
                gen_op_neon_acge_f32();
            else
                gen_op_neon_acgt_f32();
            break;
        case 30: /* Float min/max.  */
            if (size == 0)
                gen_op_neon_max_f32();
            else
                gen_op_neon_min_f32();
            break;
        case 31:
            if (size == 0)
                gen_op_neon_recps_f32();
            else
                gen_op_neon_rsqrts_f32();
            break;
        default:
            abort();
        }
        /* Save the result.  For elementwise operations we can put it
           straight into the destination register.  For pairwise operations
           we have to be careful to avoid clobbering the source operands.  */
        if (pairwise && rd == rm) {
            gen_neon_movl_scratch_T0(pass);
        } else {
            gen_op_neon_setreg_T0(neon_reg_offset(rd, pass));
        }

        } /* for pass */
        if (pairwise && rd == rm) {
            for (pass = 0; pass < (q ? 4 : 2); pass++) {
                gen_neon_movl_T0_scratch(pass);
                gen_op_neon_setreg_T0(neon_reg_offset(rd, pass));
            }
        }
    } else if (insn & (1 << 4)) {
        if ((insn & 0x00380080) != 0) {
            /* Two registers and shift.  */
            op = (insn >> 8) & 0xf;
            if (insn & (1 << 7)) {
                /* 64-bit shift.   */
                size = 3;
            } else {
                size = 2;
                while ((insn & (1 << (size + 19))) == 0)
                    size--;
            }
            shift = (insn >> 16) & ((1 << (3 + size)) - 1);
            /* To avoid excessive dumplication of ops we implement shift
               by immediate using the variable shift operations.  */
            if (op < 8) {
                /* Shift by immediate:
                   VSHR, VSRA, VRSHR, VRSRA, VSRI, VSHL, VQSHL, VQSHLU.  */
                /* Right shifts are encoded as N - shift, where N is the
                   element size in bits.  */
                if (op <= 4)
                    shift = shift - (1 << (size + 3));
                else
                    shift++;
                if (size == 3) {
                    count = q + 1;
                } else {
                    count = q ? 4: 2;
                }
                switch (size) {
                case 0:
                    imm = /* */ shift;
                    imm |= imm << 8;
                    imm |= imm << 16;
                    break;
                case 1:
                    imm = /* */ shift;
                    imm |= imm << 16;
                    break;
                case 2:
                case 3:
                    imm = shift;
                    break;
                default:
                    abort();
                }

                for (pass = 0; pass < count; pass++) {
                    if (size < 3) {
                        /* Operands in T0 and T1.  */
                        gen_op_movl_T1_im(imm);
                        gen_op_neon_getreg_T0(neon_reg_offset(rm, pass));
                    } else {
                        /* Operands in {T0, T1} and env.vfp.scratch.  */
                        gen_op_movl_T0_im(imm);
                        gen_neon_movl_scratch_T0(0);
                        gen_op_movl_T0_im(imm >>> 31);
                        gen_neon_movl_scratch_T0(1);
                        gen_op_neon_getreg_T0(neon_reg_offset(rm, pass * 2));
                        gen_op_neon_getreg_T1(neon_reg_offset(rm, pass * 2 + 1));
                    }

                    if (gen_neon_shift_im[op][u][size] == (0))
                        return 1;
                    gen_neon_shift_im[op][u][size]();

                    if (op == 1 || op == 3) {
                        /* Accumulate.  */
                        if (size == 3) {
                            gen_neon_movl_scratch_T0(0);
                            gen_neon_movl_scratch_T1(1);
                            gen_op_neon_getreg_T0(neon_reg_offset(rd, pass * 2));
                            gen_op_neon_getreg_T1(neon_reg_offset(rd, pass * 2 + 1));
                            gen_op_neon_addl_u64();
                        } else {
                            gen_op_neon_getreg_T1(neon_reg_offset(rd, pass));
                            gen_neon_add(size);
                        }
                    } else if (op == 4 || (op == 5 && u)) {
                        /* Insert */
                        if (size == 3) {
                            cpu_abort(env, "VS[LR]I.64 not implemented");
                        }
                        switch (size) {
                        case 0:
                            if (op == 4)
                                imm = 0xff >> -shift;
                            else
                                imm = (0xff << shift);
                            imm |= imm << 8;
                            imm |= imm << 16;
                            break;
                        case 1:
                            if (op == 4)
                                imm = 0xffff >> -shift;
                            else
                                imm = (0xffff << shift);
                            imm |= imm << 16;
                            break;
                        case 2:
                            if (op == 4)
                                imm = 0xffffffff /* u */ >> -shift;
                            else
                                imm = 0xffffffff /* u */ << shift;
                            break;
                        default:
                            abort();
                        }
                        gen_op_neon_getreg_T1(neon_reg_offset(rd, pass));
                        gen_op_movl_T2_im(imm);
                        gen_op_neon_bsl();
                    }
                    if (size == 3) {
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass * 2));
                        gen_op_neon_setreg_T1(neon_reg_offset(rd, pass * 2 + 1));
                    } else {
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass));
                    }
                } /* for pass */
            } else if (op < 10) {
                /* Shift by immedaiate and narrow:
                   VSHRN, VRSHRN, VQSHRN, VQRSHRN.  */
                shift = shift - (1 << (size + 3));
                size++;
                if (size == 3) {
                    count = q + 1;
                } else {
                    count = q ? 4: 2;
                }
                switch (size) {
                case 1:
                    imm = /* */ shift;
                    imm |= imm << 16;
                    break;
                case 2:
                case 3:
                    imm = shift;
                    break;
                default:
                    abort();
                }

                /* Processing MSB first means we need to do less shuffling at
                   the end.  */
                for (pass = count - 1; pass >= 0; pass--) {
                    /* Avoid clobbering the second operand before it has been
                       written.  */
                    n = pass;
                    if (rd == rm)
                        n ^= (count - 1);
                    else
                        n = pass;

                    if (size < 3) {
                        /* Operands in T0 and T1.  */
                        gen_op_movl_T1_im(imm);
                        gen_op_neon_getreg_T0(neon_reg_offset(rm, n));
                    } else {
                        /* Operands in {T0, T1} and env.vfp.scratch.  */
                        gen_op_movl_T0_im(imm);
                        gen_neon_movl_scratch_T0(0);
                        gen_op_movl_T0_im(imm >> 31);
                        gen_neon_movl_scratch_T0(1);
                        gen_op_neon_getreg_T0(neon_reg_offset(rm, n * 2));
                        gen_op_neon_getreg_T0(neon_reg_offset(rm, n * 2 + 1));
                    }

                    gen_neon_shift_im_narrow[q][u][size - 1]();

                    if (size < 3 && (pass & 1) == 0) {
                        gen_neon_movl_scratch_T0(0);
                    } else {
                        var /* uint32_t */ offset;

                        if (size < 3)
                            gen_neon_movl_T1_scratch(0);

                        if (op == 8 && !u) {
                            gen_neon_narrow[size - 1]();
                        } else {
                            if (op == 8)
                                gen_neon_narrow_sats[size - 2]();
                            else
                                gen_neon_narrow_satu[size - 1]();
                        }
                        if (size == 3)
                            offset = neon_reg_offset(rd, n);
                        else
                            offset = neon_reg_offset(rd, n >> 1);
                        gen_op_neon_setreg_T0(offset);
                    }
                } /* for pass */
            } else if (op == 10) {
                /* VSHLL */
                if (q)
                    return 1;
                for (pass = 0; pass < 2; pass++) {
                    /* Avoid clobbering the input operand.  */
                    if (rd == rm)
                        n = 1 - pass;
                    else
                        n = pass;

                    gen_op_neon_getreg_T0(neon_reg_offset(rm, n));
                    do { switch ((size << 1) | u) { case 0: gen_op_neon_widen_s8(); break; case 1: gen_op_neon_widen_u8(); break; case 2: gen_op_neon_widen_s16(); break; case 3: gen_op_neon_widen_u16(); break; case 4: gen_op_neon_widen_s32(); break; case 5: gen_op_neon_widen_u32(); break; default: return 1; }} while (0);
                    if (shift != 0) {
                        /* The shift is less than the width of the source
                           type, so in some cases we can just
                           shift the whole register.  */
                        if (size == 1 || (size == 0 && u)) {
                            gen_op_shll_T0_im(shift);
                            gen_op_shll_T1_im(shift);
                        } else {
                            switch (size) {
                            case 0: gen_op_neon_shll_u16(shift); break;
                            case 2: gen_op_neon_shll_u64(shift); break;
                            default: abort();
                            }
                        }
                    }
                    gen_op_neon_setreg_T0(neon_reg_offset(rd, n * 2));
                    gen_op_neon_setreg_T1(neon_reg_offset(rd, n * 2 + 1));
                }
            } else if (op == 15 || op == 16) {
                /* VCVT fixed-point.  */
                for (pass = 0; pass < (q ? 4 : 2); pass++) {
                    gen_op_vfp_getreg_F0s(neon_reg_offset(rm, pass));
                    if (op & 1) {
                        if (u)
                            gen_op_vfp_ultos(shift);
                        else
                            gen_op_vfp_sltos(shift);
                    } else {
                        if (u)
                            gen_op_vfp_touls(shift);
                        else
                            gen_op_vfp_tosls(shift);
                    }
                    gen_op_vfp_setreg_F0s(neon_reg_offset(rd, pass));
                }
            } else {
                return 1;
            }
        } else { /* (insn & 0x00380080) == 0 */
            var invert;

            op = (insn >> 8) & 0xf;
            /* One register and immediate.  */
            imm = (u << 7) | ((insn >> 12) & 0x70) | (insn & 0xf);
            invert = (insn & (1 << 5)) != 0;
            switch (op) {
            case 0: case 1:
                /* no-op */
                break;
            case 2: case 3:
                imm <<= 8;
                break;
            case 4: case 5:
                imm <<= 16;
                break;
            case 6: case 7:
                imm <<= 24;
                break;
            case 8: case 9:
                imm |= imm << 16;
                break;
            case 10: case 11:
                imm = (imm << 8) | (imm << 24);
                break;
            case 12:
                imm = (imm < 8) | 0xff;
                break;
            case 13:
                imm = (imm << 16) | 0xffff;
                break;
            case 14:
                imm |= (imm << 8) | (imm << 16) | (imm << 24);
                if (invert)
                    imm = ~imm;
                break;
            case 15:
                imm = ((imm & 0x80) << 24) | ((imm & 0x3f) << 19)
                      | ((imm & 0x40) ? (0x1f << 25) : (1 << 30));
                break;
            }
            if (invert)
                imm = ~imm;

            if (op != 14 || !invert)
                gen_op_movl_T1_im(imm);

            for (pass = 0; pass < (q ? 4 : 2); pass++) {
                if (op & 1 && op < 12) {
                    gen_op_neon_getreg_T0(neon_reg_offset(rd, pass));
                    if (invert) {
                        /* The immediate value has already been inverted, so
                           BIC becomes AND.  */
                        gen_op_andl_T0_T1();
                    } else {
                        gen_op_orl_T0_T1();
                    }
                    gen_op_neon_setreg_T0(neon_reg_offset(rd, pass));
                } else {
                    if (op == 14 && invert) {
                        var /* uint32_t */ tmp;
                        tmp = 0;
                        for (n = 0; n < 4; n++) {
                            if (imm & (1 << (n + (pass & 1) * 4)))
                                tmp |= 0xff << (n * 8);
                        }
                        gen_op_movl_T1_im(tmp);
                    }
                    /* VMOV, VMVN.  */
                    gen_op_neon_setreg_T1(neon_reg_offset(rd, pass));
                }
            }
        }
    } else { /* (insn & 0x00800010 == 0x00800010) */
        if (size != 3) {
            op = (insn >> 8) & 0xf;
            if ((insn & (1 << 6)) == 0) {
                /* Three registers of different lengths.  */
                var src1_wide;
                var src2_wide;
                var prewiden;
                /* prewiden, src1_wide, src2_wide */
                //static const int neon_3reg_wide[16][3] = {
                //    {1, 0, 0}, /* VADDL */
                //    {1, 1, 0}, /* VADDW */
                //    {1, 0, 0}, /* VSUBL */
                //   {1, 1, 0}, /* VSUBW */
                //   {0, 1, 1}, /* VADDHN */
                //    {0, 0, 0}, /* VABAL */
                //    {0, 1, 1}, /* VSUBHN */
                //    {0, 0, 0}, /* VABDL */
                //    {0, 0, 0}, /* VMLAL */
                //    {0, 0, 0}, /* VQDMLAL */
                //    {0, 0, 0}, /* VMLSL */
                //    {0, 0, 0}, /* VQDMLSL */
                //    {0, 0, 0}, /* Integer VMULL */
                //    {0, 0, 0}, /* VQDMULL */
                //    {0, 0, 0} /* Polynomial VMULL */
                //};
                
                prewiden = neon_3reg_wide[op][0];
                src1_wide = neon_3reg_wide[op][1];
                src2_wide = neon_3reg_wide[op][2];

                /* Avoid overlapping operands.  Wide source operands are
                   always aligned so will never overlap with wide
                   destinations in problematic ways.  */
                if (rd == rm) {
                    gen_op_neon_getreg_T2(neon_reg_offset(rm, 1));
                } else if (rd == rn) {
                    gen_op_neon_getreg_T2(neon_reg_offset(rn, 1));
                }
                for (pass = 0; pass < 2; pass++) {
                    /* Load the second operand into env.vfp.scratch.
                       Also widen narrow operands.  */
                    if (pass == 1 && rd == rm) {
                        if (prewiden) {
                            gen_op_movl_T0_T2();
                        } else {
                            gen_op_movl_T1_T2();
                        }
                    } else {
                        if (src2_wide) {
                            gen_op_neon_getreg_T0(neon_reg_offset(rm, pass * 2));
                            gen_op_neon_getreg_T1(neon_reg_offset(rm, pass * 2 + 1));
                        } else {
                            if (prewiden) {
                                gen_op_neon_getreg_T0(neon_reg_offset(rm, pass));
                            } else {
                                gen_op_neon_getreg_T1(neon_reg_offset(rm, pass));
                            }
                        }
                    }
                    if (prewiden && !src2_wide) {
                        do { switch ((size << 1) | u) { case 0: gen_op_neon_widen_s8(); break; case 1: gen_op_neon_widen_u8(); break; case 2: gen_op_neon_widen_s16(); break; case 3: gen_op_neon_widen_u16(); break; case 4: gen_op_neon_widen_s32(); break; case 5: gen_op_neon_widen_u32(); break; default: return 1; }} while (0);
                    }
                    if (prewiden || src2_wide) {
                        gen_neon_movl_scratch_T0(0);
                        gen_neon_movl_scratch_T1(1);
                    }

                    /* Load the first operand.  */
                    if (pass == 1 && rd == rn) {
                        gen_op_movl_T0_T2();
                    } else {
                        if (src1_wide) {
                            gen_op_neon_getreg_T0(neon_reg_offset(rn, pass * 2));
                            gen_op_neon_getreg_T1(neon_reg_offset(rn, pass * 2 + 1));
                        } else {
                            gen_op_neon_getreg_T0(neon_reg_offset(rn, pass));
                        }
                    }
                    if (prewiden && !src1_wide) {
                        do { switch ((size << 1) | u) { case 0: gen_op_neon_widen_s8(); break; case 1: gen_op_neon_widen_u8(); break; case 2: gen_op_neon_widen_s16(); break; case 3: gen_op_neon_widen_u16(); break; case 4: gen_op_neon_widen_s32(); break; case 5: gen_op_neon_widen_u32(); break; default: return 1; }} while (0);
                    }
                    switch (op) {
                    case 0: case 1: case 4: /* VADDL, VADDW, VADDHN, VRADDHN */
                        switch (size) {
                        case 0: gen_op_neon_addl_u16(); break;
                        case 1: gen_op_neon_addl_u32(); break;
                        case 2: gen_op_neon_addl_u64(); break;
                        default: abort();
                        }
                        break;
                    case 2: case 3: case 6: /* VSUBL, VSUBW, VSUBHL, VRSUBHL */
                        switch (size) {
                        case 0: gen_op_neon_subl_u16(); break;
                        case 1: gen_op_neon_subl_u32(); break;
                        case 2: gen_op_neon_subl_u64(); break;
                        default: abort();
                        }
                        break;
                    case 5: case 7: /* VABAL, VABDL */
                        switch ((size << 1) | u) {
                        case 0: gen_op_neon_abdl_s16(); break;
                        case 1: gen_op_neon_abdl_u16(); break;
                        case 2: gen_op_neon_abdl_s32(); break;
                        case 3: gen_op_neon_abdl_u32(); break;
                        case 4: gen_op_neon_abdl_s64(); break;
                        case 5: gen_op_neon_abdl_u64(); break;
                        default: abort();
                        }
                        break;
                    case 8: case 9: case 10: case 11: case 12: case 13:
                        /* VMLAL, VQDMLAL, VMLSL, VQDMLSL, VMULL, VQDMULL */
                        switch ((size << 1) | u) {
                        case 0: gen_op_neon_mull_s8(); break;
                        case 1: gen_op_neon_mull_u8(); break;
                        case 2: gen_op_neon_mull_s16(); break;
                        case 3: gen_op_neon_mull_u16(); break;
                        case 4: gen_op_imull_T0_T1(); break;
                        case 5: gen_op_mull_T0_T1(); break;
                        default: abort();
                        }
                        break;
                    case 14: /* Polynomial VMULL */
                        cpu_abort(env, "Polynomial VMULL not implemented");

                    default: /* 15 is RESERVED.  */
                        return 1;
                    }
                    if (op == 5 || op == 13 || (op >= 8 && op <= 11)) {
                        /* Accumulate.  */
                        if (op == 10 || op == 11) {
                            switch (size) {
                            case 0: gen_op_neon_negl_u16(); break;
                            case 1: gen_op_neon_negl_u32(); break;
                            case 2: gen_op_neon_negl_u64(); break;
                            default: abort();
                            }
                        }

                        gen_neon_movl_scratch_T0(0);
                        gen_neon_movl_scratch_T1(1);

                        if (op != 13) {
                            gen_op_neon_getreg_T0(neon_reg_offset(rd, pass * 2));
                            gen_op_neon_getreg_T1(neon_reg_offset(rd, pass * 2 + 1));
                        }

                        switch (op) {
                        case 5: case 8: case 10: /* VABAL, VMLAL, VMLSL */
                            switch (size) {
                            case 0: gen_op_neon_addl_u16(); break;
                            case 1: gen_op_neon_addl_u32(); break;
                            case 2: gen_op_neon_addl_u64(); break;
                            default: abort();
                            }
                            break;
                        case 9: case 11: /* VQDMLAL, VQDMLSL */
                            switch (size) {
                            case 1: gen_op_neon_addl_saturate_s32(); break;
                            case 2: gen_op_neon_addl_saturate_s64(); break;
                            default: abort();
                            }
                            /* Fall through.  */
                        case 13: /* VQDMULL */
                            switch (size) {
                            case 1: gen_op_neon_addl_saturate_s32(); break;
                            case 2: gen_op_neon_addl_saturate_s64(); break;
                            default: abort();
                            }
                            break;
                        default:
                            abort();
                        }
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass * 2));
                        gen_op_neon_setreg_T1(neon_reg_offset(rd, pass * 2 + 1));
                    } else if (op == 4 || op == 6) {
                        /* Narrowing operation.  */
                        if (u) {
                            switch (size) {
                            case 0: gen_op_neon_narrow_high_u8(); break;
                            case 1: gen_op_neon_narrow_high_u16(); break;
                            case 2: gen_op_movl_T0_T1(); break;
                            default: abort();
                            }
                        } else {
                            switch (size) {
                            case 0: gen_op_neon_narrow_high_round_u8(); break;
                            case 1: gen_op_neon_narrow_high_round_u16(); break;
                            case 2: gen_op_neon_narrow_high_round_u32(); break;
                            default: abort();
                            }
                        }
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass));
                    } else {
                        /* Write back the result.  */
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass * 2));
                        gen_op_neon_setreg_T1(neon_reg_offset(rd, pass * 2 + 1));
                    }
                }
            } else {
                /* Two registers and a scalar.  */
                switch (op) {
                case 0: /* Integer VMLA scalar */
                case 1: /* Float VMLA scalar */
                case 4: /* Integer VMLS scalar */
                case 5: /* Floating point VMLS scalar */
                case 8: /* Integer VMUL scalar */
                case 9: /* Floating point VMUL scalar */
                case 12: /* VQDMULH scalar */
                case 13: /* VQRDMULH scalar */
                    gen_neon_get_scalar(size, rm);
                    gen_op_movl_T2_T0();
                    for (pass = 0; pass < (u ? 4 : 2); pass++) {
                        if (pass != 0)
                            gen_op_movl_T0_T2();
                        gen_op_neon_getreg_T1(neon_reg_offset(rn, pass));
                        if (op == 12) {
                            if (size == 1) {
                                gen_op_neon_qdmulh_s16();
                            } else {
                                gen_op_neon_qdmulh_s32();
                            }
                        } else if (op == 13) {
                            if (size == 1) {
                                gen_op_neon_qrdmulh_s16();
                            } else {
                                gen_op_neon_qrdmulh_s32();
                            }
                        } else if (op & 1) {
                            gen_op_neon_mul_f32();
                        } else {
                            switch (size) {
                            case 0: gen_op_neon_mul_u8(); break;
                            case 1: gen_op_neon_mul_u16(); break;
                            case 2: gen_op_mul_T0_T1(); break;
                            default: return 1;
                            }
                        }
                        if (op < 8) {
                            /* Accumulate.  */
                            gen_op_neon_getreg_T1(neon_reg_offset(rd, pass));
                            switch (op) {
                            case 0:
                                gen_neon_add(size);
                                break;
                            case 1:
                                gen_op_neon_add_f32();
                                break;
                            case 4:
                                switch (size) {
                                case 0: gen_op_neon_rsb_u8(); break;
                                case 1: gen_op_neon_rsb_u16(); break;
                                case 2: gen_op_rsbl_T0_T1(); break;
                                default: return 1;
                                }
                                break;
                            case 5:
                                gen_op_neon_rsb_f32();
                                break;
                            default:
                                abort();
                            }
                        }
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass));
                    }
                    break;
                case 2: /* VMLAL sclar */
                case 3: /* VQDMLAL scalar */
                case 6: /* VMLSL scalar */
                case 7: /* VQDMLSL scalar */
                case 10: /* VMULL scalar */
                case 11: /* VQDMULL scalar */
                    if (rd == rn) {
                        /* Save overlapping operands before they are
                           clobbered.  */
                        gen_op_neon_getreg_T0(neon_reg_offset(rn, 1));
                        gen_neon_movl_scratch_T0(2);
                    }
                    gen_neon_get_scalar(size, rm);
                    gen_op_movl_T2_T0();
                    for (pass = 0; pass < 2; pass++) {
                        if (pass != 0) {
                            gen_op_movl_T0_T2();
                        }
                        if (pass != 0 && rd == rn) {
                            gen_neon_movl_T1_scratch(2);
                        } else {
                            gen_op_neon_getreg_T1(neon_reg_offset(rn, pass));
                        }
                        switch ((size << 1) | u) {
                        case 0: gen_op_neon_mull_s8(); break;
                        case 1: gen_op_neon_mull_u8(); break;
                        case 2: gen_op_neon_mull_s16(); break;
                        case 3: gen_op_neon_mull_u16(); break;
                        case 4: gen_op_imull_T0_T1(); break;
                        case 5: gen_op_mull_T0_T1(); break;
                        default: abort();
                        }
                        if (op == 6 || op == 7) {
                            switch (size) {
                            case 0: gen_op_neon_negl_u16(); break;
                            case 1: gen_op_neon_negl_u32(); break;
                            case 2: gen_op_neon_negl_u64(); break;
                            default: abort();
                            }
                        }
                        gen_neon_movl_scratch_T0(0);
                        gen_neon_movl_scratch_T1(1);
                        gen_op_neon_getreg_T0(neon_reg_offset(rd, pass * 2));
                        gen_op_neon_getreg_T1(neon_reg_offset(rd, pass * 2 + 1));
                        switch (op) {
                        case 2: case 6:
                            switch (size) {
                            case 0: gen_op_neon_addl_u16(); break;
                            case 1: gen_op_neon_addl_u32(); break;
                            case 2: gen_op_neon_addl_u64(); break;
                            default: abort();
                            }
                            break;
                        case 3: case 7:
                            switch (size) {
                            case 1:
                                gen_op_neon_addl_saturate_s32();
                                gen_op_neon_addl_saturate_s32();
                                break;
                            case 2:
                                gen_op_neon_addl_saturate_s64();
                                gen_op_neon_addl_saturate_s64();
                                break;
                            default: abort();
                            }
                            break;
                        case 10:
                            /* no-op */
                            break;
                        case 11:
                            switch (size) {
                            case 1: gen_op_neon_addl_saturate_s32(); break;
                            case 2: gen_op_neon_addl_saturate_s64(); break;
                            default: abort();
                            }
                            break;
                        default:
                            abort();
                        }
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass * 2));
                        gen_op_neon_setreg_T1(neon_reg_offset(rd, pass * 2 + 1));
                    }
                    break;
                default: /* 14 and 15 are RESERVED */
                    return 1;
                }
            }
        } else { /* size == 3 */
            if (!u) {
                /* Extract.  */
                var reg;
                imm = (insn >> 8) & 0xf;
                reg = rn;
                count = q ? 4 : 2;
                n = imm >> 2;
                gen_op_neon_getreg_T0(neon_reg_offset(reg, n));
                for (pass = 0; pass < count; pass++) {
                    n++;
                    if (n > count) {
                        reg = rm;
                        n -= count;
                    }
                    if (imm & 3) {
                        gen_op_neon_getreg_T1(neon_reg_offset(reg, n));
                        gen_op_neon_extract((insn << 3) & 0x1f);
                    }
                    /* ??? This is broken if rd and rm overlap */
                    gen_op_neon_setreg_T0(neon_reg_offset(rd, pass));
                    if (imm & 3) {
                        gen_op_movl_T0_T1();
                    } else {
                        gen_op_neon_getreg_T0(neon_reg_offset(reg, n));
                    }
                }
            } else if ((insn & (1 << 11)) == 0) {
                /* Two register misc.  */
                op = ((insn >> 12) & 0x30) | ((insn >> 7) & 0xf);
                size = (insn >> 18) & 3;
                switch (op) {
                case 0: /* VREV64 */
                    if (size == 3)
                        return 1;
                    for (pass = 0; pass < (q ? 2 : 1); pass++) {
                        gen_op_neon_getreg_T0(neon_reg_offset(rm, pass * 2));
                        gen_op_neon_getreg_T1(neon_reg_offset(rm, pass * 2 + 1));
                        switch (size) {
                        case 0: gen_op_rev_T0(); break;
                        case 1: gen_op_revh_T0(); break;
                        case 2: /* no-op */ break;
                        default: abort();
                        }
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass * 2 + 1));
                        if (size == 2) {
                            gen_op_neon_setreg_T1(neon_reg_offset(rd, pass * 2));
                        } else {
                            gen_op_movl_T0_T1();
                            switch (size) {
                            case 0: gen_op_rev_T0(); break;
                            case 1: gen_op_revh_T0(); break;
                            default: abort();
                            }
                            gen_op_neon_setreg_T0(neon_reg_offset(rd, pass * 2));
                        }
                    }
                    break;
                case 4: case 5: /* VPADDL */
                case 12: case 13: /* VPADAL */
                    if (size < 2) /// XXX: GOTO FIX
                        ; //goto elementwise;
                    if (size == 3)
                        return 1;
                    for (pass = 0; pass < (q ? 2 : 1); pass++) {
                        gen_op_neon_getreg_T0(neon_reg_offset(rm, pass * 2));
                        gen_op_neon_getreg_T1(neon_reg_offset(rm, pass * 2 + 1));
                        if (op & 1)
                            gen_op_neon_paddl_u32();
                        else
                            gen_op_neon_paddl_s32();
                        if (op >= 12) {
                            /* Accumulate.  */
                            gen_neon_movl_scratch_T0(0);
                            gen_neon_movl_scratch_T1(1);

                            gen_op_neon_getreg_T0(neon_reg_offset(rd, pass * 2));
                            gen_op_neon_getreg_T1(neon_reg_offset(rd, pass * 2 + 1));
                            gen_op_neon_addl_u64();
                        }
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass * 2));
                        gen_op_neon_setreg_T1(neon_reg_offset(rd, pass * 2 + 1));
                    }
                    break;
                case 33: /* VTRN */
                    if (size == 2) {
                        for (n = 0; n < (q ? 4 : 2); n += 2) {
                            gen_op_neon_getreg_T0(neon_reg_offset(rm, n));
                            gen_op_neon_getreg_T1(neon_reg_offset(rd, n + 1));
                            gen_op_neon_setreg_T1(neon_reg_offset(rm, n));
                            gen_op_neon_setreg_T0(neon_reg_offset(rd, n + 1));
                        }
                    } else {/// XXX: GOTO FIX
                        ; //goto elementwise;
                    }
                    break;
                case 34: /* VUZP */
                    /* Reg  Before       After
                       Rd   A3 A2 A1 A0  B2 B0 A2 A0
                       Rm   B3 B2 B1 B0  B3 B1 A3 A1
                     */
                    if (size == 3)
                        return 1;
                    gen_neon_unzip(rd, q, 0, size);
                    gen_neon_unzip(rm, q, 4, size);
                    /* XXX: fix neon 
                    if (q) {
                        static int unzip_order_q[8] =
                            {0, 2, 4, 6, 1, 3, 5, 7};
                        for (n = 0; n < 8; n++) {
                            var reg = (n < 4) ? rd : rm;
                            gen_neon_movl_T0_scratch(unzip_order_q[n]);
                            gen_op_neon_setreg_T0(neon_reg_offset(reg, n % 4));
                        }
                    } else {
                        static int unzip_order[4] =
                            {0, 4, 1, 5};
                        for (n = 0; n < 4; n++) {
                            int reg = (n < 2) ? rd : rm;
                            gen_neon_movl_T0_scratch(unzip_order[n]);
                            gen_op_neon_setreg_T0(neon_reg_offset(reg, n % 2));
                        }
                    }*/
                    break;
                case 35: /* VZIP */
                    /* Reg  Before       After
                       Rd   A3 A2 A1 A0  B1 A1 B0 A0
                       Rm   B3 B2 B1 B0  B3 A3 B2 A2
                     */
                    if (size == 3)
                        return 1;
                    count = (q ? 4 : 2);
                    for (n = 0; n < count; n++) {
                        gen_op_neon_getreg_T0(neon_reg_offset(rd, n));
                        gen_op_neon_getreg_T1(neon_reg_offset(rd, n));
                        switch (size) {
                        case 0: gen_op_neon_zip_u8(); break;
                        case 1: gen_op_neon_zip_u16(); break;
                        case 2: /* no-op */; break;
                        default: abort();
                        }
                        gen_neon_movl_scratch_T0(n * 2);
                        gen_neon_movl_scratch_T1(n * 2 + 1);
                    }
                    for (n = 0; n < count * 2; n++) {
                        var reg = (n < count) ? rd : rm;
                        gen_neon_movl_T0_scratch(n);
                        gen_op_neon_setreg_T0(neon_reg_offset(reg, n % count));
                    }
                    break;
                case 36: case 37: /* VMOVN, VQMOVUN, VQMOVN */
                    for (pass = 0; pass < 2; pass++) {
                        if (rd == rm + 1) {
                            n = 1 - pass;
                        } else {
                            n = pass;
                        }
                        gen_op_neon_getreg_T0(neon_reg_offset(rm, n * 2));
                        gen_op_neon_getreg_T1(neon_reg_offset(rm, n * 2 + 1));
                        if (op == 36 && q == 0) {
                            switch (size) {
                            case 0: gen_op_neon_narrow_u8(); break;
                            case 1: gen_op_neon_narrow_u16(); break;
                            case 2: /* no-op */ break;
                            default: return 1;
                            }
                        } else if (q) {
                            switch (size) {
                            case 0: gen_op_neon_narrow_sat_u8(); break;
                            case 1: gen_op_neon_narrow_sat_u16(); break;
                            case 2: gen_op_neon_narrow_sat_u32(); break;
                            default: return 1;
                            }
                        } else {
                            switch (size) {
                            case 0: gen_op_neon_narrow_sat_s8(); break;
                            case 1: gen_op_neon_narrow_sat_s16(); break;
                            case 2: gen_op_neon_narrow_sat_s32(); break;
                            default: return 1;
                            }
                        }
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, n));
                    }
                    break;
                case 38: /* VSHLL */
                    if (q)
                        return 1;
                    if (rm == rd) {
                        gen_op_neon_getreg_T2(neon_reg_offset(rm, 1));
                    }
                    for (pass = 0; pass < 2; pass++) {
                        if (pass == 1 && rm == rd) {
                            gen_op_movl_T0_T2();
                        } else {
                            gen_op_neon_getreg_T0(neon_reg_offset(rm, pass));
                        }
                        switch (size) {
                        case 0: gen_op_neon_widen_high_u8(); break;
                        case 1: gen_op_neon_widen_high_u16(); break;
                        case 2:
                            gen_op_movl_T1_T0();
                            gen_op_movl_T0_im(0);
                            break;
                        default: return 1;
                        }
                        gen_op_neon_setreg_T0(neon_reg_offset(rd, pass * 2));
                        gen_op_neon_setreg_T1(neon_reg_offset(rd, pass * 2 + 1));
                    }
                    break;
                default:
                elementwise:
                    for (pass = 0; pass < (q ? 4 : 2); pass++) {
                        if (op == 30 || op == 31 || op >= 58) {
                            gen_op_vfp_getreg_F0s(neon_reg_offset(rm, pass));
                        } else {
                            gen_op_neon_getreg_T0(neon_reg_offset(rm, pass));
                        }
                        switch (op) {
                        case 1: /* VREV32 */
                            switch (size) {
                            case 0: gen_op_rev_T0(); break;
                            case 1: gen_op_revh_T0(); break;
                            default: return 1;
                            }
                            break;
                        case 2: /* VREV16 */
                            if (size != 0)
                                return 1;
                            gen_op_rev16_T0();
                            break;
                        case 4: case 5: /* VPADDL */
                        case 12: case 13: /* VPADAL */
                            switch ((size << 1) | (op & 1)) {
                            case 0: gen_op_neon_paddl_s8(); break;
                            case 1: gen_op_neon_paddl_u8(); break;
                            case 2: gen_op_neon_paddl_s16(); break;
                            case 3: gen_op_neon_paddl_u16(); break;
                            default: abort();
                            }
                            if (op >= 12) {
                                /* Accumulate */
                                gen_op_neon_getreg_T1(neon_reg_offset(rd, pass));
                                switch (size) {
                                case 0: gen_op_neon_add_u16(); break;
                                case 1: gen_op_addl_T0_T1(); break;
                                default: abort();
                                }
                            }
                            break;
                        case 8: /* CLS */
                            switch (size) {
                            case 0: gen_op_neon_cls_s8(); break;
                            case 1: gen_op_neon_cls_s16(); break;
                            case 2: gen_op_neon_cls_s32(); break;
                            default: return 1;
                            }
                            break;
                        case 9: /* CLZ */
                            switch (size) {
                            case 0: gen_op_neon_clz_u8(); break;
                            case 1: gen_op_neon_clz_u16(); break;
                            case 2: gen_op_clz_T0(); break;
                            default: return 1;
                            }
                            break;
                        case 10: /* CNT */
                            if (size != 0)
                                return 1;
                            gen_op_neon_cnt_u8();
                            break;
                        case 11: /* VNOT */
                            if (size != 0)
                                return 1;
                            gen_op_notl_T0();
                            break;
                        case 14: /* VQABS */
                            switch (size) {
                            case 0: gen_op_neon_qabs_s8(); break;
                            case 1: gen_op_neon_qabs_s16(); break;
                            case 2: gen_op_neon_qabs_s32(); break;
                            default: return 1;
                            }
                            break;
                        case 15: /* VQNEG */
                            switch (size) {
                            case 0: gen_op_neon_qneg_s8(); break;
                            case 1: gen_op_neon_qneg_s16(); break;
                            case 2: gen_op_neon_qneg_s32(); break;
                            default: return 1;
                            }
                            break;
                        case 16: case 19: /* VCGT #0, VCLE #0 */
                            gen_op_movl_T1_im(0);
                            switch(size) {
                            case 0: gen_op_neon_cgt_s8(); break;
                            case 1: gen_op_neon_cgt_s16(); break;
                            case 2: gen_op_neon_cgt_s32(); break;
                            default: return 1;
                            }
                            if (op == 19)
                                gen_op_notl_T0();
                            break;
                        case 17: case 20: /* VCGE #0, VCLT #0 */
                            gen_op_movl_T1_im(0);
                            switch(size) {
                            case 0: gen_op_neon_cge_s8(); break;
                            case 1: gen_op_neon_cge_s16(); break;
                            case 2: gen_op_neon_cge_s32(); break;
                            default: return 1;
                            }
                            if (op == 20)
                                gen_op_notl_T0();
                            break;
                        case 18: /* VCEQ #0 */
                            gen_op_movl_T1_im(0);
                            switch(size) {
                            case 0: gen_op_neon_ceq_u8(); break;
                            case 1: gen_op_neon_ceq_u16(); break;
                            case 2: gen_op_neon_ceq_u32(); break;
                            default: return 1;
                            }
                            break;
                        case 22: /* VABS */
                            switch(size) {
                            case 0: gen_op_neon_abs_s8(); break;
                            case 1: gen_op_neon_abs_s16(); break;
                            case 2: gen_op_neon_abs_s32(); break;
                            default: return 1;
                            }
                            break;
                        case 23: /* VNEG */
                            gen_op_movl_T1_im(0);
                            switch(size) {
                            case 0: gen_op_neon_rsb_u8(); break;
                            case 1: gen_op_neon_rsb_u16(); break;
                            case 2: gen_op_rsbl_T0_T1(); break;
                            default: return 1;
                            }
                            break;
                        case 24: case 27: /* Float VCGT #0, Float VCLE #0 */
                            gen_op_movl_T1_im(0);
                            gen_op_neon_cgt_f32();
                            if (op == 27)
                                gen_op_notl_T0();
                            break;
                        case 25: case 28: /* Float VCGE #0, Float VCLT #0 */
                            gen_op_movl_T1_im(0);
                            gen_op_neon_cge_f32();
                            if (op == 28)
                                gen_op_notl_T0();
                            break;
                        case 26: /* Float VCEQ #0 */
                            gen_op_movl_T1_im(0);
                            gen_op_neon_ceq_f32();
                            break;
                        case 30: /* Float VABS */
                            gen_op_vfp_abss();
                            break;
                        case 31: /* Float VNEG */
                            gen_op_vfp_negs();
                            break;
                        case 32: /* VSWP */
                            gen_op_neon_getreg_T1(neon_reg_offset(rd, pass));
                            gen_op_neon_setreg_T1(neon_reg_offset(rm, pass));
                            break;
                        case 33: /* VTRN */
                            gen_op_neon_getreg_T1(neon_reg_offset(rd, pass));
                            switch (size) {
                            case 0: gen_op_neon_trn_u8(); break;
                            case 1: gen_op_neon_trn_u16(); break;
                            case 2: abort();
                            default: return 1;
                            }
                            gen_op_neon_setreg_T1(neon_reg_offset(rm, pass));
                            break;
                        case 56: /* Integer VRECPE */
                            gen_op_neon_recpe_u32();
                            break;
                        case 57: /* Integer VRSQRTE */
                            gen_op_neon_rsqrte_u32();
                            break;
                        case 58: /* Float VRECPE */
                            gen_op_neon_recpe_f32();
                            break;
                        case 59: /* Float VRSQRTE */
                            gen_op_neon_rsqrte_f32();
                            break;
                        case 60: /* VCVT.F32.S32 */
                            gen_op_vfp_tosizs();
                            break;
                        case 61: /* VCVT.F32.U32 */
                            gen_op_vfp_touizs();
                            break;
                        case 62: /* VCVT.S32.F32 */
                            gen_op_vfp_sitos();
                            break;
                        case 63: /* VCVT.U32.F32 */
                            gen_op_vfp_uitos();
                            break;
                        default:
                            /* Reserved: 21, 29, 39-56 */
                            return 1;
                        }
                        if (op == 30 || op == 31 || op >= 58) {
                            gen_op_vfp_setreg_F0s(neon_reg_offset(rm, pass));
                        } else {
                            gen_op_neon_setreg_T0(neon_reg_offset(rd, pass));
                        }
                    }
                    break;
                }
            } else if ((insn & (1 << 10)) == 0) {
                /* VTBL, VTBX.  */
                n = (insn >> 5) & 0x18;
                gen_op_neon_getreg_T1(neon_reg_offset(rm, 0));
                if (insn & (1 << 6)) {
                    gen_op_neon_getreg_T0(neon_reg_offset(rd, 0));
                } else {
                    gen_op_movl_T0_im(0);
                }
                gen_op_neon_tbl(rn, n);
                gen_op_movl_T2_T0();
                gen_op_neon_getreg_T1(neon_reg_offset(rm, 1));
                if (insn & (1 << 6)) {
                    gen_op_neon_getreg_T0(neon_reg_offset(rd, 0));
                } else {
                    gen_op_movl_T0_im(0);
                }
                gen_op_neon_tbl(rn, n);
                gen_op_neon_setreg_T2(neon_reg_offset(rd, 0));
                gen_op_neon_setreg_T0(neon_reg_offset(rd, 1));
            } else if ((insn & 0x380) == 0) {
                /* VDUP */
                if (insn & (1 << 19)) {
                    gen_op_neon_setreg_T0(neon_reg_offset(rm, 1));
                } else {
                    gen_op_neon_setreg_T0(neon_reg_offset(rm, 0));
                }
                if (insn & (1 << 16)) {
                    gen_op_neon_dup_u8(((insn >> 17) & 3) * 8);
                } else if (insn & (1 << 17)) {
                    if ((insn >> 18) & 1)
                        gen_op_neon_dup_high16();
                    else
                        gen_op_neon_dup_low16();
                }
                for (pass = 0; pass < (q ? 4 : 2); pass++) {
                    gen_op_neon_setreg_T0(neon_reg_offset(rd, pass));
                }
            } else {
                return 1;
            }
        }
    }
    return 0;
}

function disas_coproc_insn(/* CPUARMState * */ env, /* DisasContext * */ s, /* uint32_t */ insn)
{
    var cpnum;

    cpnum = (insn >> 8) & 0xf;
    if (arm_feature(env, ARM_FEATURE_XSCALE)
     && ((env.cp15.c15_cpar ^ 0x3fff) & (1 << cpnum)))
 return 1;

    switch (cpnum) {
      case 0:
      case 1:
 if (arm_feature(env, ARM_FEATURE_IWMMXT)) {
     return disas_iwmmxt_insn(env, s, insn);
 } else if (arm_feature(env, ARM_FEATURE_XSCALE)) {
     return disas_dsp_insn(env, s, insn);
 }
 return 1;
    case 10:
    case 11:
 return disas_vfp_insn (env, s, insn);
    case 15:
 return disas_cp15_insn (env, s, insn);
    default:
 /* Unknown coprocessor.  See if the board has hooked it.  */
 return disas_cp_insn (env, s, insn);
    }
}

/* Return true if this is a Thumb-2 logical op.  */
function thumb2_logic_op(/* int */ op)
{
    return (op < 8);
}

/* Generate code for a Thumb-2 data processing operation.  If CONDS is nonzero
   then set condition code flags based on the result of the operation.
   If SHIFTER_OUT is nonzero then set the carry flag for logical operations
   to the high bit of T1.
   Returns zero if the opcode is valid.  */

function gen_thumb2_data_op(/* DisasContext * */ s, /* int */ op, /* int */ conds, /* uint32_t */ shifter_out)
{
    var logic_cc;

    logic_cc = 0;
    switch (op) {
    case 0: /* and */
        gen_op_andl_T0_T1();
        logic_cc = conds;
        break;
    case 1: /* bic */
        gen_op_bicl_T0_T1();
        logic_cc = conds;
        break;
    case 2: /* orr */
        gen_op_orl_T0_T1();
        logic_cc = conds;
        break;
    case 3: /* orn */
        gen_op_notl_T1();
        gen_op_orl_T0_T1();
        logic_cc = conds;
        break;
    case 4: /* eor */
        gen_op_xorl_T0_T1();
        logic_cc = conds;
        break;
    case 8: /* add */
        if (conds)
            gen_op_addl_T0_T1_cc();
        else
            gen_op_addl_T0_T1();
        break;
    case 10: /* adc */
        if (conds)
            gen_op_adcl_T0_T1_cc();
        else
            gen_op_adcl_T0_T1();
        break;
    case 11: /* sbc */
        if (conds)
            gen_op_sbcl_T0_T1_cc();
        else
            gen_op_sbcl_T0_T1();
        break;
    case 13: /* sub */
        if (conds)
            gen_op_subl_T0_T1_cc();
        else
            gen_op_subl_T0_T1();
        break;
    case 14: /* rsb */
        if (conds)
            gen_op_rsbl_T0_T1_cc();
        else
            gen_op_rsbl_T0_T1();
        break;
    default: /* 5, 6, 7, 9, 12, 15. */
        return 1;
    }
    if (logic_cc) {
        gen_op_logic_T0_cc();
        if (shifter_out)
            gen_op_mov_CF_T1();
    }
    return 0;
}

/* Translate a 32-bit thumb instruction.  Returns nonzero if the instruction
   is not legal.  */
function disas_thumb2_insn(/* CPUARMState * */ env, /* DisasContext * */ s, /* uint16_t */ insn_hw1)
{
    var /* uint32_t */ insn, imm, shift, offset, addr;
    var /* uint32_t */ rd, rn, rm, rs;
    var op;
    var shiftop;
    var conds;
    var logic_cc;

    if (!(arm_feature(env, ARM_FEATURE_THUMB2)
          || arm_feature (env, ARM_FEATURE_M))) {
        /* Thumb-1 cores may need to tread bl and blx as a pair of
           16-bit instructions to get correct prefetch abort behavior.  */
        insn = insn_hw1;
        if ((insn & (1 << 12)) == 0) {
            /* Second half of blx.  */
            offset = ((insn & 0x7ff) << 1);
            gen_movl_T0_reg(s, 14);
            gen_op_movl_T1_im(offset);
            gen_op_addl_T0_T1();
            gen_op_movl_T1_im(0xfffffffc);
            gen_op_andl_T0_T1();

            addr = s.pc >>> 0; 
            gen_op_movl_T1_im(addr | 1);
            gen_movl_reg_T1(s, 14);
            gen_bx(s);
            return 0;
        }
        if (insn & (1 << 11)) {
            /* Second half of bl.  */
            offset = ((insn & 0x7ff) << 1) | 1;
            gen_movl_T0_reg(s, 14);
            gen_op_movl_T1_im(offset);
            gen_op_addl_T0_T1();

            addr =  s.pc;
            gen_op_movl_T1_im(addr | 1);
            gen_movl_reg_T1(s, 14);
            gen_bx(s);
            return 0;
        }
        if ((s.pc & ~~((1 << 10) - 1)) == 0) {
            /* Instruction spans a page boundary.  Implement it as two
               16-bit instructions in case the second half causes an
               prefetch abort.  */
            offset = ( insn << 21) >> 9;
            addr = s.pc + 2 + offset;
            gen_op_movl_T0_im(addr);
            gen_movl_reg_T0(s, 14);
            return 0;
        }
        /* Fall through to 32-bit decode.  */
    }

    insn = lduw_code(s.pc);
    s.pc += 2;
    insn |=  insn_hw1 << 16;

    if ((insn & 0xf800e800) != 0xf000e800) {
        if (!arm_feature(env, ARM_FEATURE_THUMB2)) return 1;
    }

    rn = (insn >> 16) & 0xf;
    rs = (insn >> 12) & 0xf;
    rd = (insn >> 8) & 0xf;
    rm = insn & 0xf;
    switch ((insn >> 25) & 0xf) {
    case 0: case 1: case 2: case 3:
        /* 16-bit instructions.  Should never happen.  */
        abort();
    case 4:
        if (insn & (1 << 22)) {
            /* Other load/store, table branch.  */
            if (insn & 0x01200000) {
                /* Load/store doubleword.  */
                if (rn == 15) {
                    gen_op_movl_T1_im(s.pc & ~3);
                } else {
                    gen_movl_T1_reg(s, rn);
                }
                offset = (insn & 0xff) * 4;
                if ((insn & (1 << 23)) == 0)
                    offset = -offset;
                if (insn & (1 << 24)) {
                    gen_op_addl_T1_im(offset);
                    offset = 0;
                }
                if (insn & (1 << 20)) {
                    /* ldrd */
                    do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                    gen_movl_reg_T0(s, rs);
                    gen_op_addl_T1_im(4);
                    do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                    gen_movl_reg_T0(s, rd);
                } else {
                    /* strd */
                    gen_movl_T0_reg(s, rs);
                    do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                    gen_op_addl_T1_im(4);
                    gen_movl_T0_reg(s, rd);
                    do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                }
                if (insn & (1 << 21)) {
                    /* Base writeback.  */
                    if (rn == 15)
                        return 1;
                    gen_op_addl_T1_im(offset - 4);
                    gen_movl_reg_T1(s, rn);
                }
            } else if ((insn & (1 << 23)) == 0) {
                /* Load/store exclusive word.  */
                gen_movl_T0_reg(s, rd);
                gen_movl_T1_reg(s, rn);
                if (insn & (1 << 20)) {
                    do { s.is_mem = 1; if ((s.user)) gen_op_ldlex_user(); else gen_op_ldlex_kernel(); } while (0);
                } else {
                    do { s.is_mem = 1; if ((s.user)) gen_op_stlex_user(); else gen_op_stlex_kernel(); } while (0);
                }
                gen_movl_reg_T0(s, rd);
            } else if ((insn & (1 << 6)) == 0) {
                /* Table Branch.  */
                if (rn == 15) {
                    gen_op_movl_T1_im(s.pc);
                } else {
                    gen_movl_T1_reg(s, rn);
                }
                gen_movl_T2_reg(s, rm);
                gen_op_addl_T1_T2();
                if (insn & (1 << 4)) {
                    /* tbh */
                    gen_op_addl_T1_T2();
                    do { s.is_mem = 1; if ((s.user)) gen_op_lduw_user(); else gen_op_lduw_kernel(); } while (0);
                } else { /* tbb */
                    do { s.is_mem = 1; if ((s.user)) gen_op_ldub_user(); else gen_op_ldub_kernel(); } while (0);
                }
                gen_op_jmp_T0_im(s.pc);
                s.is_jmp = 1;
            } else {
                /* Load/store exclusive byte/halfword/doubleword.  */
                op = (insn >> 4) & 0x3;
                gen_movl_T1_reg(s, rn);
                if (insn & (1 << 20)) {
                    switch (op) {
                    case 0:
                        do { s.is_mem = 1; if ((s.user)) gen_op_ldbex_user(); else gen_op_ldbex_kernel(); } while (0);
                        break;
                    case 1:
                        do { s.is_mem = 1; if ((s.user)) gen_op_ldwex_user(); else gen_op_ldwex_kernel(); } while (0);
                        break;
                    case 3:
                        do { s.is_mem = 1; if ((s.user)) gen_op_ldqex_user(); else gen_op_ldqex_kernel(); } while (0);
                        gen_movl_reg_T1(s, rd);
                        break;
                    default:
                        return 1;
                    }
                    gen_movl_reg_T0(s, rs);
                } else {
                    gen_movl_T0_reg(s, rs);
                    switch (op) {
                    case 0:
                        do { s.is_mem = 1; if ((s.user)) gen_op_stbex_user(); else gen_op_stbex_kernel(); } while (0);
                        break;
                    case 1:
                        do { s.is_mem = 1; if ((s.user)) gen_op_stwex_user(); else gen_op_stwex_kernel(); } while (0);
                        break;
                    case 3:
                        gen_movl_T2_reg(s, rd);
                        do { s.is_mem = 1; if ((s.user)) gen_op_stqex_user(); else gen_op_stqex_kernel(); } while (0);
                        break;
                    default:
                        return 1;
                    }
                    gen_movl_reg_T0(s, rm);
                }
            }
        } else {
            /* Load/store multiple, RFE, SRS.  */
            if (((insn >> 23) & 1) == ((insn >> 24) & 1)) {
                /* Not available in user mode.  */
                if (!(s.user))
                    return 1;
                if (insn & (1 << 20)) {
                    /* rfe */
                    gen_movl_T1_reg(s, rn);
                    if (insn & (1 << 24)) {
                        gen_op_addl_T1_im(4);
                    } else {
                        gen_op_addl_T1_im(-4);
                    }
                    /* Load CPSR into T2 and PC into T0.  */
                    do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                    gen_op_movl_T2_T0();
                    gen_op_addl_T1_im(-4);
                    do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                    if (insn & (1 << 21)) {
                        /* Base writeback.  */
                        if (insn & (1 << 24))
                            gen_op_addl_T1_im(8);
                        gen_movl_reg_T1(s, rn);
                    }
                    gen_rfe(s);
                } else {
                    /* srs */
                    op = (insn & 0x1f);
                    if (op == (env.uncached_cpsr & (0x1f))) {
                        gen_movl_T1_reg(s, 13);
                    } else {
                        gen_op_movl_T1_r13_banked(op);
                    }
                    if ((insn & (1 << 24)) == 0) {
                        gen_op_addl_T1_im(-8);
                    }
                    gen_movl_T0_reg(s, 14);
                    do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                    gen_op_movl_T0_cpsr();
                    gen_op_addl_T1_im(4);
                    do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                    if (insn & (1 << 21)) {
                        if ((insn & (1 << 24)) == 0) {
                            gen_op_addl_T1_im(-4);
                        } else {
                            gen_op_addl_T1_im(4);
                        }
                        if (op == (env.uncached_cpsr & (0x1f))) {
                            gen_movl_reg_T1(s, 13);
                        } else {
                            gen_op_movl_r13_T1_banked(op);
                        }
                    }
                }
            } else {
                var i;
                /* Load/store multiple.  */
                gen_movl_T1_reg(s, rn);
                offset = 0;
                for (i = 0; i < 16; i++) {
                    if (insn & (1 << i))
                        offset += 4;
                }
                if (insn & (1 << 24)) {
                    gen_op_addl_T1_im(-offset);
                }

                for (i = 0; i < 16; i++) {
                    if ((insn & (1 << i)) == 0)
                        continue;
                    if (insn & (1 << 20)) {
                        /* Load.  */
                        do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                        if (i == 15) {
                            gen_bx(s);
                        } else {
                            gen_movl_reg_T0(s, i);
                        }
                    } else {
                        /* Store.  */
                        gen_movl_T0_reg(s, i);
                        do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                    }
                    gen_op_addl_T1_im(4);
                }
                if (insn & (1 << 21)) {
                    /* Base register writeback.  */
                    if (insn & (1 << 24)) {
                        gen_op_addl_T1_im(-offset);
                    }
                    /* Fault if writeback register is in register list.  */
                    if (insn & (1 << rn))
                        return 1;
                    gen_movl_reg_T1(s, rn);
                }
            }
        }
        break;
    case 5: /* Data processing register constant shift.  */
        if (rn == 15)
            gen_op_movl_T0_im(0);
        else
            gen_movl_T0_reg(s, rn);
        gen_movl_T1_reg(s, rm);
        op = (insn >> 21) & 0xf;
        shiftop = (insn >> 4) & 3;
        shift = ((insn >> 6) & 3) | ((insn >> 10) & 0x1c);
        conds = (insn & (1 << 20)) != 0;
        logic_cc = (conds && thumb2_logic_op(op));
        if (shift != 0) {
            if (logic_cc) {
                gen_shift_T1_im_cc[shiftop](shift);
            } else {
                gen_shift_T1_im[shiftop](shift);
            }
        } else if (shiftop != 0) {
            if (logic_cc) {
                gen_shift_T1_0_cc[shiftop]();
            } else {
                gen_shift_T1_0[shiftop]();
            }
        }
        if (gen_thumb2_data_op(s, op, conds, 0))
            return 1;
        if (rd != 15)
            gen_movl_reg_T0(s, rd);
        break;
    case 13: /* Misc data processing.  */
        op = ((insn >> 22) & 6) | ((insn >> 7) & 1);
        if (op < 4 && (insn & 0xf000) != 0xf000)
            return 1;
        switch (op) {
        case 0: /* Register controlled shift.  */
            gen_movl_T0_reg(s, rm);
            gen_movl_T1_reg(s, rn);
            if ((insn & 0x70) != 0)
                return 1;
            op = (insn >> 21) & 3;
            if (insn & (1 << 20)) {
                gen_shift_T1_T0_cc[op]();
                gen_op_logic_T1_cc();
            } else {
                gen_shift_T1_T0[op]();
            }
            gen_movl_reg_T1(s, rd);
            break;
        case 1: /* Sign/zero extend.  */
            gen_movl_T1_reg(s, rm);
            shift = (insn >> 4) & 3;
            /* ??? In many cases it's not neccessary to do a
               rotate, a shift is sufficient.  */
            if (shift != 0)
                gen_op_rorl_T1_im(shift * 8);
            op = (insn >> 20) & 7;
            switch (op) {
            case 0: gen_op_sxth_T1(); break;
            case 1: gen_op_uxth_T1(); break;
            case 2: gen_op_sxtb16_T1(); break;
            case 3: gen_op_uxtb16_T1(); break;
            case 4: gen_op_sxtb_T1(); break;
            case 5: gen_op_uxtb_T1(); break;
            default: return 1;
            }
            if (rn != 15) {
                gen_movl_T2_reg(s, rn);
                if ((op >> 1) == 1) {
                    gen_op_add16_T1_T2();
                } else {
                    gen_op_addl_T1_T2();
                }
            }
            gen_movl_reg_T1(s, rd);
            break;
        case 2: /* SIMD add/subtract.  */
            op = (insn >> 20) & 7;
            shift = (insn >> 4) & 7;
            if ((op & 3) == 3 || (shift & 3) == 3)
                return 1;
            gen_movl_T0_reg(s, rn);
            gen_movl_T1_reg(s, rm);
            gen_thumb2_parallel_addsub[op][shift]();
            gen_movl_reg_T0(s, rd);
            break;
        case 3: /* Other data processing.  */
            op = ((insn >> 17) & 0x38) | ((insn >> 4) & 7);
            if (op < 4) {
                /* Saturating add/subtract.  */
                gen_movl_T0_reg(s, rm);
                gen_movl_T1_reg(s, rn);
                if (op & 2)
                    gen_op_double_T1_saturate();
                if (op & 1)
                    gen_op_subl_T0_T1_saturate();
                else
                    gen_op_addl_T0_T1_saturate();
            } else {
                gen_movl_T0_reg(s, rn);
                switch (op) {
                case 0x0a: /* rbit */
                    gen_op_rbit_T0();
                    break;
                case 0x08: /* rev */
                    gen_op_rev_T0();
                    break;
                case 0x09: /* rev16 */
                    gen_op_rev16_T0();
                    break;
                case 0x0b: /* revsh */
                    gen_op_revsh_T0();
                    break;
                case 0x10: /* sel */
                    gen_movl_T1_reg(s, rm);
                    gen_op_sel_T0_T1();
                    break;
                case 0x18: /* clz */
                    gen_op_clz_T0();
                    break;
                default:
                    return 1;
                }
            }
            gen_movl_reg_T0(s, rd);
            break;
        case 4: case 5: /* 32-bit multiply.  Sum of absolute differences.  */
            op = (insn >> 4) & 0xf;
            gen_movl_T0_reg(s, rn);
            gen_movl_T1_reg(s, rm);
            switch ((insn >> 20) & 7) {
            case 0: /* 32 x 32 -> 32 */
                gen_op_mul_T0_T1();
                if (rs != 15) {
                    gen_movl_T1_reg(s, rs);
                    if (op)
                        gen_op_rsbl_T0_T1();
                    else
                        gen_op_addl_T0_T1();
                }
                gen_movl_reg_T0(s, rd);
                break;
            case 1: /* 16 x 16 -> 32 */
                gen_mulxy(op & 2, op & 1);
                if (rs != 15) {
                    gen_movl_T1_reg(s, rs);
                    gen_op_addl_T0_T1_setq();
                }
                gen_movl_reg_T0(s, rd);
                break;
            case 2: /* Dual multiply add.  */
            case 4: /* Dual multiply subtract.  */
                if (op)
                    gen_op_swap_half_T1();
                gen_op_mul_dual_T0_T1();
                /* This addition cannot overflow.  */
                if (insn & (1 << 22)) {
                    gen_op_subl_T0_T1();
                } else {
                    gen_op_addl_T0_T1();
                }
                if (rs != 15)
                  {
                    gen_movl_T1_reg(s, rs);
                    gen_op_addl_T0_T1_setq();
                  }
                gen_movl_reg_T0(s, rd);
                break;
            case 3: /* 32 * 16 -> 32msb */
                if (op)
                    gen_op_sarl_T1_im(16);
                else
                    gen_op_sxth_T1();
                gen_op_imulw_T0_T1();
                if (rs != 15)
                  {
                    gen_movl_T1_reg(s, rs);
                    gen_op_addl_T0_T1_setq();
                  }
                gen_movl_reg_T0(s, rd);
                break;
            case 5: case 6: /* 32 * 32 -> 32msb */
                gen_op_imull_T0_T1();
                if (insn & (1 << 5))
                    gen_op_roundqd_T0_T1();
                else
                    gen_op_movl_T0_T1();
                if (rs != 15) {
                    gen_movl_T1_reg(s, rs);
                    if (insn & (1 << 21)) {
                        gen_op_addl_T0_T1();
                    } else {
                        gen_op_rsbl_T0_T1();
                    }
                }
                gen_movl_reg_T0(s, rd);
                break;
            case 7: /* Unsigned sum of absolute differences.  */
                gen_op_usad8_T0_T1();
                if (rs != 15) {
                    gen_movl_T1_reg(s, rs);
                    gen_op_addl_T0_T1();
                }
                gen_movl_reg_T0(s, rd);
                break;
            }
            break;
        case 6: case 7: /* 64-bit multiply, Divide.  */
            op = ((insn >> 4) & 0xf) | ((insn >> 16) & 0x70);
            gen_movl_T0_reg(s, rn);
            gen_movl_T1_reg(s, rm);
            if ((op & 0x50) == 0x10) {
                /* sdiv, udiv */
                if (!arm_feature(env, ARM_FEATURE_DIV))
                    return 1;
                if (op & 0x20)
                    gen_op_udivl_T0_T1();
                else
                    gen_op_sdivl_T0_T1();
                gen_movl_reg_T0(s, rd);
            } else if ((op & 0xe) == 0xc) {
                /* Dual multiply accumulate long.  */
                if (op & 1)
                    gen_op_swap_half_T1();
                gen_op_mul_dual_T0_T1();
                if (op & 0x10) {
                    gen_op_subl_T0_T1();
                } else {
                    gen_op_addl_T0_T1();
                }
                gen_op_signbit_T1_T0();
                gen_op_addq_T0_T1(rs, rd);
                gen_movl_reg_T0(s, rs);
                gen_movl_reg_T1(s, rd);
            } else {
                if (op & 0x20) {
                    /* Unsigned 64-bit multiply  */
                    gen_op_mull_T0_T1();
                } else {
                    if (op & 8) {
                        /* smlalxy */
                        gen_mulxy(op & 2, op & 1);
                        gen_op_signbit_T1_T0();
                    } else {
                        /* Signed 64-bit multiply  */
                        gen_op_imull_T0_T1();
                    }
                }
                if (op & 4) {
                    /* umaal */
                    gen_op_addq_lo_T0_T1(rs);
                    gen_op_addq_lo_T0_T1(rd);
                } else if (op & 0x40) {
                    /* 64-bit accumulate.  */
                    gen_op_addq_T0_T1(rs, rd);
                }
                gen_movl_reg_T0(s, rs);
                gen_movl_reg_T1(s, rd);
            }
            break;
        }
        break;
    case 6: case 7: case 14: case 15:
        /* Coprocessor.  */
        if (((insn >> 24) & 3) == 3) {
            /* Translate into the equivalent ARM encoding.  */
            insn = (insn & 0xe2ffffff) | ((insn & (1 << 28)) >> 4);
            if (disas_neon_data_insn(env, s, insn))
                return 1;
        } else {
            if (insn & (1 << 28))
                return 1;
            if (disas_coproc_insn (env, s, insn))
                return 1;
        }
        break;
    case 8: case 9: case 10: case 11:
        if (insn & (1 << 15)) {
            /* Branches, misc control.  */
            if (insn & 0x5000) {
                /* Unconditional branch.  */
                /* signextend(hw1[10:0]) -> offset[:12].  */
                offset = (insn << 5) >> 9 & ~0xfff;
                /* hw1[10:0] -> offset[11:1].  */
                offset |= (insn & 0x7ff) << 1;
                /* (~hw2[13, 11] ^ offset[24]) -> offset[23,22]
                   offset[24:22] already have the same value because of the
                   sign extension above.  */
                offset ^= ((~insn) & (1 << 13)) << 10;
                offset ^= ((~insn) & (1 << 11)) << 11;

                addr = s.pc;
                if (insn & (1 << 14)) {
                    /* Branch and link.  */
                    gen_op_movl_T1_im(addr | 1);
                    gen_movl_reg_T1(s, 14);
                }

                addr += offset;
                if (insn & (1 << 12)) {
                    /* b/bl */
                    gen_jmp(s, addr);
                } else {
                    /* blx */
                    addr &= ~2;
                    gen_op_movl_T0_im(addr);
                    gen_bx(s);
                }
            } else if (((insn >> 23) & 7) == 7) {
                /* Misc control */
                if (insn & (1 << 13))
                    return 1;

                if (insn & (1 << 26)) {
                    /* Secure monitor call (v6Z) */
                   return 1; /* not implemented.  */
                } else {
                    op = (insn >> 20) & 7;
                    switch (op) {
                    case 0: /* msr cpsr.  */
                        if (arm_feature(env, ARM_FEATURE_M)) {
                            gen_op_v7m_msr_T0(insn & 0xff);
                            gen_movl_reg_T0(s, rn);
                            gen_lookup_tb(s);
                            break;
                        }
                        /* fall through */
                    case 1: /* msr spsr.  */
                        if (arm_feature(env, ARM_FEATURE_M))
                            return 1;
                        gen_movl_T0_reg(s, rn);
                        if (gen_set_psr_T0(s,
                              msr_mask(env, s, (insn >> 8) & 0xf, op == 1),
                              op == 1))
                            return 1;
                        break;
                    case 2: /* cps, nop-hint.  */
                        if (((insn >> 8) & 7) == 0) {
                            gen_nop_hint(s, insn & 0xff);
                        }
                        /* Implemented as NOP in user mode.  */
                        if ((s.user))
                            break;
                        offset = 0;
                        imm = 0;
                        if (insn & (1 << 10)) {
                            if (insn & (1 << 7))
                                offset |= (1 << 8);
                            if (insn & (1 << 6))
                                offset |= (1 << 7);
                            if (insn & (1 << 5))
                                offset |= (1 << 6);
                            if (insn & (1 << 9))
                                imm = (1 << 8) | (1 << 7) | (1 << 6);
                        }
                        if (insn & (1 << 8)) {
                            offset |= 0x1f;
                            imm |= (insn & 0x1f);
                        }
                        if (offset) {
                            gen_op_movl_T0_im(imm);
                            gen_set_psr_T0(s, offset, 0);
                        }
                        break;
                    case 3: /* Special control operations.  */
                        op = (insn >> 4) & 0xf;
                        switch (op) {
                        case 2: /* clrex */
                            gen_op_clrex();
                            break;
                        case 4: /* dsb */
                        case 5: /* dmb */
                        case 6: /* isb */
                            /* These execute as NOPs.  */
                            if (!arm_feature(env, ARM_FEATURE_V7)) return 1;
                            break;
                        default:
                            return 1;
                        }
                        break;
                    case 4: /* bxj */
                        /* Trivial implementation equivalent to bx.  */
                        gen_movl_T0_reg(s, rn);
                        gen_bx(s);
                        break;
                    case 5: /* Exception return.  */
                        /* Unpredictable in user mode.  */
                        return 1;
                    case 6: /* mrs cpsr.  */
                        if (arm_feature(env, ARM_FEATURE_M)) {
                            gen_op_v7m_mrs_T0(insn & 0xff);
                        } else {
                            gen_op_movl_T0_cpsr();
                        }
                        gen_movl_reg_T0(s, rd);
                        break;
                    case 7: /* mrs spsr.  */
                        /* Not accessible in user mode.  */
                        if ((s.user) || arm_feature(env, ARM_FEATURE_M))
                            return 1;
                        gen_op_movl_T0_spsr();
                        gen_movl_reg_T0(s, rd);
                        break;
                    }
                }
            } else {
                /* Conditional branch.  */
                op = (insn >> 22) & 0xf;
                /* Generate a conditional jump to next instruction.  */
                s.condlabel = gen_new_label();
                gen_test_cc[op ^ 1](s.condlabel);
                s.condjmp = 1;

                /* offset[11:1] = insn[10:0] */
                offset = (insn & 0x7ff) << 1;
                /* offset[17:12] = insn[21:16].  */
                offset |= (insn & 0x003f0000) >> 4;
                /* offset[31:20] = insn[26].  */
                offset |= (/* (int32_t) */((insn << 5) & 0x80000000)) >> 11;
                /* offset[18] = insn[13].  */
                offset |= (insn & (1 << 13)) << 5;
                /* offset[19] = insn[11].  */
                offset |= (insn & (1 << 11)) << 8;

                /* jump to the offset */
                addr = s.pc + offset;
                gen_jmp(s, addr);
            }
        } else {
            /* Data processing immediate.  */
            if (insn & (1 << 25)) {
                if (insn & (1 << 24)) {
                    if (insn & (1 << 20))
                        return 1;
                    /* Bitfield/Saturate.  */
                    op = (insn >> 21) & 7;
                    imm = insn & 0x1f;
                    shift = ((insn >> 6) & 3) | ((insn >> 10) & 0x1c);
                    if (rn == 15)
                        gen_op_movl_T1_im(0);
                    else
                        gen_movl_T1_reg(s, rn);
                    switch (op) {
                    case 2: /* Signed bitfield extract.  */
                        imm++;
                        if (shift + imm > 32)
                            return 1;
                        if (imm < 32)
                            gen_op_sbfx_T1(shift, imm);
                        break;
                    case 6: /* Unsigned bitfield extract.  */
                        imm++;
                        if (shift + imm > 32)
                            return 1;
                        if (imm < 32)
                            gen_op_ubfx_T1(shift, (1/* u */ << imm) - 1);
                        break;
                    case 3: /* Bitfield insert/clear.  */
                        if (imm < shift)
                            return 1;
                        imm = imm + 1 - shift;
                        if (imm != 32) {
                            gen_movl_T0_reg(s, rd);
                            gen_op_bfi_T1_T0(shift, ((1/* u*/ << imm) - 1) << shift);
                        }
                        break;
                    case 7:
                        return 1;
                    default: /* Saturate.  */
                        gen_movl_T1_reg(s, rn);
                        if (shift) {
                            if (op & 1)
                                gen_op_sarl_T1_im(shift);
                            else
                                gen_op_shll_T1_im(shift);
                        }
                        if (op & 4) {
                            /* Unsigned.  */
                            gen_op_ssat_T1(imm);
                            if ((op & 1) && shift == 0)
                                gen_op_usat16_T1(imm);
                            else
                                gen_op_usat_T1(imm);
                        } else {
                            /* Signed.  */
                            gen_op_ssat_T1(imm);
                            if ((op & 1) && shift == 0)
                                gen_op_ssat16_T1(imm);
                            else
                                gen_op_ssat_T1(imm);
                        }
                        break;
                    }
                    gen_movl_reg_T1(s, rd);
                } else {
                    imm = ((insn & 0x04000000) >> 15)
                          | ((insn & 0x7000) >> 4) | (insn & 0xff);
                    if (insn & (1 << 22)) {
                        /* 16-bit immediate.  */
                        imm |= (insn >> 4) & 0xf000;
                        if (insn & (1 << 23)) {
                            /* movt */
                            gen_movl_T0_reg(s, rd);
                            gen_op_movtop_T0_im(imm << 16);
                        } else {
                            /* movw */
                            gen_op_movl_T0_im(imm);
                        }
                    } else {
                        /* Add/sub 12-bit immediate.  */
                        if (rn == 15) {
                            addr = s.pc & ~3;
                            if (insn & (1 << 23))
                                addr -= imm;
                            else
                                addr += imm;
                            gen_op_movl_T0_im(addr);
                        } else {
                            gen_movl_T0_reg(s, rn);
                            gen_op_movl_T1_im(imm);
                            if (insn & (1 << 23))
                                gen_op_subl_T0_T1();
                            else
                                gen_op_addl_T0_T1();
                        }
                    }
                    gen_movl_reg_T0(s, rd);
                }
            } else {
                var shifter_out = 0;
                /* modified 12-bit immediate.  */
                shift = ((insn & 0x04000000) >> 23) | ((insn & 0x7000) >> 12);
                imm = (insn & 0xff);
                switch (shift) {
                case 0: /* XY */
                    /* Nothing to do.  */
                    break;
                case 1: /* 00XY00XY */
                    imm |= imm << 16;
                    break;
                case 2: /* XY00XY00 */
                    imm |= imm << 16;
                    imm <<= 8;
                    break;
                case 3: /* XYXYXYXY */
                    imm |= imm << 16;
                    imm |= imm << 8;
                    break;
                default: /* Rotated constant.  */
                    shift = (shift << 1) | (imm >> 7);
                    imm |= 0x80;
                    imm = imm << (32 - shift);
                    shifter_out = 1;
                    break;
                }
                gen_op_movl_T1_im(imm);
                rn = (insn >> 16) & 0xf;
                if (rn == 15)
                    gen_op_movl_T0_im(0);
                else
                    gen_movl_T0_reg(s, rn);
                op = (insn >> 21) & 0xf;
                if (gen_thumb2_data_op(s, op, (insn & (1 << 20)) != 0,
                                       shifter_out))
                    return 1;
                rd = (insn >> 8) & 0xf;
                if (rd != 15) {
                    gen_movl_reg_T0(s, rd);
                }
            }
        }
        break;
    case 12: /* Load/store single data item.  */
        {
        var postinc = 0;
        var writeback = 0;
        if ((insn & 0x01100000) == 0x01000000) {
            if (disas_neon_ls_insn(env, s, insn))
                return 1;
            break;
        }
        if (rn == 15) {
            /* PC relative.  */
            /* s.pc has already been incremented by 4.  */
            imm = s.pc & 0xfffffffc;
            if (insn & (1 << 23))
                imm += insn & 0xfff;
            else
                imm -= insn & 0xfff;
            gen_op_movl_T1_im(imm);
        } else {
            gen_movl_T1_reg(s, rn);
            if (insn & (1 << 23)) {
                /* Positive offset.  */
                imm = insn & 0xfff;
                gen_op_addl_T1_im(imm);
            } else {
                op = (insn >> 8) & 7;
                imm = insn & 0xff;
                switch (op) {
                case 0: case 8: /* Shifted Register.  */
                    shift = (insn >> 4) & 0xf;
                    if (shift > 3)
                        return 1;
                    gen_movl_T2_reg(s, rm);
                    if (shift)
                        gen_op_shll_T2_im(shift);
                    gen_op_addl_T1_T2();
                    break;
                case 4: /* Negative offset.  */
                    gen_op_addl_T1_im(-imm);
                    break;
                case 6: /* User privilege.  */
                    gen_op_addl_T1_im(imm);
                    break;
                case 1: /* Post-decrement.  */
                    imm = -imm;
                    /* Fall through.  */
                case 3: /* Post-increment.  */
                    gen_op_movl_T2_im(imm);
                    postinc = 1;
                    writeback = 1;
                    break;
                case 5: /* Pre-decrement.  */
                    imm = -imm;
                    /* Fall through.  */
                case 7: /* Pre-increment.  */
                    gen_op_addl_T1_im(imm);
                    writeback = 1;
                    break;
                default:
                    return 1;
                }
            }
        }
        op = ((insn >> 21) & 3) | ((insn >> 22) & 4);
        if (insn & (1 << 20)) {
            /* Load.  */
            if (rs == 15 && op != 2) {
                if (op & 2)
                    return 1;
                /* Memory hint.  Implemented as NOP.  */
            } else {
                switch (op) {
                case 0: do { s.is_mem = 1; if ((s.user)) gen_op_ldub_user(); else gen_op_ldub_kernel(); } while (0); break;
                case 4: do { s.is_mem = 1; if ((s.user)) gen_op_ldsb_user(); else gen_op_ldsb_kernel(); } while (0); break;
                case 1: do { s.is_mem = 1; if ((s.user)) gen_op_lduw_user(); else gen_op_lduw_kernel(); } while (0); break;
                case 5: do { s.is_mem = 1; if ((s.user)) gen_op_ldsw_user(); else gen_op_ldsw_kernel(); } while (0); break;
                case 2: do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0); break;
                default: return 1;
                }
                if (rs == 15) {
                    gen_bx(s);
                } else {
                    gen_movl_reg_T0(s, rs);
                }
            }
        } else {
            /* Store.  */
            if (rs == 15)
                return 1;
            gen_movl_T0_reg(s, rs);
            switch (op) {
            case 0: do { s.is_mem = 1; if ((s.user)) gen_op_stb_user(); else gen_op_stb_kernel(); } while (0); break;
            case 1: do { s.is_mem = 1; if ((s.user)) gen_op_stw_user(); else gen_op_stw_kernel(); } while (0); break;
            case 2: do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0); break;
            default: return 1;
            }
        }
        if (postinc)
            gen_op_addl_T1_im(imm);
        if (writeback)
            gen_movl_reg_T1(s, rn);
        }
        break;
    default:
        return 1;
    }
    return 0;
}

function disas_thumb_insn(/* CPUARMState * */ env, /* DisasContext * */s)
{
    var /* uint32_t*/ val, insn, op, rm, rn, rd, shift, cond;
    var offset;
    var i;

    if (s.condexec_mask) {
        cond = s.condexec_cond;
        s.condlabel = gen_new_label();
        gen_test_cc[cond ^ 1](s.condlabel);
        s.condjmp = 1;
    }

    insn = lduw_code(s.pc);
    s.pc += 2;

    switch (insn >> 12) {
    case 0: case 1:
        rd = insn & 7;
        op = (insn >> 11) & 3;
        if (op == 3) {
            /* add/subtract */
            rn = (insn >> 3) & 7;
            gen_movl_T0_reg(s, rn);
            if (insn & (1 << 10)) {
                /* immediate */
                gen_op_movl_T1_im((insn >> 6) & 7);
            } else {
                /* reg */
                rm = (insn >> 6) & 7;
                gen_movl_T1_reg(s, rm);
            }
            if (insn & (1 << 9)) {
                if (s.condexec_mask)
                    gen_op_subl_T0_T1();
                else
                    gen_op_subl_T0_T1_cc();
            } else {
                if (s.condexec_mask)
                    gen_op_addl_T0_T1();
                else
                    gen_op_addl_T0_T1_cc();
            }
            gen_movl_reg_T0(s, rd);
        } else {
            /* shift immediate */
            rm = (insn >> 3) & 7;
            shift = (insn >> 6) & 0x1f;
            gen_movl_T0_reg(s, rm);
            if (s.condexec_mask)
                gen_shift_T0_im_thumb[op](shift);
            else
                gen_shift_T0_im_thumb_cc[op](shift);
            gen_movl_reg_T0(s, rd);
        }
        break;
    case 2: case 3:
        /* arithmetic large immediate */
        op = (insn >> 11) & 3;
        rd = (insn >> 8) & 0x7;
        if (op == 0) {
            gen_op_movl_T0_im(insn & 0xff);
        } else {
            gen_movl_T0_reg(s, rd);
            gen_op_movl_T1_im(insn & 0xff);
        }
        switch (op) {
        case 0: /* mov */
            if (!s.condexec_mask)
                gen_op_logic_T0_cc();
            break;
        case 1: /* cmp */
            gen_op_subl_T0_T1_cc();
            break;
        case 2: /* add */
            if (s.condexec_mask)
                gen_op_addl_T0_T1();
            else
                gen_op_addl_T0_T1_cc();
            break;
        case 3: /* sub */
            if (s.condexec_mask)
                gen_op_subl_T0_T1();
            else
                gen_op_subl_T0_T1_cc();
            break;
        }
        if (op != 1)
            gen_movl_reg_T0(s, rd);
        break;
    case 4:
        if (insn & (1 << 11)) {
            rd = (insn >> 8) & 7;
            /* load pc-relative.  Bit 1 of PC is ignored.  */
            val = s.pc + 2 + ((insn & 0xff) * 4);
            val &= ~2;
            gen_op_movl_T1_im(val);
            do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
            gen_movl_reg_T0(s, rd);
            break;
        }
        if (insn & (1 << 10)) {
            /* data processing extended or blx */
            rd = (insn & 7) | ((insn >> 4) & 8);
            rm = (insn >> 3) & 0xf;
            op = (insn >> 8) & 3;
            switch (op) {
            case 0: /* add */
                gen_movl_T0_reg(s, rd);
                gen_movl_T1_reg(s, rm);
                gen_op_addl_T0_T1();
                gen_movl_reg_T0(s, rd);
                break;
            case 1: /* cmp */
                gen_movl_T0_reg(s, rd);
                gen_movl_T1_reg(s, rm);
                gen_op_subl_T0_T1_cc();
                break;
            case 2: /* mov/cpy */
                gen_movl_T0_reg(s, rm);
                gen_movl_reg_T0(s, rd);
                break;
            case 3:/* branch [and link] exchange thumb register */
                if (insn & (1 << 7)) {
                    val = s.pc | 1;
                    gen_op_movl_T1_im(val);
                    gen_movl_reg_T1(s, 14);
                }
                gen_movl_T0_reg(s, rm);
                gen_bx(s);
                break;
            }
            break;
        }

        /* data processing register */
        rd = insn & 7;
        rm = (insn >> 3) & 7;
        op = (insn >> 6) & 0xf;
        if (op == 2 || op == 3 || op == 4 || op == 7) {
            /* the shift/rotate ops want the operands backwards */
            val = rm;
            rm = rd;
            rd = val;
            val = 1;
        } else {
            val = 0;
        }

        if (op == 9) /* neg */
            gen_op_movl_T0_im(0);
        else if (op != 0xf) /* mvn doesn't read its first operand */
            gen_movl_T0_reg(s, rd);

        gen_movl_T1_reg(s, rm);
        switch (op) {
        case 0x0: /* and */
            gen_op_andl_T0_T1();
            if (!s.condexec_mask)
                gen_op_logic_T0_cc();
            break;
        case 0x1: /* eor */
            gen_op_xorl_T0_T1();
            if (!s.condexec_mask)
                gen_op_logic_T0_cc();
            break;
        case 0x2: /* lsl */
            if (s.condexec_mask) {
                gen_op_shll_T1_T0();
            } else {
                gen_op_shll_T1_T0_cc();
                gen_op_logic_T1_cc();
            }
            break;
        case 0x3: /* lsr */
            if (s.condexec_mask) {
                gen_op_shrl_T1_T0();
            } else {
                gen_op_shrl_T1_T0_cc();
                gen_op_logic_T1_cc();
            }
            break;
        case 0x4: /* asr */
            if (s.condexec_mask) {
                gen_op_sarl_T1_T0();
            } else {
                gen_op_sarl_T1_T0_cc();
                gen_op_logic_T1_cc();
            }
            break;
        case 0x5: /* adc */
            if (s.condexec_mask)
                gen_op_adcl_T0_T1();
            else
                gen_op_adcl_T0_T1_cc();
            break;
        case 0x6: /* sbc */
            if (s.condexec_mask)
                gen_op_sbcl_T0_T1();
            else
                gen_op_sbcl_T0_T1_cc();
            break;
        case 0x7: /* ror */
            if (s.condexec_mask) {
                gen_op_rorl_T1_T0();
            } else {
                gen_op_rorl_T1_T0_cc();
                gen_op_logic_T1_cc();
            }
            break;
        case 0x8: /* tst */
            gen_op_andl_T0_T1();
            gen_op_logic_T0_cc();
            rd = 16;
            break;
        case 0x9: /* neg */
            if (s.condexec_mask)
                gen_op_subl_T0_T1();
            else
                gen_op_subl_T0_T1_cc();
            break;
        case 0xa: /* cmp */
            gen_op_subl_T0_T1_cc();
            rd = 16;
            break;
        case 0xb: /* cmn */
            gen_op_addl_T0_T1_cc();
            rd = 16;
            break;
        case 0xc: /* orr */
            gen_op_orl_T0_T1();
            if (!s.condexec_mask)
                gen_op_logic_T0_cc();
            break;
        case 0xd: /* mul */
            gen_op_mull_T0_T1();
            if (!s.condexec_mask)
                gen_op_logic_T0_cc();
            break;
        case 0xe: /* bic */
            gen_op_bicl_T0_T1();
            if (!s.condexec_mask)
                gen_op_logic_T0_cc();
            break;
        case 0xf: /* mvn */
            gen_op_notl_T1();
            if (!s.condexec_mask)
                gen_op_logic_T1_cc();
            val = 1;
            rm = rd;
            break;
        }
        if (rd != 16) {
            if (val)
                gen_movl_reg_T1(s, rm);
            else
                gen_movl_reg_T0(s, rd);
        }
        break;

    case 5:
        /* load/store register offset.  */
        rd = insn & 7;
        rn = (insn >> 3) & 7;
        rm = (insn >> 6) & 7;
        op = (insn >> 9) & 7;
        gen_movl_T1_reg(s, rn);
        gen_movl_T2_reg(s, rm);
        gen_op_addl_T1_T2();

        if (op < 3) /* store */
            gen_movl_T0_reg(s, rd);

        switch (op) {
        case 0: /* str */
            do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
            break;
        case 1: /* strh */
            do { s.is_mem = 1; if ((s.user)) gen_op_stw_user(); else gen_op_stw_kernel(); } while (0);
            break;
        case 2: /* strb */
            do { s.is_mem = 1; if ((s.user)) gen_op_stb_user(); else gen_op_stb_kernel(); } while (0);
            break;
        case 3: /* ldrsb */
            do { s.is_mem = 1; if ((s.user)) gen_op_ldsb_user(); else gen_op_ldsb_kernel(); } while (0);
            break;
        case 4: /* ldr */
            do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
            break;
        case 5: /* ldrh */
            do { s.is_mem = 1; if ((s.user)) gen_op_lduw_user(); else gen_op_lduw_kernel(); } while (0);
            break;
        case 6: /* ldrb */
            do { s.is_mem = 1; if ((s.user)) gen_op_ldub_user(); else gen_op_ldub_kernel(); } while (0);
            break;
        case 7: /* ldrsh */
            do { s.is_mem = 1; if ((s.user)) gen_op_ldsw_user(); else gen_op_ldsw_kernel(); } while (0);
            break;
        }
        if (op >= 3) /* load */
            gen_movl_reg_T0(s, rd);
        break;

    case 6:
        /* load/store word immediate offset */
        rd = insn & 7;
        rn = (insn >> 3) & 7;
        gen_movl_T1_reg(s, rn);
        val = (insn >> 4) & 0x7c;
        gen_op_movl_T2_im(val);
        gen_op_addl_T1_T2();

        if (insn & (1 << 11)) {
            /* load */
            do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
            gen_movl_reg_T0(s, rd);
        } else {
            /* store */
            gen_movl_T0_reg(s, rd);
            do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
        }
        break;

    case 7:
        /* load/store byte immediate offset */
        rd = insn & 7;
        rn = (insn >> 3) & 7;
        gen_movl_T1_reg(s, rn);
        val = (insn >> 6) & 0x1f;
        gen_op_movl_T2_im(val);
        gen_op_addl_T1_T2();

        if (insn & (1 << 11)) {
            /* load */
            do { s.is_mem = 1; if ((s.user)) gen_op_ldub_user(); else gen_op_ldub_kernel(); } while (0);
            gen_movl_reg_T0(s, rd);
        } else {
            /* store */
            gen_movl_T0_reg(s, rd);
            do { s.is_mem = 1; if ((s.user)) gen_op_stb_user(); else gen_op_stb_kernel(); } while (0);
        }
        break;

    case 8:
        /* load/store halfword immediate offset */
        rd = insn & 7;
        rn = (insn >> 3) & 7;
        gen_movl_T1_reg(s, rn);
        val = (insn >> 5) & 0x3e;
        gen_op_movl_T2_im(val);
        gen_op_addl_T1_T2();

        if (insn & (1 << 11)) {
            /* load */
            do { s.is_mem = 1; if ((s.user)) gen_op_lduw_user(); else gen_op_lduw_kernel(); } while (0);
            gen_movl_reg_T0(s, rd);
        } else {
            /* store */
            gen_movl_T0_reg(s, rd);
            do { s.is_mem = 1; if ((s.user)) gen_op_stw_user(); else gen_op_stw_kernel(); } while (0);
        }
        break;

    case 9:
        /* load/store from stack */
        rd = (insn >> 8) & 7;
        gen_movl_T1_reg(s, 13);
        val = (insn & 0xff) * 4;
        gen_op_movl_T2_im(val);
        gen_op_addl_T1_T2();

        if (insn & (1 << 11)) {
            /* load */
            do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
            gen_movl_reg_T0(s, rd);
        } else {
            /* store */
            gen_movl_T0_reg(s, rd);
            do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
        }
        break;

    case 10:
        /* add to high reg */
        rd = (insn >> 8) & 7;
        if (insn & (1 << 11)) {
            /* SP */
            gen_movl_T0_reg(s, 13);
        } else {
            /* PC. bit 1 is ignored.  */
            gen_op_movl_T0_im((s.pc + 2) & ~2);
        }
        val = (insn & 0xff) * 4;
        gen_op_movl_T1_im(val);
        gen_op_addl_T0_T1();
        gen_movl_reg_T0(s, rd);
        break;

    case 11:
        /* misc */
        op = (insn >> 8) & 0xf;
        switch (op) {
        case 0:
            /* adjust stack pointer */
            gen_movl_T1_reg(s, 13);
            val = (insn & 0x7f) * 4;
            if (insn & (1 << 7))
              val =- val;
            gen_op_movl_T2_im(val);
            gen_op_addl_T1_T2();
            gen_movl_reg_T1(s, 13);
            break;

        case 2: /* sign/zero extend.  */
            if (!arm_feature(env, ARM_FEATURE_V6))
            {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im( s.pc - 2);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
            }
            rd = insn & 7;
            rm = (insn >> 3) & 7;
            gen_movl_T1_reg(s, rm);
            switch ((insn >> 6) & 3) {
            case 0: gen_op_sxth_T1(); break;
            case 1: gen_op_sxtb_T1(); break;
            case 2: gen_op_uxth_T1(); break;
            case 3: gen_op_uxtb_T1(); break;
            }
            gen_movl_reg_T1(s, rd);
            break;
        case 4: case 5: case 0xc: case 0xd:
            /* push/pop */
            gen_movl_T1_reg(s, 13);
            if (insn & (1 << 8))
                offset = 4;
            else
                offset = 0;
            for (i = 0; i < 8; i++) {
                if (insn & (1 << i))
                    offset += 4;
            }
            if ((insn & (1 << 11)) == 0) {
                gen_op_movl_T2_im(-offset);
                gen_op_addl_T1_T2();
            }
            gen_op_movl_T2_im(4);
            for (i = 0; i < 8; i++) {
                if (insn & (1 << i)) {
                    if (insn & (1 << 11)) {
                        /* pop */
                        do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                        gen_movl_reg_T0(s, i);
                    } else {
                        /* push */
                        gen_movl_T0_reg(s, i);
                        do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                    }
                    /* advance to the next address.  */
                    gen_op_addl_T1_T2();
                }
            }
            if (insn & (1 << 8)) {
                if (insn & (1 << 11)) {
                    /* pop pc */
                    do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                    /* don't set the pc until the rest of the instruction
                       has completed */
                } else {
                    /* push lr */
                    gen_movl_T0_reg(s, 14);
                    do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                }
                gen_op_addl_T1_T2();
            }
            if ((insn & (1 << 11)) == 0) {
                gen_op_movl_T2_im(-offset);
                gen_op_addl_T1_T2();
            }
            /* write back the new stack pointer */
            gen_movl_reg_T1(s, 13);
            /* set the new PC value */
            if ((insn & 0x0900) == 0x0900)
                gen_bx(s);
            break;

        case 1: case 3: case 9: case 11: /* czb */
            rm = insn & 7;
            gen_movl_T0_reg(s, rm);
            s.condlabel = gen_new_label();
            s.condjmp = 1;
            if (insn & (1 << 11))
                gen_op_testn_T0(s.condlabel);
            else
                gen_op_test_T0(s.condlabel);

            offset = ((insn & 0xf8) >> 2) | (insn & 0x200) >> 3;
            val = s.pc + 2;
            val += offset;
            gen_jmp(s, val);
            break;

        case 15: /* IT, nop-hint.  */
            if ((insn & 0xf) == 0) {
                gen_nop_hint(s, (insn >> 4) & 0xf);
                break;
            }
            /* If Then.  */
            s.condexec_cond = (insn >> 4) & 0xe;
            s.condexec_mask = insn & 0x1f;
            /* No actual code generated for this insn, just setup state.  */
            break;

        case 0xe: /* bkpt */
            gen_set_condexec(s);
            gen_op_movl_T0_im(s.pc - 2);
            gen_op_movl_reg_TN[0][15]();
            gen_op_bkpt();
            s.is_jmp = 1;
            break;

        case 0xa: /* rev */
            if (!arm_feature(env, ARM_FEATURE_V6))
            {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im( s.pc - 2);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
            }
            rn = (insn >> 3) & 0x7;
            rd = insn & 0x7;
            gen_movl_T0_reg(s, rn);
            switch ((insn >> 6) & 3) {
            case 0: gen_op_rev_T0(); break;
            case 1: gen_op_rev16_T0(); break;
            case 3: gen_op_revsh_T0(); break;
            default: 
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im( s.pc - 2);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                }
            }
            gen_movl_reg_T0(s, rd);
            break;

        case 6: /* cps */
            if (!arm_feature(env, ARM_FEATURE_V6))
            {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im( s.pc - 2);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
            }
            if ((s.user))
                break;
            if (arm_feature(env, ARM_FEATURE_M)) {
                val = (insn & (1 << 4)) != 0;
                gen_op_movl_T0_im(val);
                /* PRIMASK */
                if (insn & 1)
                    gen_op_v7m_msr_T0(16);
                /* FAULTMASK */
                if (insn & 2)
                    gen_op_v7m_msr_T0(17);

                gen_lookup_tb(s);
            } else {
                if (insn & (1 << 4))
                    shift = (1 << 8) | (1 << 7) | (1 << 6);
                else
                    shift = 0;

                val = ((insn & 7) << 6) & shift;
                gen_op_movl_T0_im(val);
                gen_set_psr_T0(s, shift, 0);
            }
            break;

        default:
            {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im( s.pc - 2);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
            }
        }
        break;

    case 12:
        /* load/store multiple */
        rn = (insn >> 8) & 0x7;
        gen_movl_T1_reg(s, rn);
        gen_op_movl_T2_im(4);
        for (i = 0; i < 8; i++) {
            if (insn & (1 << i)) {
                if (insn & (1 << 11)) {
                    /* load */
                    do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                    gen_movl_reg_T0(s, i);
                } else {
                    /* store */
                    gen_movl_T0_reg(s, i);
                    do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                }
                /* advance to the next address */
                gen_op_addl_T1_T2();
            }
        }
        /* Base register writeback.  */
        if ((insn & (1 << rn)) == 0)
            gen_movl_reg_T1(s, rn);
        break;

    case 13:
        /* conditional branch or swi */
        cond = (insn >> 8) & 0xf;
        if (cond == 0xe)
        {
                gen_set_condexec(s);
                gen_op_movl_T0_im( s.pc - 2);
                gen_op_movl_reg_TN[0][15]();
                gen_op_undef_insn();
                s.is_jmp = 1;
                return;
        }

        if (cond == 0xf) {
            /* swi */
            gen_set_condexec(s);
            gen_op_movl_T0_im( s.pc | 1);
            /* Don't set r15.  */
            gen_op_movl_reg_TN[0][15]();
            s.is_jmp = 5;
            break;
        }
        /* generate a conditional jump to next instruction */
        s.condlabel = gen_new_label();
        gen_test_cc[cond ^ 1](s.condlabel);
        s.condjmp = 1;
        gen_movl_T1_reg(s, 15);

        /* jump to the offset */
        val =  s.pc + 2;
        offset = ( insn << 24) >> 24;
        val += offset << 1;
        gen_jmp(s, val);
        break;

    case 14:
        if (insn & (1 << 11)) {
            if (disas_thumb2_insn(env, s, insn))
            {
                gen_set_condexec(s);
                gen_op_movl_T0_im( s.pc - 4);
                gen_op_movl_reg_TN[0][15]();
                gen_op_undef_insn();
                s.is_jmp = 1;
                return;
            }
            break;
        }
        /* unconditional branch */
        val =  s.pc;
        offset = (insn << 21) >> 21;
        val += (offset << 1) + 2;
        gen_jmp(s, val);
        break;

    case 15:
        if (disas_thumb2_insn(env, s, insn))
        {
            gen_set_condexec(s);
            gen_op_movl_T0_im( s.pc - 4);
            gen_op_movl_reg_TN[0][15]();
            gen_op_undef_insn();
            s.is_jmp = 1;
            return;
        }
        break;
    }
    return;
    /*
undef32:
    gen_set_condexec(s);
    gen_op_movl_T0_im( s.pc - 4);
    gen_op_movl_reg_TN[0][15]();
    gen_op_undef_insn();
    s.is_jmp = 1;
    return;
                                                                                                                                                                                                                                                                      
illegal_op:
undef:
    gen_set_condexec(s);
    gen_op_movl_T0_im(s.pc - 2);
    gen_op_movl_reg_TN[0][15]();
    gen_op_undef_insn();
    s.is_jmp = 1;
 */                                                                                                                                                                                                                                                                      
}

/* generate intermediate code in gen_opc_buf and gen_opparam_buf for
   basic block 'tb'. If search_pc is TRUE, also generate PC
   information for each intermediate instruction. */
/** function XXX **/
function gen_intermediate_code_internal(/* CPUARMState * */ env,
                                                 /* TranslationBlock * */ tb,
                                                 /* int */ search_pc)
{
    var /* DisasContext */ dc1, dc=dc1;/* *dc = &dc1;*/
    var /* uint16_t * */ gen_opc_end;
    var j, lj;
    var /* target_ulong */ pc_start;
    var /* uint32_t */ next_page_start;
    dc1 = new DisasContext();
    dc=dc1;
    /* generate intermediate code */
    pc_start = tb.pc;

    dc.tb = tb;

    //gen_opc_ptr = gen_opc_buf;
    //gen_opc_end = gen_opc_buf + (512 - 32);
    //gen_opparam_ptr = gen_opparam_buf;

    dc.is_jmp = 0;
    dc.pc = pc_start;
    dc.singlestep_enabled = env.singlestep_enabled;
    dc.condjmp = 0;
    dc.thumb = env.thumb;
    dc.condexec_mask = (env.condexec_bits & 0xf) << 1;
    dc.condexec_cond = env.condexec_bits >> 4;
    dc.is_mem = 0;

    if (arm_feature(env, ARM_FEATURE_M)) {
        dc.user = ((env.v7m.exception == 0) && (env.v7m.control & 1));
    } else {
        dc.user = (env.uncached_cpsr & 0x1f) == ARM_CPU_MODE_USR;
    }

    next_page_start = (pc_start & ~((1 << 10) - 1)) + (1 << 10);
    //nb_gen_labels = 0;
    lj = -1;
    /* Reset the conditional execution bits immediately. This avoids
       complications trying to do it at the end of the block.  */
    if (env.condexec_bits)
      gen_op_set_condexec(0);
    do {

        if (dc.pc >= 0xfffffff0 && arm_feature(env, ARM_FEATURE_M)) {
            /* We always get here via a jump, so know we are not in a
               conditional execution block.  */
            gen_op_exception_exit();
        }

        /*
        if (env.nb_breakpoints > 0) {
            for(j = 0; j < env.nb_breakpoints; j++) {
                if (cpu_single_env.breakpoints[j] == dc.pc) {
                    gen_set_condexec(dc);
                    gen_op_movl_T0_im((long)dc.pc);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_debug();
                    dc.is_jmp = 1;
                    // Advance PC so that clearing the breakpoint will
                    //   invalidate this TB.  
                    dc.pc += 2;
                    goto done_generating;
                    break;
                }
            }
        }
        */
       /*
        if (search_pc) {
            j = gen_opc_ptr - gen_opc_buf;
            if (lj < j) {
                lj++;
                while (lj < j)
                    gen_opc_instr_start[lj++] = 0;
            }
            gen_opc_pc[lj] = dc.pc;
            gen_opc_instr_start[lj] = 1;
        }
        */
        if (env.thumb) {
            disas_thumb_insn(env, dc);
            if (dc.condexec_mask) {
                dc.condexec_cond = (dc.condexec_cond & 0xe)
                                   | ((dc.condexec_mask >> 4) & 1);
                dc.condexec_mask = (dc.condexec_mask << 1) & 0x1f;
                if (dc.condexec_mask == 0) {
                    dc.condexec_cond = 0;
                }
            }
        } else {
            disas_arm_insn(env, dc);
        }
        if (dc.condjmp && !dc.is_jmp) {
            gen_set_label(dc.condlabel, dc.tb.tc_ptr);
            dc.condjmp = 0;
        }
        /* Terminate the TB on memory ops if watchpoints are present.  */
        /* FIXME: This should be replacd by the deterministic execution
         * IRQ raising bits.  */
        //if (dc.is_mem && env.nb_watchpoints)
        //    break;

        /* Translation stops when a conditional branch is enoutered.
         * Otherwise the subsequent code could get translated several times.
         * Also stop translation when a page boundary is reached.  This
         * ensures prefech aborts occur at the right place.  */
    } while (!dc.is_jmp && /* gen_opc_ptr < gen_opc_end &&
             !env.singlestep_enabled && */ dc.pc < next_page_start);

    /* At this stage dc.condjmp will only be set when the skipped
       instruction was a conditional branch or trap, and the PC has
       already been written.  */
    if (env.singlestep_enabled == 0) {
        /* Make sure the pc is updated, and raise a debug exception.  */
        if (dc.condjmp) {
            gen_set_condexec(dc);
            if (dc.is_jmp == 5) {
                gen_op_swi();
            } else {
                gen_op_debug();
            }
            gen_set_label(dc.condlabel, dc.tb.tc_ptr);
        }
        if (dc.condjmp || !dc.is_jmp) {
            gen_op_movl_T0_im(dc.pc);
            gen_op_movl_reg_TN[0][15]();
            dc.condjmp = 0;
        }
        gen_set_condexec(dc);
        if (dc.is_jmp == 5 && !dc.condjmp) {
            gen_op_swi();
        } else {
            /* FIXME: Single stepping a WFI insn will not halt
               the CPU.  */
            gen_op_debug();
        }
    } else {
        /* While branches must always occur at the end of an IT block,
           there are a few other things that can cause us to terminate
           the TB in the middel of an IT block:
            - Exception generating instructions (bkpt, swi, undefined).
            - Page boundaries.
            - Hardware watchpoints.
           Hardware breakpoints have already been handled and skip this code.
         */
        gen_set_condexec(dc);
        switch(dc.is_jmp) {
        case 0:
            gen_goto_tb(dc, 1, dc.pc);
            break;
        default:
        case 1:
        case 2:
            /* indicate that the hash table must be used to find the next TB */
            gen_op_movl_T0_0();
            gen_op_exit_tb();
            break;
        case 3:
            /* nothing more to generate */
            break;
        case 4:
            gen_op_wfi();
            break;
        case 5:
            gen_op_swi();
            break;
        }
        if (dc.condjmp) {
            gen_set_label(dc.condlabel, dc.tb.tc_ptr);
            gen_set_condexec(dc);
            gen_goto_tb(dc, 1, dc.pc);
            dc.condjmp = 0;
        }
    }
    /* XXX: FIX ME GOTO
done_generating:
    gen_opc_ptr.push({func:op_end);
*/
    /*
    if (loglevel & (1 << 1)) {
        fprintf(logfile, "----------------\n");
        fprintf(logfile, "IN: %s\n", lookup_symbol(pc_start));
        target_disas(logfile, pc_start, dc.pc - pc_start, env.thumb);
        fprintf(logfile, "\n");
        if (loglevel & ((1 << 2))) {
            fprintf(logfile, "OP:\n");
            dump_ops(gen_opc_buf, gen_opparam_buf);
            fprintf(logfile, "\n");
        }
    }
    */
    /*
    if (search_pc) {
        j = gen_opc_ptr - gen_opc_buf;
        lj++;
        while (lj <= j)
            gen_opc_instr_start[lj++] = 0;
    } else {
    */
    gen_opc_ptr.push({func:op_end});
    tb.size = dc.pc - pc_start;
    //}
    return 0;
}

function gen_intermediate_code(/* CPUARMState * */ env, /* TranslationBlock * */ tb)
{
    return gen_intermediate_code_internal(env, tb, 0);
}

function gen_intermediate_code_pc(/* CPUARMState * */ env, /* TranslationBlock * */ tb)
{
    return gen_intermediate_code_internal(env, tb, 1);
}

/*
static const char *cpu_mode_names[16] = {
  "usr", "fiq", "irq", "svc", "???", "???", "???", "abt",
  "???", "???", "???", "und", "???", "???", "???", "sys"
};
*/

function cpu_dump_state(/* CPUARMState * */ env, /* FILE * */ f,
                   /*  int (*cpu_fprintf)(FILE *f, const char *fmt, ...)*/ fptr,
                    /*int */ flags)
{
    /*
    int i;
    union {
        uint32_t i;
        float s;
    } s0, s1;
    CPU_DoubleU d;
    // ??? This assumes float64 and double have the same layout.
    // Oh well, it's only debug dumps.  
    union {
        float64 f64;
        double d;
    } d0;
    uint32_t psr;

    for(i=0;i<16;i++) {
        cpu_fprintf(f, "R%02d=%08x", i, cpu_single_env.regs[i]);
        if ((i % 4) == 3)
            cpu_fprintf(f, "\n");
        else
            cpu_fprintf(f, " ");
    }
    psr = cpsr_read(env);
    cpu_fprintf(f, "PSR=%08x %c%c%c%c %c %s%d\n",
                psr,
                psr & (1 << 31) ? 'N' : '-',
                psr & (1 << 30) ? 'Z' : '-',
                psr & (1 << 29) ? 'C' : '-',
                psr & (1 << 28) ? 'V' : '-',
                psr & (1 << 5) ? 'T' : 'A',
                cpu_mode_names[psr & 0xf], (psr & 0x10) ? 32 : 26);

    for (i = 0; i < 16; i++) {
        d.d = env.vfp.regs[i];
        s0.i = d.l.lower;
        s1.i = d.l.upper;
        d0.f64 = d.d;
        cpu_fprintf(f, "s%02d=%08x(%8g) s%02d=%08x(%8g) d%02d=%08x%08x(%8g)\n",
                    i * 2, s0.i, s0.s,
                    i * 2 + 1, s1.i, s1.s,
                    i, d.l.upper, d.l.lower,
                    d0.d);
    }
    cpu_fprintf(f, "FPSCR: %08x\n", (int)env.vfp.xregs[1]);
    */
}
function disas_arm_insn(/* CPUARMState * */env, /* DisasContext * */s)
{
    var /* unsigned int*/ cond, insn, val, op1, i, shift, rm, rs, rn, rd, sh;

    insn = ldl_code(s.pc) >>> 0;
    s.pc += 4;

    console.log("disas_arm_insn 0x" + insn.toString(16));
    /* M variants do not implement ARM mode.  */
    if (arm_feature(env, ARM_FEATURE_M))
    {
        gen_set_condexec(s);
        gen_op_movl_T0_im(/*(long) */s.pc - 4);
        gen_op_movl_reg_TN[0][15]();
        gen_op_undef_insn();
        s.is_jmp = 1;
        return;
       
    }
    cond = insn >>> 28;
    if (cond == 0xf){
        /* Unconditional instructions.  */
        if (((insn >> 25) & 7) == 1) {
            /* NEON Data processing.  */
            if (!arm_feature(env, ARM_FEATURE_NEON))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }

            if (disas_neon_data_insn(env, s, insn))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            return;
        }
        if ((insn & 0x0f100000) == 0x04000000) {
            /* NEON load/store.  */
            if (!arm_feature(env, ARM_FEATURE_NEON))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }

            if (disas_neon_ls_insn(env, s, insn))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            return;
        }
        if ((insn & 0x0d70f000) == 0x0550f000)
            return; /* PLD */
        else if ((insn & 0x0ffffdff) == 0x01010000) {
            if (!arm_feature(env, ARM_FEATURE_V6))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            /* setend */
            if (insn & (1 << 9)) {
                /* BE8 mode not implemented.  */
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            }
            return;
        } else if ((insn & 0x0fffff00) == 0x057ff000) {
            switch ((insn >> 4) & 0xf) {
            case 1: /* clrex */
                if (!arm_feature(env, ARM_FEATURE_V6K))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
                gen_op_clrex();
                return;
            case 4: /* dsb */
            case 5: /* dmb */
            case 6: /* isb */
                if (!arm_feature(env, ARM_FEATURE_V7))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
                /* We don't emulate caches so these are a no-op.  */
                return;
            default:
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            }
        } else if ((insn & 0x0e5fffe0) == 0x084d0500) {
            /* srs */
            var /* uint32_t*/ offset;
            if ((s.user))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            if (!arm_feature(env, ARM_FEATURE_V6))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            op1 = (insn & 0x1f);
            if (op1 == (env.uncached_cpsr & (0x1f))) {
                gen_movl_T1_reg(s, 13);
            } else {
                gen_op_movl_T1_r13_banked(op1);
            }
            i = (insn >> 23) & 3;
            switch (i) {
            case 0: offset = -4; break; /* DA */
            case 1: offset = -8; break; /* DB */
            case 2: offset = 0; break; /* IA */
            case 3: offset = 4; break; /* IB */
            default: abort();
            }
            if (offset)
                gen_op_addl_T1_im(offset);
            gen_movl_T0_reg(s, 14);
            do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
            gen_op_movl_T0_cpsr();
            gen_op_addl_T1_im(4);
            do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
            if (insn & (1 << 21)) {
                /* Base writeback.  */
                switch (i) {
                case 0: offset = -8; break;
                case 1: offset = -4; break;
                case 2: offset = 4; break;
                case 3: offset = 0; break;
                default: abort();
                }
                if (offset)
                    gen_op_addl_T1_im(offset);
                if (op1 == (env.uncached_cpsr & (0x1f))) {
                    gen_movl_reg_T1(s, 13);
                } else {
                    gen_op_movl_r13_T1_banked(op1);
                }
            }
        } else if ((insn & 0x0e5fffe0) == 0x081d0a00) {
            /* rfe */
            var /* uint32_t*/ offset;
            if ((s.user))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            if (!arm_feature(env, ARM_FEATURE_V6))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            rn = (insn >> 16) & 0xf;
            gen_movl_T1_reg(s, rn);
            i = (insn >> 23) & 3;
            switch (i) {
            case 0: offset = 0; break; /* DA */
            case 1: offset = -4; break; /* DB */
            case 2: offset = 4; break; /* IA */
            case 3: offset = 8; break; /* IB */
            default: abort();
            }
            if (offset)
                gen_op_addl_T1_im(offset);
            /* Load CPSR into T2 and PC into T0.  */
            do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
            gen_op_movl_T2_T0();
            gen_op_addl_T1_im(-4);
            do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
            if (insn & (1 << 21)) {
                /* Base writeback.  */
                switch (i) {
                case 0: offset = -4; break;
                case 1: offset = 0; break;
                case 2: offset = 8; break;
                case 3: offset = 4; break;
                default: abort();
                }
                if (offset)
                    gen_op_addl_T1_im(offset);
                gen_movl_reg_T1(s, rn);
            }
            gen_rfe(s);
        } else if ((insn & 0x0e000000) == 0x0a000000) {
            /* branch link and change to thumb (blx <offset>) */
            var /* int32_t */ offset;

            val =  s.pc;
            gen_op_movl_T0_im(val);
            gen_movl_reg_T0(s, 14);
            /* Sign-extend the 24-bit offset */
            offset = ((insn) << 8) >> 8;
            /* offset * 4 + bit24 * 2 + (thumb bit) */
            val += (offset << 2) | ((insn >> 23) & 2) | 1;
            /* pipeline offset */
            val += 4;
            gen_op_movl_T0_im(val);
            gen_bx(s);
            return;
        } else if ((insn & 0x0e000f00) == 0x0c000100) {
            if (arm_feature(env, ARM_FEATURE_IWMMXT)) {
                /* iWMMXt register transfer.  */
                if (env.cp15.c15_cpar & (1 << 1))
                    if (!disas_iwmmxt_insn(env, s, insn))
                        return;
            }
        } else if ((insn & 0x0fe00000) == 0x0c400000) {
            /* Coprocessor double register transfer.  */
        } else if ((insn & 0x0f000010) == 0x0e000010) {
            /* Additional coprocessor register transfer.  */
        } else if ((insn & 0x0ff10010) == 0x01000000) {
            var /* uint32_t*/ mask;
            var /* uint32_t */val;
            /* cps (privileged) */
            if ((s.user))
                return;
            mask = val = 0;
            if (insn & (1 << 19)) {
                if (insn & (1 << 8))
                    mask |= (1 << 8);
                if (insn & (1 << 7))
                    mask |= (1 << 7);
                if (insn & (1 << 6))
                    mask |= (1 << 6);
                if (insn & (1 << 18))
                    val |= mask;
            }
            if (insn & (1 << 14)) {
                mask |= (0x1f);
                val |= (insn & 0x1f);
            }
            if (mask) {
                gen_op_movl_T0_im(val);
                gen_set_psr_T0(s, mask, 0);
            }
            return;
        }
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
    }
    if (cond != 0xe) {
        /* if not always execute, we generate a conditional jump to
           next instruction */
        s.condlabel = gen_new_label();
        gen_test_cc[cond ^ 1](s.condlabel);
        s.condjmp = 1;
    }
    if ((insn & 0x0f900000) == 0x03000000) {
        if ((insn & (1 << 21)) == 0) {
            if (!arm_feature(env, ARM_FEATURE_THUMB2))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            rd = (insn >> 12) & 0xf;
            val = ((insn >> 4) & 0xf000) | (insn & 0xfff);
            if ((insn & (1 << 22)) == 0) {
                /* MOVW */
                gen_op_movl_T0_im(val);
            } else {
                /* MOVT */
                gen_movl_T0_reg(s, rd);
                gen_op_movl_T1_im(0xffff);
                gen_op_andl_T0_T1();
                gen_op_movl_T1_im(val << 16);
                gen_op_orl_T0_T1();
            }
            gen_movl_reg_T0(s, rd);
        } else {
            if (((insn >> 12) & 0xf) != 0xf)
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            if (((insn >> 16) & 0xf) == 0) {
                gen_nop_hint(s, insn & 0xff);
            } else {
                /* CPSR = immediate */
                val = insn & 0xff;
                shift = ((insn >> 8) & 0xf) * 2;
                if (shift)
                    val = (val >> shift) | (val << (32 - shift));
                gen_op_movl_T0_im(val);
                i = ((insn & (1 << 22)) != 0);
                if (gen_set_psr_T0(s, msr_mask(env, s, (insn >> 16) & 0xf, i), i))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            }
        }
    } else if ((insn & 0x0f900000) == 0x01000000
               && (insn & 0x00000090) != 0x00000090) {
        /* miscellaneous instructions */
        op1 = (insn >> 21) & 3;
        sh = (insn >> 4) & 0xf;
        rm = insn & 0xf;
        switch (sh) {
        case 0x0: /* move program status register */
            if (op1 & 1) {
                /* PSR = reg */
                gen_movl_T0_reg(s, rm);
                i = ((op1 & 2) != 0);
                if (gen_set_psr_T0(s, msr_mask(env, s, (insn >> 16) & 0xf, i), i))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
            } else {
                /* reg = PSR */
                rd = (insn >> 12) & 0xf;
                if (op1 & 2) {
                    if ((s.user))
                            {
                                gen_set_condexec(s);
                                gen_op_movl_T0_im(/*(long) */s.pc - 4);
                                gen_op_movl_reg_TN[0][15]();
                                gen_op_undef_insn();
                                s.is_jmp = 1;
                                return;
                               
                            }
                    gen_op_movl_T0_spsr();
                } else {
                    gen_op_movl_T0_cpsr();
                }
                gen_movl_reg_T0(s, rd);
            }
            break;
        case 0x1:
            if (op1 == 1) {
                /* branch/exchange thumb (bx).  */
                gen_movl_T0_reg(s, rm);
                gen_bx(s);
            } else if (op1 == 3) {
                /* clz */
                rd = (insn >> 12) & 0xf;
                gen_movl_T0_reg(s, rm);
                gen_op_clz_T0();
                gen_movl_reg_T0(s, rd);
            } else {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
            }
            break;
        case 0x2:
            if (op1 == 1) {
                if (!0)
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
                /* Trivial implementation equivalent to bx.  */
                gen_movl_T0_reg(s, rm);
                gen_bx(s);
            } else {
            {
                gen_set_condexec(s);
                gen_op_movl_T0_im(/*(long) */s.pc - 4);
                gen_op_movl_reg_TN[0][15]();
                gen_op_undef_insn();
                s.is_jmp = 1;
                return;
               
            }
            }
            break;
        case 0x3:
            if (op1 != 1)
            {
                gen_set_condexec(s);
                gen_op_movl_T0_im(/*(long) */s.pc - 4);
                gen_op_movl_reg_TN[0][15]();
                gen_op_undef_insn();
                s.is_jmp = 1;
                return;
               
            }

            /* branch link/exchange thumb (blx) */
            val =  s.pc;
            gen_op_movl_T1_im(val);
            gen_movl_T0_reg(s, rm);
            gen_movl_reg_T1(s, 14);
            gen_bx(s);
            break;
        case 0x5: /* saturating add/subtract */
            rd = (insn >> 12) & 0xf;
            rn = (insn >> 16) & 0xf;
            gen_movl_T0_reg(s, rm);
            gen_movl_T1_reg(s, rn);
            if (op1 & 2)
                gen_op_double_T1_saturate();
            if (op1 & 1)
                gen_op_subl_T0_T1_saturate();
            else
                gen_op_addl_T0_T1_saturate();
            gen_movl_reg_T0(s, rd);
            break;
        case 7: /* bkpt */
            gen_set_condexec(s);
            gen_op_movl_T0_im(/* (long)*/s.pc - 4);
            gen_op_movl_reg_TN[0][15]();
            gen_op_bkpt();
            s.is_jmp = 1;
            break;
        case 0x8: /* signed multiply */
        case 0xa:
        case 0xc:
        case 0xe:
            rs = (insn >> 8) & 0xf;
            rn = (insn >> 12) & 0xf;
            rd = (insn >> 16) & 0xf;
            if (op1 == 1) {
                /* (32 * 16) >> 16 */
                gen_movl_T0_reg(s, rm);
                gen_movl_T1_reg(s, rs);
                if (sh & 4)
                    gen_op_sarl_T1_im(16);
                else
                    gen_op_sxth_T1();
                gen_op_imulw_T0_T1();
                if ((sh & 2) == 0) {
                    gen_movl_T1_reg(s, rn);
                    gen_op_addl_T0_T1_setq();
                }
                gen_movl_reg_T0(s, rd);
            } else {
                /* 16 * 16 */
                gen_movl_T0_reg(s, rm);
                gen_movl_T1_reg(s, rs);
                gen_mulxy(sh & 2, sh & 4);
                if (op1 == 2) {
                    gen_op_signbit_T1_T0();
                    gen_op_addq_T0_T1(rn, rd);
                    gen_movl_reg_T0(s, rn);
                    gen_movl_reg_T1(s, rd);
                } else {
                    if (op1 == 0) {
                        gen_movl_T1_reg(s, rn);
                        gen_op_addl_T0_T1_setq();
                    }
                    gen_movl_reg_T0(s, rd);
                }
            }
            break;
        default:
        {
            gen_set_condexec(s);
            gen_op_movl_T0_im(/*(long) */s.pc - 4);
            gen_op_movl_reg_TN[0][15]();
            gen_op_undef_insn();
            s.is_jmp = 1;
            return;
           
        }
        }
    } else if (((insn & 0x0e000000) == 0 &&
                (insn & 0x00000090) != 0x90) ||
               ((insn & 0x0e000000) == (1 << 25))) {
        var set_cc, logic_cc, shiftop;

        op1 = (insn >> 21) & 0xf;
        set_cc = (insn >> 20) & 1;
        logic_cc = table_logic_cc[op1] & set_cc;

        /* data processing instruction */
        if (insn & (1 << 25)) {
            /* immediate operand */
            val = insn & 0xff;
            shift = ((insn >> 8) & 0xf) * 2;
            if (shift)
                val = (val >> shift) | (val << (32 - shift));
            gen_op_movl_T1_im(val);
            if (logic_cc && shift)
                gen_op_mov_CF_T1();
        } else {
            /* register */
            rm = (insn) & 0xf;
            gen_movl_T1_reg(s, rm);
            shiftop = (insn >> 5) & 3;
            if (!(insn & (1 << 4))) {
                shift = (insn >> 7) & 0x1f;
                if (shift != 0) {
                    if (logic_cc) {
                        gen_shift_T1_im_cc[shiftop](shift);
                    } else {
                        gen_shift_T1_im[shiftop](shift);
                    }
                } else if (shiftop != 0) {
                    if (logic_cc) {
                        gen_shift_T1_0_cc[shiftop]();
                    } else {
                        gen_shift_T1_0[shiftop]();
                    }
                }
            } else {
                rs = (insn >> 8) & 0xf;
                gen_movl_T0_reg(s, rs);
                if (logic_cc) {
                    gen_shift_T1_T0_cc[shiftop]();
                } else {
                    gen_shift_T1_T0[shiftop]();
                }
            }
        }
        if (op1 != 0x0f && op1 != 0x0d) {
            rn = (insn >> 16) & 0xf;
            gen_movl_T0_reg(s, rn);
        }
        rd = (insn >> 12) & 0xf;
        switch(op1) {
        case 0x00:
            gen_op_andl_T0_T1();
            gen_movl_reg_T0(s, rd);
            if (logic_cc)
                gen_op_logic_T0_cc();
            break;
        case 0x01:
            gen_op_xorl_T0_T1();
            gen_movl_reg_T0(s, rd);
            if (logic_cc)
                gen_op_logic_T0_cc();
            break;
        case 0x02:
            if (set_cc && rd == 15) {
                /* SUBS r15, ... is used for exception return.  */
                if ((s.user))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
                gen_op_subl_T0_T1_cc();
                gen_exception_return(s);
            } else {
                if (set_cc)
                    gen_op_subl_T0_T1_cc();
                else
                    gen_op_subl_T0_T1();
                gen_movl_reg_T0(s, rd);
            }
            break;
        case 0x03:
            if (set_cc)
                gen_op_rsbl_T0_T1_cc();
            else
                gen_op_rsbl_T0_T1();
            gen_movl_reg_T0(s, rd);
            break;
        case 0x04:
            if (set_cc)
                gen_op_addl_T0_T1_cc();
            else
                gen_op_addl_T0_T1();
            gen_movl_reg_T0(s, rd);
            break;
        case 0x05:
            if (set_cc)
                gen_op_adcl_T0_T1_cc();
            else
                gen_op_adcl_T0_T1();
            gen_movl_reg_T0(s, rd);
            break;
        case 0x06:
            if (set_cc)
                gen_op_sbcl_T0_T1_cc();
            else
                gen_op_sbcl_T0_T1();
            gen_movl_reg_T0(s, rd);
            break;
        case 0x07:
            if (set_cc)
                gen_op_rscl_T0_T1_cc();
            else
                gen_op_rscl_T0_T1();
            gen_movl_reg_T0(s, rd);
            break;
        case 0x08:
            if (set_cc) {
                gen_op_andl_T0_T1();
                gen_op_logic_T0_cc();
            }
            break;
        case 0x09:
            if (set_cc) {
                gen_op_xorl_T0_T1();
                gen_op_logic_T0_cc();
            }
            break;
        case 0x0a:
            if (set_cc) {
                gen_op_subl_T0_T1_cc();
            }
            break;
        case 0x0b:
            if (set_cc) {
                gen_op_addl_T0_T1_cc();
            }
            break;
        case 0x0c:
            gen_op_orl_T0_T1();
            gen_movl_reg_T0(s, rd);
            if (logic_cc)
                gen_op_logic_T0_cc();
            break;
        case 0x0d:
            if (logic_cc && rd == 15) {
                /* MOVS r15, ... is used for exception return.  */
                if ((s.user))
                {
                        gen_set_condexec(s);
                        gen_op_movl_T0_im(/*(long) */s.pc - 4);
                        gen_op_movl_reg_TN[0][15]();
                        gen_op_undef_insn();
                        s.is_jmp = 1;
                        return;
                       
                }
                gen_op_movl_T0_T1();
                gen_exception_return(s);
            } else {
                gen_movl_reg_T1(s, rd);
                if (logic_cc)
                    gen_op_logic_T1_cc();
            }
            break;
        case 0x0e:
            gen_op_bicl_T0_T1();
            gen_movl_reg_T0(s, rd);
            if (logic_cc)
                gen_op_logic_T0_cc();
            break;
        default:
        case 0x0f:
            gen_op_notl_T1();
            gen_movl_reg_T1(s, rd);
            if (logic_cc)
                gen_op_logic_T1_cc();
            break;
        }
    } else {
        /* other instructions */
        op1 = (insn >> 24) & 0xf;
        switch(op1) {
        case 0x0:
        case 0x1:
            /* multiplies, extra load/stores */
            sh = (insn >> 5) & 3;
            if (sh == 0) {
                if (op1 == 0x0) {
                    rd = (insn >> 16) & 0xf;
                    rn = (insn >> 12) & 0xf;
                    rs = (insn >> 8) & 0xf;
                    rm = (insn) & 0xf;
                    op1 = (insn >> 20) & 0xf;
                    switch (op1) {
                    case 0: case 1: case 2: case 3: case 6:
                        /* 32 bit mul */
                        gen_movl_T0_reg(s, rs);
                        gen_movl_T1_reg(s, rm);
                        gen_op_mul_T0_T1();
                        if (insn & (1 << 22)) {
                            /* Subtract (mls) */
                            if (!arm_feature(env, ARM_FEATURE_THUMB2))
                            {
                                gen_set_condexec(s);
                                gen_op_movl_T0_im(/*(long) */s.pc - 4);
                                gen_op_movl_reg_TN[0][15]();
                                gen_op_undef_insn();
                                s.is_jmp = 1;
                                return;
                               
                            }
                            gen_movl_T1_reg(s, rn);
                            gen_op_rsbl_T0_T1();
                        } else if (insn & (1 << 21)) {
                            /* Add */
                            gen_movl_T1_reg(s, rn);
                            gen_op_addl_T0_T1();
                        }
                        if (insn & (1 << 20))
                            gen_op_logic_T0_cc();
                        gen_movl_reg_T0(s, rd);
                        break;
                    default:
                        /* 64 bit mul */
                        gen_movl_T0_reg(s, rs);
                        gen_movl_T1_reg(s, rm);
                        if (insn & (1 << 22))
                            gen_op_imull_T0_T1();
                        else
                            gen_op_mull_T0_T1();
                        if (insn & (1 << 21)) /* mult accumulate */
                            gen_op_addq_T0_T1(rn, rd);
                        if (!(insn & (1 << 23))) { /* double accumulate */
                            if (!arm_feature(env, ARM_FEATURE_V6))
                            {
                                gen_set_condexec(s);
                                gen_op_movl_T0_im(/*(long) */s.pc - 4);
                                gen_op_movl_reg_TN[0][15]();
                                gen_op_undef_insn();
                                s.is_jmp = 1;
                                return;
                               
                            }
                            gen_op_addq_lo_T0_T1(rn);
                            gen_op_addq_lo_T0_T1(rd);
                        }
                        if (insn & (1 << 20))
                            gen_op_logicq_cc();
                        gen_movl_reg_T0(s, rn);
                        gen_movl_reg_T1(s, rd);
                        break;
                    }
                } else {
                    rn = (insn >> 16) & 0xf;
                    rd = (insn >> 12) & 0xf;
                    if (insn & (1 << 23)) {
                        /* load/store exclusive */
                        gen_movl_T1_reg(s, rn);
                        if (insn & (1 << 20)) {
                            do { s.is_mem = 1; if ((s.user)) gen_op_ldlex_user(); else gen_op_ldlex_kernel(); } while (0);
                        } else {
                            rm = insn & 0xf;
                            gen_movl_T0_reg(s, rm);
                            do { s.is_mem = 1; if ((s.user)) gen_op_stlex_user(); else gen_op_stlex_kernel(); } while (0);
                        }
                        gen_movl_reg_T0(s, rd);
                    } else {
                        /* SWP instruction */
                        rm = (insn) & 0xf;

                        gen_movl_T0_reg(s, rm);
                        gen_movl_T1_reg(s, rn);
                        if (insn & (1 << 22)) {
                            do { s.is_mem = 1; if ((s.user)) gen_op_swpb_user(); else gen_op_swpb_kernel(); } while (0);
                        } else {
                            do { s.is_mem = 1; if ((s.user)) gen_op_swpl_user(); else gen_op_swpl_kernel(); } while (0);
                        }
                        gen_movl_reg_T0(s, rd);
                    }
                }
            } else {
                var address_offset;
                var load;
                /* Misc load/store */
                rn = (insn >> 16) & 0xf;
                rd = (insn >> 12) & 0xf;
                gen_movl_T1_reg(s, rn);
                if (insn & (1 << 24))
                    gen_add_datah_offset(s, insn, 0);
                address_offset = 0;
                if (insn & (1 << 20)) {
                    /* load */
                    switch(sh) {
                    case 1:
                        do { s.is_mem = 1; if ((s.user)) gen_op_lduw_user(); else gen_op_lduw_kernel(); } while (0);
                        break;
                    case 2:
                        do { s.is_mem = 1; if ((s.user)) gen_op_ldsb_user(); else gen_op_ldsb_kernel(); } while (0);
                        break;
                    default:
                    case 3:
                        do { s.is_mem = 1; if ((s.user)) gen_op_ldsw_user(); else gen_op_ldsw_kernel(); } while (0);
                        break;
                    }
                    load = 1;
                } else if (sh & 2) {
                    /* doubleword */
                    if (sh & 1) {
                        /* store */
                        gen_movl_T0_reg(s, rd);
                        do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                        gen_op_addl_T1_im(4);
                        gen_movl_T0_reg(s, rd + 1);
                        do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                        load = 0;
                    } else {
                        /* load */
                        do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                        gen_movl_reg_T0(s, rd);
                        gen_op_addl_T1_im(4);
                        do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                        rd++;
                        load = 1;
                    }
                    address_offset = -4;
                } else {
                    /* store */
                    gen_movl_T0_reg(s, rd);
                    do { s.is_mem = 1; if ((s.user)) gen_op_stw_user(); else gen_op_stw_kernel(); } while (0);
                    load = 0;
                }
                /* Perform base writeback before the loaded value to
                   ensure correct behavior with overlapping index registers.
                   ldrd with base writeback is is undefined if the
                   destination and index registers overlap.  */
                if (!(insn & (1 << 24))) {
                    gen_add_datah_offset(s, insn, address_offset);
                    gen_movl_reg_T1(s, rn);
                } else if (insn & (1 << 21)) {
                    if (address_offset)
                        gen_op_addl_T1_im(address_offset);
                    gen_movl_reg_T1(s, rn);
                }
                if (load) {
                    /* Complete the load.  */
                    gen_movl_reg_T0(s, rd);
                }
            }
            break;
        case 0x6:
        case 0x7:
            if (insn & (1 << 4)) {
                if (!arm_feature(env, ARM_FEATURE_V6))
                {
                    gen_set_condexec(s);
                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                    gen_op_movl_reg_TN[0][15]();
                    gen_op_undef_insn();
                    s.is_jmp = 1;
                    return;
                   
                }
                /* Armv6 Media instructions.  */
                rm = insn & 0xf;
                rn = (insn >> 16) & 0xf;
                rd = (insn >> 12) & 0xf;
                rs = (insn >> 8) & 0xf;
                switch ((insn >> 23) & 3) {
                case 0: /* Parallel add/subtract.  */
                    op1 = (insn >> 20) & 7;
                    gen_movl_T0_reg(s, rn);
                    gen_movl_T1_reg(s, rm);
                    sh = (insn >> 5) & 7;
                    if ((op1 & 3) == 0 || sh == 5 || sh == 6)
                        {
                            gen_set_condexec(s);
                            gen_op_movl_T0_im(/*(long) */s.pc - 4);
                            gen_op_movl_reg_TN[0][15]();
                            gen_op_undef_insn();
                            s.is_jmp = 1;
                            return;
                           
                        }
                    gen_arm_parallel_addsub[op1][sh]();
                    gen_movl_reg_T0(s, rd);
                    break;
                case 1:
                    if ((insn & 0x00700020) == 0) {
                        /* Hafword pack.  */
                        gen_movl_T0_reg(s, rn);
                        gen_movl_T1_reg(s, rm);
                        shift = (insn >> 7) & 0x1f;
                        if (shift)
                            gen_op_shll_T1_im(shift);
                        if (insn & (1 << 6))
                            gen_op_pkhtb_T0_T1();
                        else
                            gen_op_pkhbt_T0_T1();
                        gen_movl_reg_T0(s, rd);
                    } else if ((insn & 0x00200020) == 0x00200000) {
                        /* [us]sat */
                        gen_movl_T1_reg(s, rm);
                        shift = (insn >> 7) & 0x1f;
                        if (insn & (1 << 6)) {
                            if (shift == 0)
                                shift = 31;
                            gen_op_sarl_T1_im(shift);
                        } else {
                            gen_op_shll_T1_im(shift);
                        }
                        sh = (insn >> 16) & 0x1f;
                        if (sh != 0) {
                            if (insn & (1 << 22))
                                gen_op_usat_T1(sh);
                            else
                                gen_op_ssat_T1(sh);
                        }
                        gen_movl_T1_reg(s, rd);
                    } else if ((insn & 0x00300fe0) == 0x00200f20) {
                        /* [us]sat16 */
                        gen_movl_T1_reg(s, rm);
                        sh = (insn >> 16) & 0x1f;
                        if (sh != 0) {
                            if (insn & (1 << 22))
                                gen_op_usat16_T1(sh);
                            else
                                gen_op_ssat16_T1(sh);
                        }
                        gen_movl_T1_reg(s, rd);
                    } else if ((insn & 0x00700fe0) == 0x00000fa0) {
                        /* Select bytes.  */
                        gen_movl_T0_reg(s, rn);
                        gen_movl_T1_reg(s, rm);
                        gen_op_sel_T0_T1();
                        gen_movl_reg_T0(s, rd);
                    } else if ((insn & 0x000003e0) == 0x00000060) {
                        gen_movl_T1_reg(s, rm);
                        shift = (insn >> 10) & 3;
                        /* ??? In many cases it's not neccessary to do a
                           rotate, a shift is sufficient.  */
                        if (shift != 0)
                            gen_op_rorl_T1_im(shift * 8);
                        op1 = (insn >> 20) & 7;
                        switch (op1) {
                        case 0: gen_op_sxtb16_T1(); break;
                        case 2: gen_op_sxtb_T1(); break;
                        case 3: gen_op_sxth_T1(); break;
                        case 4: gen_op_uxtb16_T1(); break;
                        case 6: gen_op_uxtb_T1(); break;
                        case 7: gen_op_uxth_T1(); break;
                        default:
                         {
                            gen_set_condexec(s);
                            gen_op_movl_T0_im(/*(long) */s.pc - 4);
                            gen_op_movl_reg_TN[0][15]();
                            gen_op_undef_insn();
                            s.is_jmp = 1;
                            return;
                           
                          }
                        }
                        if (rn != 15) {
                            gen_movl_T2_reg(s, rn);
                            if ((op1 & 3) == 0) {
                                gen_op_add16_T1_T2();
                            } else {
                                gen_op_addl_T1_T2();
                            }
                        }
                        gen_movl_reg_T1(s, rd);
                    } else if ((insn & 0x003f0f60) == 0x003f0f20) {
                        /* rev */
                        gen_movl_T0_reg(s, rm);
                        if (insn & (1 << 22)) {
                            if (insn & (1 << 7)) {
                                gen_op_revsh_T0();
                            } else {
                                if (!arm_feature(env, ARM_FEATURE_THUMB2))
                                {
                                    gen_set_condexec(s);
                                    gen_op_movl_T0_im(/*(long) */s.pc - 4);
                                    gen_op_movl_reg_TN[0][15]();
                                    gen_op_undef_insn();
                                    s.is_jmp = 1;
                                    return;
                                   
                                 }
                                gen_op_rbit_T0();
                            }
                        } else {
                            if (insn & (1 << 7))
                                gen_op_rev16_T0();
                            else
                                gen_op_rev_T0();
                        }
                        gen_movl_reg_T0(s, rd);
                    } else {
                        {
                            gen_set_condexec(s);
                            gen_op_movl_T0_im(/*(long) */s.pc - 4);
                            gen_op_movl_reg_TN[0][15]();
                            gen_op_undef_insn();
                            s.is_jmp = 1;
                            return;
                           
                        }
                    }
                    break;
                case 2: /* Multiplies (Type 3).  */
                    gen_movl_T0_reg(s, rm);
                    gen_movl_T1_reg(s, rs);
                    if (insn & (1 << 20)) {
                        /* Signed multiply most significant [accumulate].  */
                        gen_op_imull_T0_T1();
                        if (insn & (1 << 5))
                            gen_op_roundqd_T0_T1();
                        else
                            gen_op_movl_T0_T1();
                        if (rn != 15) {
                            gen_movl_T1_reg(s, rn);
                            if (insn & (1 << 6)) {
                                gen_op_addl_T0_T1();
                            } else {
                                gen_op_rsbl_T0_T1();
                            }
                        }
                        gen_movl_reg_T0(s, rd);
                    } else {
                        if (insn & (1 << 5))
                            gen_op_swap_half_T1();
                        gen_op_mul_dual_T0_T1();
                        if (insn & (1 << 22)) {
                            if (insn & (1 << 6)) {
                                /* smlald */
                                gen_op_addq_T0_T1_dual(rn, rd);
                            } else {
                                /* smlsld */
                                gen_op_subq_T0_T1_dual(rn, rd);
                            }
                        } else {
                            /* This addition cannot overflow.  */
                            if (insn & (1 << 6)) {
                                /* sm[ul]sd */
                                gen_op_subl_T0_T1();
                            } else {
                                /* sm[ul]ad */
                                gen_op_addl_T0_T1();
                            }
                            if (rn != 15)
                              {
                                gen_movl_T1_reg(s, rn);
                                gen_op_addl_T0_T1_setq();
                              }
                            gen_movl_reg_T0(s, rd);
                        }
                    }
                    break;
                case 3:
                    op1 = ((insn >> 17) & 0x38) | ((insn >> 5) & 7);
                    switch (op1) {
                    case 0: /* Unsigned sum of absolute differences.  */
                        {
                            gen_set_condexec(s);
                            gen_op_movl_T0_im(/*(long) */s.pc - 4);
                            gen_op_movl_reg_TN[0][15]();
                            gen_op_undef_insn();
                            s.is_jmp = 1;
                            return;
                           
                        }
                        gen_movl_T0_reg(s, rm);
                        gen_movl_T1_reg(s, rs);
                        gen_op_usad8_T0_T1();
                        if (rn != 15) {
                            gen_movl_T1_reg(s, rn);
                            gen_op_addl_T0_T1();
                        }
                        gen_movl_reg_T0(s, rd);
                        break;
                    case 0x20: case 0x24: case 0x28: case 0x2c:
                        /* Bitfield insert/clear.  */
                        if (!arm_feature(env, ARM_FEATURE_THUMB2)) 
                        {
                            gen_set_condexec(s);
                            gen_op_movl_T0_im(/*(long) */s.pc - 4);
                            gen_op_movl_reg_TN[0][15]();
                            gen_op_undef_insn();
                            s.is_jmp = 1;
                            return;
                           
                        }
                        shift = (insn >> 7) & 0x1f;
                        i = (insn >> 16) & 0x1f;
                        i = i + 1 - shift;
                        if (rm == 15) {
                            gen_op_movl_T1_im(0);
                        } else {
                            gen_movl_T1_reg(s, rm);
                        }
                        if (i != 32) {
                            gen_movl_T0_reg(s, rd);
                            gen_op_bfi_T1_T0(shift, ((1 /* u */ << i) - 1) << shift);
                        }
                        gen_movl_reg_T1(s, rd);
                        break;
                    case 0x12: case 0x16: case 0x1a: case 0x1e: /* sbfx */
                    case 0x32: case 0x36: case 0x3a: case 0x3e: /* ubfx */
                        gen_movl_T1_reg(s, rm);
                        shift = (insn >> 7) & 0x1f;
                        i = ((insn >> 16) & 0x1f) + 1;
                        if (shift + i > 32)
                        {
                            gen_set_condexec(s);
                            gen_op_movl_T0_im(/*(long) */s.pc - 4);
                            gen_op_movl_reg_TN[0][15]();
                            gen_op_undef_insn();
                            s.is_jmp = 1;
                            return;
                        }
                        if (i < 32) {
                            if (op1 & 0x20) {
                                gen_op_ubfx_T1(shift, (1 /* u */ << i) - 1);
                            } else {
                                gen_op_sbfx_T1(shift, i);
                            }
                        }
                        gen_movl_reg_T1(s, rd);
                        break;
                    default:
                    {
                            gen_set_condexec(s);
                            gen_op_movl_T0_im(/*(long) */s.pc - 4);
                            gen_op_movl_reg_TN[0][15]();
                            gen_op_undef_insn();
                            s.is_jmp = 1;
                            return;
                    }
                    }
                    break;
                }
                break;
            }
        case 0x4:
        case 0x5:
        //do_ldst:
            /* Check for undefined extension instructions
             * per the ARM Bible IE:
             * xxxx 0111 1111 xxxx  xxxx xxxx 1111 xxxx
             */
            sh = (0xf << 20) | (0xf << 4);
            if (op1 == 0x7 && ((insn & sh) == sh))
            {
                        gen_set_condexec(s);
                        gen_op_movl_T0_im(/*(long) */s.pc - 4);
                        gen_op_movl_reg_TN[0][15]();
                        gen_op_undef_insn();
                        s.is_jmp = 1;
                        return;
            }
            /* load/store byte/word */
            rn = (insn >> 16) & 0xf;
            rd = (insn >> 12) & 0xf;
            gen_movl_T1_reg(s, rn);
            i = ((s.user) || (insn & 0x01200000) == 0x00200000);
            if (insn & (1 << 24))
                gen_add_data_offset(s, insn);
            if (insn & (1 << 20)) {
                /* load */
                s.is_mem = 1;
                if (insn & (1 << 22)) {
                    if (i)
                        gen_op_ldub_user();
                    else
                        gen_op_ldub_kernel();
                } else {
                    if (i)
                        gen_op_ldl_user();
                    else
                        gen_op_ldl_kernel();
                }

            } else {
                /* store */
                gen_movl_T0_reg(s, rd);
                if (insn & (1 << 22)) {
                    if (i)
                        gen_op_stb_user();
                    else
                        gen_op_stb_kernel();
                } else {
                    if (i)
                        gen_op_stl_user();
                    else
                        gen_op_stl_kernel();
                }

            }
            if (!(insn & (1 << 24))) {
                gen_add_data_offset(s, insn);
                gen_movl_reg_T1(s, rn);
            } else if (insn & (1 << 21))
                gen_movl_reg_T1(s, rn); {
            }
            if (insn & (1 << 20)) {
                /* Complete the load.  */
                if (rd == 15)
                    gen_bx(s);
                else
                    gen_movl_reg_T0(s, rd);
            }
            break;
        case 0x08:
        case 0x09:
            {
                var j, n, user, loaded_base;
                /* load/store multiple words */
                /* XXX: store correct base if write back */
                user = 0;
                if (insn & (1 << 22)) {
                    if ((s.user))
                    {
                            gen_set_condexec(s);
                            gen_op_movl_T0_im(/*(long) */s.pc - 4);
                            gen_op_movl_reg_TN[0][15]();
                            gen_op_undef_insn();
                            s.is_jmp = 1;
                            return;
                    }
                    //goto illegal_op; /* only usable in supervisor mode */
                    if ((insn & (1 << 15)) == 0)
                        user = 1;
                }
                rn = (insn >> 16) & 0xf;
                gen_movl_T1_reg(s, rn);

                /* compute total size */
                loaded_base = 0;
                n = 0;
                for(i=0;i<16;i++) {
                    if (insn & (1 << i))
                        n++;
                }
                /* XXX: test invalid n == 0 case ? */
                if (insn & (1 << 23)) {
                    if (insn & (1 << 24)) {
                        /* pre increment */
                        gen_op_addl_T1_im(4);
                    } else {
                        /* post increment */
                    }
                } else {
                    if (insn & (1 << 24)) {
                        /* pre decrement */
                        gen_op_addl_T1_im(-(n * 4));
                    } else {
                        /* post decrement */
                        if (n != 1)
                            gen_op_addl_T1_im(-((n - 1) * 4));
                    }
                }
                j = 0;
                for(i=0;i<16;i++) {
                    if (insn & (1 << i)) {
                        if (insn & (1 << 20)) {
                            /* load */
                            do { s.is_mem = 1; if ((s.user)) gen_op_ldl_user(); else gen_op_ldl_kernel(); } while (0);
                            if (i == 15) {
                                gen_bx(s);
                            } else if (user) {
                                gen_op_movl_user_T0(i);
                            } else if (i == rn) {
                                gen_op_movl_T2_T0();
                                loaded_base = 1;
                            } else {
                                gen_movl_reg_T0(s, i);
                            }
                        } else {
                            /* store */
                            if (i == 15) {
                                /* special case: r15 = PC + 8 */
                                val =  s.pc + 4;
                                gen_op_movl_TN_im[0](val);
                            } else if (user) {
                                gen_op_movl_T0_user(i);
                            } else {
                                gen_movl_T0_reg(s, i);
                            }
                            do { s.is_mem = 1; if ((s.user)) gen_op_stl_user(); else gen_op_stl_kernel(); } while (0);
                        }
                        j++;
                        /* no need to add after the last transfer */
                        if (j != n)
                            gen_op_addl_T1_im(4);
                    }
                }
                if (insn & (1 << 21)) {
                    /* write back */
                    if (insn & (1 << 23)) {
                        if (insn & (1 << 24)) {
                            /* pre increment */
                        } else {
                            /* post increment */
                            gen_op_addl_T1_im(4);
                        }
                    } else {
                        if (insn & (1 << 24)) {
                            /* pre decrement */
                            if (n != 1)
                                gen_op_addl_T1_im(-((n - 1) * 4));
                        } else {
                            /* post decrement */
                            gen_op_addl_T1_im(-(n * 4));
                        }
                    }
                    gen_movl_reg_T1(s, rn);
                }
                if (loaded_base) {
                    gen_op_movl_T0_T2();
                    gen_movl_reg_T0(s, rn);
                }
                if ((insn & (1 << 22)) && !user) {
                    /* Restore CPSR from SPSR.  */
                    gen_op_movl_T0_spsr();
                    gen_op_movl_cpsr_T0(0xffffffff);
                    s.is_jmp = 2;
                }
            }
            break;
        case 0xa:
        case 0xb:
            {
                var/* int32_t */ offset;

                /* branch (and link) */
                val =  s.pc;
                if (insn & (1 << 24)) {
                    gen_op_movl_T0_im(val);
                    gen_op_movl_reg_TN[0][14]();
                }
                offset = (( insn << 8) >> 8);
                val += (offset << 2) + 4;
                gen_jmp(s, val);
            }
            break;
        case 0xc:
        case 0xd:
        case 0xe:
            /* Coprocessor.  */
            if (disas_coproc_insn(env, s, insn))
            {
                gen_set_condexec(s);
                gen_op_movl_T0_im(/*(long) */s.pc - 4);
                gen_op_movl_reg_TN[0][15]();
                gen_op_undef_insn();
                s.is_jmp = 1;
                return;
            }
            break;
        case 0xf:
            /* swi */
            gen_op_movl_T0_im(s.pc);
            gen_op_movl_reg_TN[0][15]();
            s.is_jmp = 5;
            break;
        default:
        //illegal_op:
            gen_set_condexec(s);
            gen_op_movl_T0_im(/*(long) */s.pc - 4);
            gen_op_movl_reg_TN[0][15]();
            gen_op_undef_insn();
            s.is_jmp = 1;
            break;
        }
    }
}


/*******************************************/
/* host CPU ticks (if available) */
/*
static __attribute__ (( always_inline )) __inline__ int64_t cpu_get_real_ticks(void)
{
    uint32_t low,high;
    int64_t val;
    asm volatile("rdtsc" : "=a" (low), "=d" (high));
    val = high;
    val <<= 32;
    val |= low;
    return val;
}
*/
/* maximum total translate dcode allocated */

/* NOTE: the translated code area cannot be too big because on some
   archs the range of "fast" function calls is limited. Here is a
   summary of the ranges:

   i386  : signed 32 bits
   arm   : signed 26 bits
   ppc   : signed 24 bits
   sparc : signed 32 bits
   alpha : signed 23 bits
*/
//#define CODE_GEN_BUFFER_SIZE     (128 * 1024)

/* estimated block size for TB allocation */
/* XXX: use a per code average code fragment size and modulate it
   according to the host CPU */
var TranslationBlock = function() {
    /* target_ulong*/ this.pc = 0; /* simulated PC corresponding to this block (EIP + CS base) */
    /*target_ulong*/ this.cs_base = 0; /* CS base for this block */
    /*uint64_t*/ this.flags = 0; /* flags defining in which context the code was generated */
    /*uint16_t*/ this.size = 0; /* size of target code for this block (1 <=
                           size <= TARGET_PAGE_SIZE) */
    /*uint16_t*/ this.cflags = 0; /* compile flags */
    /*uint8_t * */this.tc_ptr = 0;/* pointer to the translated code */
    this.tsize = 0;
    /* next matching tb for physical address. */
    /* struct TranslationBlock * */this.phys_hash_next = 0;
    /* first and second physical page containing code. The lower bit
       of the pointer tells the index in page_next[] */
    /* struct TranslationBlock* * */ this.page_next = new Uint32Array(2); 
    this.page_addr = new Uint32Array(2); 

    /* the following data are used to directly call another TB from
       the code of this one. */
    /*uint16_t */ this.tb_next_offset = new Uint16Array(2);  /* offset of original jump target */
    /* uint32_t */ this.tb_next = new Uint32Array(2);  /* address of jump generated code */

    /* list of TBs jumping to this one. This is a circular list using
       the two least significant bits of the pointers to tell what is
       the next pointer: 0 = jmp_next[0], 1 = jmp_next[1], 2 =
       jmp_first */
    /* struct TranslationBlock * */ this.jmp_next = new Array(2);//Uint32Array(2); 
   /* struct TranslationBlock * */ this.jmp_first = 0;
}

function tb_jmp_cache_hash_page(/* target_ulong */ pc)
{
    var /*target_ulong*/ tmp;
    tmp = pc ^ (pc >> (10 - (12 / 2)));
    return (tmp >> (12 / 2)) & ((1 << 12) - (1 << (12 / 2)));
}

function tb_jmp_cache_hash_func(/* target_ulong */ pc)
{
    var /* target_ulong*/ tmp;
    tmp = pc ^ (pc >> (10 - (12 / 2)));
    return (((tmp >> (12 / 2)) & ((1 << 12) - (1 << (12 / 2)))) |
     (tmp & ((1 << (12 / 2)) - 1)));
}

function tb_phys_hash_func(/* unsigned long */ pc)
{
    return pc & (((1 << 15) - 1) >>> 0);
}

/* set the jump target */
function tb_set_jmp_target(/* TranslationBlock * */tb,
                                     /* int */ n, /* unsigned long */ addr)
{
    tb.tb_next[n] = addr;
}



function tb_add_jump(/* TranslationBlock * */tb, /* int*/ n,
                               /* TranslationBlock * */ tb_next)
{
    console.log("tb_add_jump n=" + n);
    /* NOTE: this test is only needed for thread safety */
    if (!tb.jmp_next[n]) {
        /* patch the native jump address */
        tb_set_jmp_target(tb, n, tb_next.tc_ptr);

        /* add in TB jmp circular list */
        tb.jmp_next[n] = tb_next.jmp_first;
        tb_next.jmp_first = ((tb) | (n));
    }
}

function testandset (/* int * */p)
{
    /*
    long int readval = 0;

    __asm__ __volatile__ ("lock; cmpxchgl %2, %0"
                          : "+m" (*p), "+a" (readval)
                          : "r" (1)
                          : "cc");
    return readval;
    */        
   console.log("ERROR:");
   return 0;
}
function spin_trylock(lock)
{
    return 1;
}

/* NOTE: this function can trigger an exception */
/* NOTE2: the returned address is not exactly the physical address: it
   is the offset relative to phys_ram_base */
function get_phys_addr_code(/* CPUARMState * */ env, /* target_ulong */ addr)
{
    /* XXX mmu
    int mmu_idx, index, pd;

    index = (addr >> 10) & ((1 << 8) - 1);
    mmu_idx = cpu_mmu_index(env);
    if (__builtin_expect(env.tlb_table[mmu_idx][index].addr_code !=
                         (addr & ~((1 << 10) - 1)), 0)) {
        ldub_code(addr);
    }
    pd = env.tlb_table[mmu_idx][index].addr_code & ~~((1 << 10) - 1);
    if (pd > (1 << 4) && !(pd & (1))) {



        cpu_abort(env, "Trying to execute code outside RAM or ROM at 0x" "%08x" "\n", addr);

    }
    return addr + env.tlb_table[mmu_idx][index].addend - (unsigned long)phys_ram_base;
*/
   return address;
}

function env_to_regs()
{
    ;
}

function regs_to_env()
{
    ;
}

function cpu_halted(/* CPUARMState * */ env) {
    if (!env.halted)
        return 0;
    /* An interrupt wakes the CPU even if the I and F CPSR bits are
       set.  We use EXITTB to silently wake CPU without causing an
       actual interrupt.  */
    if (env.interrupt_request &
        (0x10 | 0x02 | 0x04)) {
        env.halted = 0;
        return 0;
    }
    return 0x10003;
}

var tb_invalidated_flag;

function cpu_loop_exit()
{
    /* NOTE: the register at this point must be saved by hand because
       longjmp restore them */
    regs_to_env();
    //longjmp(env.jmp_env, 1);
}

var tbs = new Array((16 * 1024 * 1024) / 128);//new TranslationBlock((16 * 1024 * 1024) / 128);
var tb_phys_hash = new Array(1 << 15);
var nb_tbs = 0;
var tb_lock = 0;


function tb_alloc(/* target_ulong*/ pc)
{
    var tb;
    /* Max size FIX xxx */
    if (nb_tbs >= tbs.length)  
        //    || (code_gen_ptr - code_gen_buffer) >= ((16 * 1024 * 1024) - code_gen_max_block_size()))
        return 0;
    tb = tbs[nb_tbs++] = new TranslationBlock();
    tb.pc = pc;
    tb.cflags = 0;
    return tb;
}

function cpu_arm_gen_code(/* CPUState * */env, /* TranslationBlock * */tb, /* int * */gen_code_size_ptr)
{
    var gen_code_buf;
    var gen_code_size;

    if (gen_intermediate_code(env, tb) < 0)
        return -1;

    /* generate machine code */
    tb.tb_next_offset[0] = 0xffff;
    tb.tb_next_offset[1] = 0xffff;
    //gen_code_buf = tb.tc_ptr;
 /*
#ifdef USE_DIRECT_JUMP
    // the following two entries are optional (only used for string ops) 
    tb->tb_jmp_offset[2] = 0xffff;
    tb->tb_jmp_offset[3] = 0xffff;
#endif
    dyngen_labels(gen_labels, nb_gen_labels, gen_code_buf, gen_opc_buf);

    gen_code_size = dyngen_code(gen_code_buf, tb->tb_next_offset,
#ifdef USE_DIRECT_JUMP
                                tb->tb_jmp_offset,
#else
                                NULL,
                                gen_opc_buf, gen_opparam_buf, gen_labels);
    *gen_code_size_ptr = gen_code_size;
    */
    return 0;
    
}
var tb_flush_count = 0;
var NULL = 0;

/* flush all the translation blocks */
function tb_flush(/*CPUARMState * */env)
{
    nb_tbs = 0;
    var i;

    for(i=0;i < env.tb_jmp_cache.length; i++) {
       env.tb_jmp_cache[i] = 0;
    }

    //for(i=0;i < tb_phys_hash.length; i++) {
    //    tb_phys_hash[i] = 0;
    //}
    //page_flush_tb();

    //code_gen_ptr = code_gen_buffer;
    /* XXX: flush processor icache at this point if cache flush is
       expensive */
    tb_flush_count++;
}

function tb_find_slow(/* target_ulong */ pc,
                                      /* target_ulong */ cs_base,
                                      /* uint64_t */ flags, env)
{
    var tb, ptb1;
    var code_gen_size = 0;
    var h;
    var phys_pc, phys_page1, phys_page2, virt_page2;
    var tc_ptr;
    var tb_lock = 0;

    //spin_lock(tb_lock);

    tb_invalidated_flag = 0;

    regs_to_env(); /* XXX: do it just before cpu_gen_code() */

    /* find translated block using physical mappings */
    phys_pc = pc; //get_phys_addr_code(env, pc);
    //phys_page1 = phys_pc & ~((1 << 10) - 1);
    //phys_page2 = -1;
    h = tb_phys_hash_func(phys_pc);
    ptb1 = tb_phys_hash[h];
    for(;;) {
        tb = ptb1;
        if (!tb)
            break;
        if (tb.pc == pc &&
            //tb.page_addr[0] == phys_page1 &&
            tb.cs_base == cs_base &&
            tb.flags == flags) {
            /* check next page if needed */
            /* 
            if (tb.page_addr[1] != -1) {
                virt_page2 = (pc & ~((1 << 10) - 1)) +
                    (1 << 10);
                phys_page2 = get_phys_addr_code(env, virt_page2);
                if (tb.page_addr[1] == phys_page2)
                {
                        env.tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
                        spin_unlock(tb_lock);
                        return tb;
                }
            } else {
            */
                /* we add the TB in the virtual pc hash table */
                env.tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
                //spin_unlock(tb_lock);
                return tb;
            //}
        }
        ptb1 = /*& */tb.phys_hash_next;
    }
// not_found:
    /* if no translated code available, then translate it now */
    tb = tb_alloc(pc);
    if (!tb) {
        /* flush must be done */
        tb_flush(env);
        /* cannot fail at this point */
        tb = tb_alloc(pc);
        /* don't forget to invalidate previous TB info */
        tb_invalidated_flag = 1;
    }
    tc_ptr = gen_opc_ptr.length;
    tb.tc_ptr = tc_ptr;
    tb.cs_base = cs_base;
    tb.flags = flags;
    cpu_arm_gen_code(env, tb,code_gen_size);
    tb.tsize = gen_opc_ptr.length - tc_ptr;
    //code_gen_ptr = ((code_gen_ptr + code_gen_size + 16 - 1) & ~(16 - 1));

    /* check next page if needed */
    /*
    virt_page2 = (pc + tb.size - 1) & ~((1 << 10) - 1);
    phys_page2 = -1;
    if ((pc & ~((1 << 10) - 1)) != virt_page2) {
        phys_page2 = get_phys_addr_code(env, virt_page2);
    }
    tb_link_phys(tb, phys_pc, phys_page2);
    */
 //found:
    /* we add the TB in the virtual pc hash table */
    env.tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
    //spin_unlock(tb_lock);
    return tb;
}

function tb_link_phys(/* TranslationBlock * */ tb,
                  /*target_ulong*/ phys_pc, /* target_ulong*/ phys_page2)
{
    var h;
    var ptb;

    /* add in the physical hash table */
    h = tb_phys_hash_func(phys_pc);
    ptb = tb_phys_hash[h];
    tb.phys_hash_next = ptb;
    ptb = tb;

    /* add in the page list */
    /*
    tb_alloc_page(tb, 0, phys_pc & TARGET_PAGE_MASK);
    if (phys_page2 != -1)
        tb_alloc_page(tb, 1, phys_page2);
    else
        tb.page_addr[1] = -1;
    */
    tb.jmp_first = (tb | 2);
    tb.jmp_next[0] = NULL;
    tb.jmp_next[1] = NULL;

    /* init original jump addresses */
    if (tb.tb_next_offset[0] != 0xffff)
        tb_reset_jump(tb, 0);
    if (tb.tb_next_offset[1] != 0xffff)
        tb_reset_jump(tb, 1);
}

function tb_find_fast(env)
{
    var /* TranslationBlock * */ tb;
    var /* target_ulong*/ cs_base, pc;
    var /* uint64_t */ flags;

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    flags = env.thumb | (env.vfp.vec_len << 1)
            | (env.vfp.vec_stride << 4);
    if ((env.uncached_cpsr & (0x1f)) != ARM_CPU_MODE_USR)
        flags |= (1 << 6);
    if (env.vfp.xregs[8] & (1 << 30))
        flags |= (1 << 7);
    flags |= (env.condexec_bits << 8);
    cs_base = 0;
    pc = env.regs[15];
    tb = env.tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
    if ((!tb || tb.pc != pc || tb.cs_base != cs_base || tb.flags != flags)) {
        console.log("tb_find_fast... pc 0x" + pc.toString(16) + " not found");
        tb = tb_find_slow(pc, cs_base, flags, env);
        if (tb_invalidated_flag) {
            /* as some TB could have been invalidated because
               of memory exceptions while generating the code, we
               must recompute the hash index here */
            T0 = 0;
        }
    }
    return tb;
}

/* main execution loop */
var tb_lock = 0;

function cpu_arm_exec(/* CPUARMState * */ env)
{
    var ret, interrupt_request;
    //void (*gen_func)(void);
    var tb;
    var tc_ptr;

    if (cpu_halted(env) == 0x10003)
        return 0x10003;
    
    env_to_regs();
    env.exception_index = -1;

    
    /* prepare setjmp context for exception handling */
    //for(;;) {
    //for(var i=0; i < 1; i++) {
        if (/* _setjmp (env.jmp_env)*/1) {
            env.current_tb = 0;
            /* if an exception is pending, we execute it here */
            if (env.exception_index >= 0) {
                if (env.exception_index >= 0x10000) {
                    /* exit request from the cpu execution loop */
                    ret = env.exception_index;
                    //break;
                } else {
                    do_interrupt(env);
                }
                env.exception_index = -1;
            }
            T0 = 0; /* force lookup of first TB */
            //for(;;) {
                interrupt_request = env.interrupt_request;
                if (interrupt_request != 0) {
                    if (interrupt_request & 0x80) {
                        env.interrupt_request &= ~0x80;
                        env.exception_index = 0x10002;
                        cpu_loop_exit();
                    }
                    if (interrupt_request & 0x20) {
                        env.interrupt_request &= ~0x20;
                        env.halted = 1;
                        env.exception_index = 0x10001;
                        cpu_loop_exit();
                    }
                    if (interrupt_request & 0x10
                        && !(env.uncached_cpsr & (1 << 6))) {
                        env.exception_index = 6;
                        do_interrupt(env);
                        T0 = 0;
                    }
                    /* ARMv7-M interrupt return works by loading a magic value
                       into the PC.  On real hardware the load causes the
                       return to occur.  The qemu implementation performs the
                       jump normally, then does the exception return when the
                       CPU tries to execute code at the magic address.
                       This will cause the magic PC value to be pushed to
                       the stack if an interrupt occured at the wrong time.
                       We avoid this by disabling interrupts when
                       pc contains a magic address.  */
                    if (interrupt_request & 0x02
                        && ((arm_feature(env, ARM_FEATURE_M) && env.regs[15] < 0xfffffff0)
                            || !(env.uncached_cpsr & (1 << 7)))) {
                        env.exception_index = 5;
                        do_interrupt(env);
                        T0 = 0;
                    }
                   /* Don't use the cached interupt_request value,
                      do_interrupt may have updated the EXITTB flag. */
                    if (env.interrupt_request & 0x04) {
                        env.interrupt_request &= ~0x04;
                        /* ensure that no TB jump will be modified as
                           the program flow was changed */
                        T0 = 0;
                    }
                    if (interrupt_request & 0x01) {
                        env.interrupt_request &= ~0x01;
                        env.exception_index = 0x10000;
                        cpu_loop_exit();
                    }
                }
                tb = tb_find_fast(env);
                /* see if we can patch the calling TB. When the TB
                   spans two pages, we cannot safely do a direct
                   jump. */
                //if (T0 instanceof TranslationBlock) //&& tb.page_addr[1] == -1) 
                //{
                    //spin_lock(tb_lock);
                    // here they pass tb+n
               //     tb_add_jump(T0 /*& ~3 */, T0.tc_ptr & 3/* T0 & 3*/, tb);
                    //spin_unlock(tb_lock);
               // }
                //}
                 
                //tc_ptr = tb.tc_ptr;
                env.current_tb = tb;
                console.log("starting translation block at pc 0x" + env.regs[15].toString(16));
                for(cur_tb_op=0;gen_opc_ptr[tb.tc_ptr+cur_tb_op].func != op_end; cur_tb_op++) {
                    // else execute the block
                    //switch(gen_opc_ptr[tb.tc_ptr+i].__count__) {
                        //case 1:
                        //    gen_opc_ptr[tb.tc_ptr+i].func();
                        //    break;
                        //case 2:
                        //    gen_opc_ptr[tb.tc_ptr+i].func(gen_opc_ptr[tb.tc_ptr+i].param1);
                        //    break;
                        //case 3:
                        //console.log("opc ptr param 0 0x" + gen_opc_ptr[tb.tc_ptr+i].param);
                        
                        //console.log("executing " + gen_opc_ptr[tb.tc_ptr+cur_tb_op].func);
                        gen_opc_ptr[tb.tc_ptr+cur_tb_op].func(gen_opc_ptr[tb.tc_ptr+cur_tb_op].param, gen_opc_ptr[tb.tc_ptr+cur_tb_op].param2);
                      //      break;
                    //}
                    //gen_opc_ptr[tb.tc_ptr+i][0].func(gen_opc_ptr[tb.tc_ptr+i][1], gen_opc_ptr[tb.tc_ptr+i][2]);
                }
                console.log("cpu_arm_exec tb size = 0x" + tb.size.toString(16) + " tsize 0x" + tb.tsize.toString(16));
                /* execute the generated code */
                //XXX: execute actual block
                //gen_func = (void *)tc_ptr;
                //gen_func();
                
                env.current_tb = 0;
                /* reset soft MMU for next block (it can currently
                   only be set by a memory fault) */
            //} /* for(;;) */
       // } else {
      //      env_to_regs();
    // }
    //console.log("HMmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm");
    //cpu_single_env = 0;
    return ret;
}

/* must only be called from the generated code as an exception can be
   generated */
function tb_invalidate_page_range(/* target_ulong */ start, /* target_ulong */ end)
{
    /* XXX: cannot enable it yet because it yields to MMU exception
       where NIP != read address on PowerPC */
}

function spin_lock (lock)
{
    console.log("spin_lock"); // implement later
}

function spin_unlock (lock)
{
    console.log("spin_unlock"); // implement later
}

function cpu_reset_model_id(/* CPUARMState * */env, /* uint32_t */ id)
{
    env.cp15.c0_cpuid = id;
    switch (id) {
    case ARM_CPUID_ARM926:
        set_feature(env, ARM_FEATURE_VFP);
        env.vfp.xregs[ARM_VFP_FPSID] = 0x41011090;
        env.cp15.c0_cachetype = 0x1dd20d2;
        env.cp15.c1_sys = 0x00090078;
        break;
    case ARM_CPUID_ARM946:
        set_feature(env, ARM_FEATURE_MPU);
        env.cp15.c0_cachetype = 0x0f004006;
        env.cp15.c1_sys = 0x00000078;
        break;
    case ARM_CPUID_ARM1026:
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_AUXCR);
        env.vfp.xregs[ARM_VFP_FPSID] = 0x410110a0;
        env.cp15.c0_cachetype = 0x1dd20d2;
        env.cp15.c1_sys = 0x00090078;
        break;
    case ARM_CPUID_ARM1136:
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_AUXCR);
        env.vfp.xregs[ARM_VFP_FPSID] = 0x410120b4;
        env.vfp.xregs[ARM_VFP_MVFR0] = 0x11111111;
        env.vfp.xregs[ARM_VFP_MVFR1] = 0x00000000;
        memcpy(env.cp15.c0_c1, arm1136_cp15_c0_c1, 8 * sizeof(uint32_t));
        memcpy(env.cp15.c0_c1, arm1136_cp15_c0_c2, 8 * sizeof(uint32_t));
        env.cp15.c0_cachetype = 0x1dd20d2;
        break;
    case ARM_CPUID_ARM11MPCORE:
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_V6K);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_AUXCR);
        env.vfp.xregs[ARM_VFP_FPSID] = 0x410120b4;
        env.vfp.xregs[ARM_VFP_MVFR0] = 0x11111111;
        env.vfp.xregs[ARM_VFP_MVFR1] = 0x00000000;
        memcpy(env.cp15.c0_c1, mpcore_cp15_c0_c1, 8 * sizeof(uint32_t));
        memcpy(env.cp15.c0_c1, mpcore_cp15_c0_c2, 8 * sizeof(uint32_t));
        env.cp15.c0_cachetype = 0x1dd20d2;
        break;
    case ARM_CPUID_CORTEXA8:
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_V6K);
        set_feature(env, ARM_FEATURE_V7);
        set_feature(env, ARM_FEATURE_AUXCR);
        set_feature(env, ARM_FEATURE_THUMB2);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_VFP3);
        set_feature(env, ARM_FEATURE_NEON);
        env.vfp.xregs[ARM_VFP_FPSID] = 0x410330c0;
        env.vfp.xregs[ARM_VFP_MVFR0] = 0x11110222;
        env.vfp.xregs[ARM_VFP_MVFR1] = 0x00011100;
        memcpy(env.cp15.c0_c1, cortexa8_cp15_c0_c1, 8 * sizeof(uint32_t));
        memcpy(env.cp15.c0_c1, cortexa8_cp15_c0_c2, 8 * sizeof(uint32_t));
        env.cp15.c0_cachetype = 0x1dd20d2;
        break;
    case ARM_CPUID_CORTEXM3:
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_THUMB2);
        set_feature(env, ARM_FEATURE_V7);
        set_feature(env, ARM_FEATURE_M);
        set_feature(env, ARM_FEATURE_DIV);
        break;
    case ARM_CPUID_ANY: /* For userspace emulation.  */
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_V6K);
        set_feature(env, ARM_FEATURE_V7);
        set_feature(env, ARM_FEATURE_THUMB2);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_VFP3);
        set_feature(env, ARM_FEATURE_NEON);
        set_feature(env, ARM_FEATURE_DIV);
        break;
    case ARM_CPUID_TI915T:
    case ARM_CPUID_TI925T:
        set_feature(env, ARM_FEATURE_OMAPCP);
        env.cp15.c0_cpuid = ARM_CPUID_TI925T; /* Depends on wiring.  */
        env.cp15.c0_cachetype = 0x5109149;
        env.cp15.c1_sys = 0x00000070;
        env.cp15.c15_i_max = 0x000;
        env.cp15.c15_i_min = 0xff0;
        break;
    case ARM_CPUID_PXA250:
    case ARM_CPUID_PXA255:
    case ARM_CPUID_PXA260:
    case ARM_CPUID_PXA261:
    case ARM_CPUID_PXA262:
        set_feature(env, ARM_FEATURE_XSCALE);
        /* JTAG_ID is ((id << 28) | 0x09265013) */
        env.cp15.c0_cachetype = 0xd172172;
        env.cp15.c1_sys = 0x00000078;
        break;
    case ARM_CPUID_PXA270_A0:
    case ARM_CPUID_PXA270_A1:
    case ARM_CPUID_PXA270_B0:
    case ARM_CPUID_PXA270_B1:
    case ARM_CPUID_PXA270_C0:
    case ARM_CPUID_PXA270_C5:
        set_feature(env, ARM_FEATURE_XSCALE);
        /* JTAG_ID is ((id << 28) | 0x09265013) */
        set_feature(env, ARM_FEATURE_IWMMXT);
        env.iwmmxt.cregs[ARM_IWMMXT_wCID] = 0x69051000 | 'Q';
        env.cp15.c0_cachetype = 0xd172172;
        env.cp15.c1_sys = 0x00000078;
        break;
    default:
        cpu_abort(env, "Bad CPU ID: %x\n", id);
        break;
    }
}
}
var ARM_CPUID_ARM1026     = 0x4106a262 >>> 0;
var ARM_CPUID_ARM926      = 0x41069265 >>> 0;
var ARM_CPUID_ARM946      = 0x41059461 >>> 0;
var ARM_CPUID_TI915T      = 0x54029152 >>> 0;
var ARM_CPUID_TI925T      = 0x54029252 >>> 0;
var ARM_CPUID_PXA250      = 0x69052100 >>> 0;
var ARM_CPUID_PXA255      = 0x69052d00 >>> 0;
var ARM_CPUID_PXA260      = 0x69052903 >>> 0;
var ARM_CPUID_PXA261      = 0x69052d05 >>> 0;
var ARM_CPUID_PXA262      = 0x69052d06 >>> 0;
var ARM_CPUID_PXA270      = 0x69054110 >>> 0;
var ARM_CPUID_PXA270_A0   = 0x69054110 >>> 0;
var ARM_CPUID_PXA270_A1   = 0x69054111 >>> 0;
var ARM_CPUID_PXA270_B0   = 0x69054112 >>> 0;
var ARM_CPUID_PXA270_B1   = 0x69054113 >>> 0;
var ARM_CPUID_PXA270_C0   = 0x69054114 >>> 0;
var ARM_CPUID_PXA270_C5   = 0x69054117 >>> 0;
var ARM_CPUID_ARM1136     = 0x4117b363 >>> 0;
var ARM_CPUID_ARM11MPCORE = 0x410fb022 >>> 0;
var ARM_CPUID_CORTEXA8    = 0x410fc080 >>> 0;
var ARM_CPUID_CORTEXM3    = 0x410fc231 >>> 0;
var ARM_CPUID_ANY         = 0xffffffff >>> 0;

var arm_cpu_names = [
    [ ARM_CPUID_ARM926, "arm926"],
    [ ARM_CPUID_ARM946, "arm946"],
    [ ARM_CPUID_ARM1026, "arm1026"],
    [ ARM_CPUID_ARM1136, "arm1136"],
    [ ARM_CPUID_ARM11MPCORE, "arm11mpcore"],
    [ ARM_CPUID_CORTEXM3, "cortex-m3"],
    [ ARM_CPUID_CORTEXA8, "cortex-a8"],
    [ ARM_CPUID_TI925T, "ti925t" ],
    [ ARM_CPUID_PXA250, "pxa250" ],
    [ ARM_CPUID_PXA255, "pxa255" ],
    [ ARM_CPUID_PXA260, "pxa260" ],
    [ ARM_CPUID_PXA261, "pxa261" ],
    [ ARM_CPUID_PXA262, "pxa262" ],
    [ ARM_CPUID_PXA270, "pxa270" ],
    [ ARM_CPUID_PXA270_A0, "pxa270-a0" ],
    [ ARM_CPUID_PXA270_A1, "pxa270-a1" ],
    [ ARM_CPUID_PXA270_B0, "pxa270-b0" ],
    [ ARM_CPUID_PXA270_B1, "pxa270-b1" ],
    [ ARM_CPUID_PXA270_C0, "pxa270-c0" ],
    [ ARM_CPUID_PXA270_C5, "pxa270-c5" ],
    [ ARM_CPUID_ANY, "any"],
    [ 0, 0]
];

var table_logic_cc = [
    1, /* and */
    1, /* xor */
    0, /* sub */
    0, /* rsb */
    0, /* add */
    0, /* adc */
    0, /* sbc */
    0, /* rsc */
    1, /* andl */
    1, /* xorl */
    0, /* cmp */
    0, /* cmn */
    1, /* orr */
    1, /* mov */
    1, /* bic */
    1, /* mvn */
];

var CPSR_M = (0x1f);
var CPSR_T = (1 << 5);
var CPSR_F = (1 << 6);
var CPSR_I = (1 << 7);
var CPSR_A = (1 << 8);
var CPSR_E = (1 << 9);
var CPSR_IT_2_7 = (0xfc00);
var CPSR_GE = (0xf << 16);
var CPSR_RESERVED = (0xf << 20);
var CPSR_J = (1 << 24);
var CPSR_IT_0_1 = (3 << 25);
var CPSR_Q = (1 << 27);
var CPSR_V = (1 << 28);
var CPSR_C = (1 << 29);
var CPSR_Z = (1 << 30);
var CPSR_N = (1 << 31);
var CPSR_NZCV = (CPSR_N | CPSR_Z | CPSR_C | CPSR_V);

var CPSR_IT = (CPSR_IT_0_1 | CPSR_IT_2_7);
var CACHED_CPSR_BITS = (CPSR_T | CPSR_GE | CPSR_IT | CPSR_Q | CPSR_NZCV);
/* Bits writable in user mode.  */
var CPSR_USER = (CPSR_NZCV | CPSR_Q | CPSR_GE);
/* Execution state bits.  MRS read as zero, MSR writes ignored.  */
var CPSR_EXEC = (CPSR_T | CPSR_IT | CPSR_J);

var gen_op_movl_TN_reg = [
    [
        gen_op_movl_T0_r0,
        gen_op_movl_T0_r1,
        gen_op_movl_T0_r2,
        gen_op_movl_T0_r3,
        gen_op_movl_T0_r4,
        gen_op_movl_T0_r5,
        gen_op_movl_T0_r6,
        gen_op_movl_T0_r7,
        gen_op_movl_T0_r8,
        gen_op_movl_T0_r9,
        gen_op_movl_T0_r10,
        gen_op_movl_T0_r11,
        gen_op_movl_T0_r12,
        gen_op_movl_T0_r13,
        gen_op_movl_T0_r14,
        gen_op_movl_T0_r15,
    ],
    [
        gen_op_movl_T1_r0,
        gen_op_movl_T1_r1,
        gen_op_movl_T1_r2,
        gen_op_movl_T1_r3,
        gen_op_movl_T1_r4,
        gen_op_movl_T1_r5,
        gen_op_movl_T1_r6,
        gen_op_movl_T1_r7,
        gen_op_movl_T1_r8,
        gen_op_movl_T1_r9,
        gen_op_movl_T1_r10,
        gen_op_movl_T1_r11,
        gen_op_movl_T1_r12,
        gen_op_movl_T1_r13,
        gen_op_movl_T1_r14,
        gen_op_movl_T1_r15,
    ],
    [
        gen_op_movl_T2_r0,
        gen_op_movl_T2_r1,
        gen_op_movl_T2_r2,
        gen_op_movl_T2_r3,
        gen_op_movl_T2_r4,
        gen_op_movl_T2_r5,
        gen_op_movl_T2_r6,
        gen_op_movl_T2_r7,
        gen_op_movl_T2_r8,
        gen_op_movl_T2_r9,
        gen_op_movl_T2_r10,
        gen_op_movl_T2_r11,
        gen_op_movl_T2_r12,
        gen_op_movl_T2_r13,
        gen_op_movl_T2_r14,
        gen_op_movl_T2_r15,
    ]
];

var gen_op_movl_TN_im = [
    gen_op_movl_T0_im,
    gen_op_movl_T1_im,
    gen_op_movl_T2_im,
];

function cpu_reset(/* CPUARMState * */env)
{
    var /* uint32_t*/ id;
    id = env.cp15.c0_cpuid;
    //env = 0;
    if (id)
        cpu_reset_model_id(env, id);
    /* SVC mode with interrupts disabled.  */
    env.uncached_cpsr = ARM_CPU_MODE_SVC | CPSR_A | CPSR_F | CPSR_I;
    /* On ARMv7-M the CPSR_I is the value of the PRIMASK register, and is
       clear at reset.  */
    if (arm_feature(env, ARM_FEATURE_M))
        env.uncached_cpsr &= ~CPSR_I;
    env.vfp.xregs[ARM_VFP_FPEXC] = 0;
    env.regs[15] = 0;
    //tlb_flush(env, 1);
}

function cpu_arm_find_by_name(name)
{
    var i;
    var id = 0;
    
    for (i = 0; arm_cpu_names[i][0]; i++) {
        if (arm_cpu_names[i][1] == name) {
            id = arm_cpu_names[i][0] >>> 0;
            break;
        }
    }
    return id;
}
/* CPUARMState * */ function cpu_arm_init(/* const char * */cpu_model)
{
    var env;
    var id;

    id = cpu_arm_find_by_name(cpu_model);
    if (id == 0)
        return NULL;
    env = new CPUARMState();
    cpu_single_env = env;
    if (!env)
        return NULL;
    cpu_exec_init(env);
    env.cpu_model_str = cpu_model;
    env.cp15.c0_cpuid = id;
    //cpu_reset(env);
    return env;
}

function cpu_exec_init(/* CPUARMState  */env)
{
    
    
}
var mem_size=0;
var phys_mem=0;
var phys_mem8=0;
var phys_mem16=0;
var phys_mem32=0;

function CPU_ARM() 
{
        this.cpuenv = cpu_arm_init("arm946");
}
CPU_ARM.prototype.exec=function(count, env)
{
	while (count > 0)
	{
                cpu_arm_exec(env);
				count--;
	}
}
CPU_ARM.prototype.phys_mem_resize=function(size){
    mem_size=size;
    size+=((15+3)&~3);
    phys_mem=new ArrayBuffer(size);
    phys_mem8=new Uint8Array(phys_mem,0, size);
    phys_mem16=new Uint16Array(phys_mem,0,size/2);
    phys_mem32=new Int32Array(phys_mem,0, size/4);
};
function ld8_phys(fa){
    return phys_mem8[fa];
}
function st8_phys(fa,ga){
    phys_mem8[fa]=ga;
}
function ld32_phys(fa){
    return phys_mem32[fa>>2];
}
function st32_phys(fa,ga){
    phys_mem32[fa>>2]=ga;
}
CPU_ARM.prototype.load_binary=function(Hg,fa,Ig){
    var Jg,wa;
    wa=this;
    Jg=function(Kg,rg){
        var i;
        if(rg<0){
            Ig(rg);
        }else{
            if(typeof Kg=="string"){
                for(i=0;
                    i<rg;
                    i++){
                    st8_phys(fa+i,Kg.charCodeAt(i));
                }
            }else{
                for(i=0;
                    i<rg;
                    i++){
                    st8_phys(fa+i,Kg[i]);
                }
            }
            Ig(rg);
        }
    };
    load_binary(Hg,Jg);
};

function ArmEmulator(params){
    var CPUEnv,fi,gi,i,p;
    CPUEnv = new CPU_ARM();
    this.cpu=CPUEnv;
    this.cpu.cycle_count = 0;
    CPUEnv.phys_mem_resize(params.mem_size);
}

ArmEmulator.prototype.load_binary=function(Hg,ha,Ig){
    return this.cpu.load_binary(Hg,ha,Ig);
};

ArmEmulator.prototype.start=function(){
    setTimeout(this.timer_func.bind(this),10);
};
