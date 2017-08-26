#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/loader.h>

#include "macho.h"
#include "filetools.h"
#include "offsets.h"
#include "patchfinder.h"

uint32_t LOAD_ADDR;

long find_OSSerializer_serialize(FILE *f, struct symtab_command *st) {
	static const char symb[] = "__ZNK12OSSerializer9serializeEP11OSSerialize";
	static long offset = -1;

	if (offset == -1) {
		long val;
		if (!find_symbol_value(f, st, symb, &val)) {
			offset = val - LOAD_ADDR;
		} else {
			offset = -2;
		}
	}

	return offset;
};

long find_OSSymbol_getMetaClass(FILE *f, struct symtab_command *st) {
	static const char symb[] = "__ZNK8OSSymbol12getMetaClassEv";
	static long offset = -1;

	if (offset == -1) {
		long val;
		if (!find_symbol_value(f, st, symb, &val)) {
			offset = val - LOAD_ADDR;
		} else {
			offset = -2;
		}
	}

	return offset;
};

long find_calend_gettime(FILE *f) {
	static const char sign[] = {
		0x90, 0xb5, 0x01, 0xaf, 0x82, 0xb0, 0x04,
		0x46, 0x01, 0xa8, 0x69, 0x46, 0xff, 0xf7
	};

	static long offset = -1;

	if (offset == -1) {
		long val = get_data_offset(sign, sizeof(sign)/sizeof(char), f, 0, -1);
		if (val >= 0) {
			offset = val;
		} else {
			offset = -2;
		}
	}

	return offset;
};

long find_bufattr_cpx(FILE *f, struct symtab_command *st) {
	static const char symb[] = "_bufattr_cpx";
	static long offset = -1;

	if (offset == -1) {
		long val;
		if (!find_symbol_value(f, st, symb, &val)) {
			offset = val - LOAD_ADDR;
		} else {
			offset = -2;
		}
	}

	return offset;
};

long find_clock_ops(FILE *f, struct symtab_command *st) {
	static long offset = -1;

	if (offset == -1) {
		long cgsv_off;
		if (find_symbol_value(f, st, "_clock_get_system_value", &cgsv_off)) {
			offset = -2;
			return offset;
		}
		cgsv_off -= LOAD_ADDR;

		long addr;
		uint16_t buf[2];
		uint16_t *p = (uint16_t *) buf;
		load_bytes_to_buf(f, cgsv_off, sizeof(buf), &buf);
		cgsv_off += sizeof(uint16_t);

		while (*p != 0xBF00) { // proc ends with 00 BF nop
	        if (insn_is_mov_imm(p) && (insn_mov_imm_rd(p) == 0)) {
	        	// movw r0, #X
	            addr = insn_mov_imm_imm(p);
	        } else if (insn_is_movt(p) && (insn_movt_rd(p)) == 0) {
	        	// movt r0, #X
	            addr |= (insn_movt_imm(p) << 16);
	        } else if (insn_is_add_reg(p) && (insn_add_reg_rd(p) == 0) && (insn_add_reg_rm(p) == 0xF)) {
	        	// add r0, pc
				// cgsv_off is file offset of next instruction, and pc is address of instruction + 4
				// so loaded addr is going to be addr + cgsv_off + 2
				addr += cgsv_off+2;
			} else if (insn_is_ldr_imm(p) && (insn_ldr_imm_rt(p) == 0) && (insn_ldr_imm_rn(p) == 0)) {
				// ldr r0, [r0]
	            load_bytes_to_buf(f, addr, sizeof(uint32_t), &addr);
	        } else if (insn_is_ldr_imm(p) && (insn_ldr_imm_rt(p) == 1) && (insn_ldr_imm_rn(p) == 0)) {
				// ldr r1, [r0, #X]
				// addr contains result of ldr r0, [r0]
				// *4, because fucking arm stores offset/4.
	            offset = addr + insn_ldr_imm_imm(p) * 4;
	            offset += 0x4; // "next line"

	            // Changing to file offset
	            offset -= LOAD_ADDR;
	            break;
	        }

			load_bytes_to_buf(f, cgsv_off, sizeof(buf), buf);
			cgsv_off+=2;
	    }
	}

    return offset;
};

long find_copyin(FILE *f, struct symtab_command *st) {
	static const char symb[] = "_copyin";
	static long offset = -1;

	if (offset == -1) {
		long val;
		if (!find_symbol_value(f, st, symb, &val)) {
			offset = val - LOAD_ADDR;
		} else {
			offset = -2;
		}
	}

	return offset;
};

long find_bx_lr(FILE *f, struct symtab_command *st) {
	static const char sign[] = {
		0x70, 0x47 // bx lr;
	};

	static long offset = -1;

	if (offset == -1) {
		long bufattr_cpx = find_bufattr_cpx(f, st);
		if (bufattr_cpx < 0) {
			offset = -2;
		} else {
			long val = get_data_offset(sign, sizeof(sign)/sizeof(char), f, bufattr_cpx, -1);
			if (val >= 0) {
				offset = val + bufattr_cpx;
			} else {
				offset = -2;
			}
		}
	}
	return offset;
};

long find_write_gadget(FILE *f) {
	static const char sign[] = {
		0x0c, 0x10, 0x80, 0xe5, 0x1e, 0xff, 0x2f, 0xe1
	};

	static long offset = -1;

	if (offset == -1) {
		long val = get_data_offset(sign, sizeof(sign)/sizeof(char), f, 0, -1);
		if (val >= 0) {
			offset = val;
		} else {
			offset = -2;
		}
	}

	return offset;
};

long find_vm_kernel_addrperm(FILE *f, struct symtab_command *st) {
	static long offset = -1;

	if (offset == -1) {
		long bcaa_off;
		if (find_symbol_value(f, st, "_buf_kernel_addrperm_addr", &bcaa_off)) {
			offset = -2;
			return offset;
		}
		bcaa_off -= LOAD_ADDR;

		long addr;
		uint16_t buf[2];
		uint16_t *p = (uint16_t *) &buf;
		load_bytes_to_buf(f, bcaa_off, sizeof(buf), &buf);
		bcaa_off += sizeof(uint16_t);

		while (*p != 0x4700) { // proc ends with bx lr
	        if (insn_is_mov_imm(p) && (insn_mov_imm_rd(p) == 1)) {
	        	// movw r1, #X
	            addr = insn_mov_imm_imm(p);
	        } else if (insn_is_movt(p) && (insn_movt_rd(p) == 1)) {
	        	// movt r1, #X
	            addr |= (insn_movt_imm(p) << 16);
	        } else if (insn_is_add_reg(p) && (insn_add_reg_rd(p) == 1) && (insn_add_reg_rm(p) == 0xF)) {
	        	// add r1, pc
				// bcaa_off is file offset of next instruction, and pc is address of instruction + 4
				// so loaded addr is going to be addr + cgsv_off + 2
				offset = addr;
				// add r1, pc
				offset += bcaa_off + 2;
			} else if (insn_is_ldr_imm(p) && (insn_ldr_imm_rt(p) == 1)) {
				// ldr r1, [r0, #XX]
	            offset += insn_ldr_imm_imm(p) * 4;
	            offset -= 0x4; // "substract 4"
	            return offset;
	        }

			load_bytes_to_buf(f, bcaa_off, sizeof(buf), &buf);
			bcaa_off+=2;
	    }
	}

    return offset;
};

long find_kernel_pmap(FILE *f, struct symtab_command *st) {
	static const char symb[] = "_kernel_pmap";
	static long offset = -1;

	if (offset == -1) {
		long val;
		if (!find_symbol_value(f, st, symb, &val)) {
			offset = val - LOAD_ADDR;
		} else {
			offset = -2;
		}
	}

	return offset;
};

long find_invalidate_tlb(FILE *f) {
	static const char sign[] = {
		0x00, 0x00, 0xa0, 0xe3, 0x17, 0x0f, 0x08, 
		0xee, 0x4b, 0xf0, 0x7f, 0xf5, 0x6f, 0xf0, 
		0x7f, 0xf5, 0x1e, 0xff, 0x2f
	};

	static long offset = -1;

	if (offset == -1) {
		long val = get_data_offset(sign, sizeof(sign)/sizeof(char), f, 0, -1);
		if (val >= 0) {
			offset = val;
		} else {
			offset = -2;
		}
	}

	return offset;
};

long allproc(FILE *f, struct symtab_command *st, struct section *tsect) {
	const char pgrp_add_str[] = "\"pgrp_add : pgrp is dead adding process\"";
	long pgrp_offs = get_data_offset(pgrp_add_str, strlen(pgrp_add_str) + 1, f, 0, -1);
	if (pgrp_offs < 0) return 1;
	
	long panic_offset;
	int v;
	if ((v = find_symbol_value(f, st, "_panic", &panic_offset)) ){
		return v;
	}

	long addr;
	uint16_t buf[2];
	uint16_t *p = (uint16_t *) buf;
	long __text_start = tsect->offset;
	long __text_end = __text_start + tsect->size;
	load_bytes_to_buf(f, __text_start, sizeof(buf), &buf);
	long cur_off = __text_start + sizeof(buf);

	#define readbyte do {\
		buf[0] = buf[1];\
		load_bytes_to_buf(f, -1, sizeof(buf[1]), &buf[1]);\
		cur_off+=sizeof(buf[1]);\
	} while(0)

	while (cur_off < __text_end) {
        if (insn_is_mov_imm(p) && (insn_mov_imm_rd(p) == 0)) {
        	// movw r0, #X
            addr = insn_mov_imm_imm(p);
            //printf("%lx movw r0, #0x%lx\n", cur_off - 4 + LOAD_ADDR, addr);
            
            readbyte;readbyte;
        	if (!(insn_is_movt(p) && (insn_movt_rd(p) == 0))) 
        		continue;
        	// movt r0, #X
            addr |= (insn_movt_imm(p) << 16);
            //printf("%lx movt r0, #0x%lx\n", cur_off - 4 + LOAD_ADDR, insn_movt_imm(p));

            readbyte;readbyte;
        	if (!(insn_is_add_reg(p) && (insn_add_reg_rd(p) == 0) && (insn_add_reg_rm(p) == 0xF)))
        		continue;
        	// add r0, pc
			addr += cur_off;
            //printf("%lx add r0, rp ; 0x%lx\n", cur_off - 4 + LOAD_ADDR, addr + LOAD_ADDR);

			if (addr != pgrp_offs)
				continue;

			readbyte;
			if (!(insn_is_32bit(p) && insn_is_bl(p)))
				continue;

			// bl _panic
			uint32_t bl_to = (int32_t) insn_bl_imm32(p) + cur_off + LOAD_ADDR;
			//printf("%lx bl %d ; %x\n", cur_off - 4 + LOAD_ADDR, (int32_t)insn_bl_imm32(p), bl_to);

			if ((long)bl_to != panic_offset)
				continue;
			
			// found it!
			break;
		}

		readbyte;
	}
	#undef readbyte

	if (cur_off >= __text_end) return -1;

	#define readbyte do {\
		buf[1] = buf[0];\
		load_bytes_to_buf(f, cur_off, sizeof(buf[0]), &buf[0]);\
		cur_off-=sizeof(buf[1]);\
	} while(0)

	readbyte;
	int32_t allproc_struct_offs = 0;
	while (cur_off > __text_start) {
		if (*p == 0x2900) { //cmp r1, #0x0
			readbyte;
			// str r1, [r5]
			if (!(insn_is_str_imm(p) && insn_str_imm_rt(p) == 1 && insn_str_imm_rn(p) == 5 && insn_str_imm_imm(p) == 0))
				continue;

			readbyte;
			if (!(insn_is_ldr_imm(p) && insn_ldr_imm_rt(p) == 1 && insn_str_imm_rn(p) == 0))
				continue;

			allproc_struct_offs = insn_ldr_imm_imm(p) << 2;

			if (allproc_struct_offs != 0xc) 
				printf("WTF ldr_imm is 0x%x and not 0xc!!\n", allproc_struct_offs);

			while(!(insn_is_add_reg(p) && (insn_add_reg_rd(p) == 0) && (insn_add_reg_rm(p) == 0xF)))
				readbyte;

			allproc_struct_offs += cur_off + 2 + 4;

			while (!(insn_is_movt(p) && insn_movt_rd(p) == 0)) 
				readbyte;

			allproc_struct_offs += insn_movt_imm(p) << 16;

			readbyte;readbyte;

			if (!(insn_is_mov_imm(p) && insn_mov_imm_rd(p) == 0))
				continue;

			allproc_struct_offs += insn_mov_imm_imm(p);

			return allproc_struct_offs;
		}
		readbyte;
	}

	#undef readbyte

    return -1;
};

char *version(FILE *f, struct symtab_command *st) {
	long _version;

	if (find_symbol_value(f, st, "_version", &_version)) {
		return NULL;
	}

	_version -= LOAD_ADDR;
	
	char s_term[] = {0x0};
	int v_len = get_data_offset((void*) s_term, sizeof(s_term), f, _version, -1);

	if (v_len < 0) return NULL;
	char *ret = malloc(sizeof(char) * (v_len+1));
	load_bytes_to_buf(f, _version, sizeof(char) * v_len, ret);
	ret[v_len] = '\0';

	return ret;
}

long proc_ucred(FILE *f, struct symtab_command *st) {
	static long offset = -1;

	if (offset == -1) {
		long _proc_ucred_a;
		if (find_symbol_value(f, st, "_proc_ucred", &_proc_ucred_a)) {
			offset = -2;
			return offset;
		}

		uint32_t _proc_ucred = _proc_ucred_a;

		_proc_ucred -= LOAD_ADDR;
		uint16_t buf[2];
		load_bytes_to_buf(f, _proc_ucred, sizeof(buf), buf);
		if (buf[0] == 0xF8D0) { // ldr.w r0, [r0, #X]
			offset = buf[1]; // #X
		}
	}

	return offset;
};

struct clock_ops_offset *untether_clock_ops(FILE *f, struct symtab_command *st) {
	static struct clock_ops_offset *offset = NULL;
	static int ran = 0;

	if (!ran) {
		long clock_ops = find_clock_ops(f, st);
		
		if (clock_ops >= 0) {
			offset = load_bytes(f, clock_ops, sizeof(struct clock_ops_offset));
		}

		ran = 1;
	}

	return offset;
}
