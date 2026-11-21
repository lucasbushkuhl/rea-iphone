// Objective-C class using *relative* method lists (the iOS 14+ format that
// ld64 emits by default for modern deployment targets; LLVM 18's lld cannot
// emit it, so it is laid out by hand). Entries are 12 bytes of 32-bit
// relative offsets {name -> selref, types -> string, imp -> code}, and the
// list header carries the 0x80000000 "small method list" flag.

        .section __TEXT,__objc_methname,cstring_literals
sel_ping:      .asciz "ping"
sel_pongWith:  .asciz "pongWith:"
sel_make:      .asciz "make"

        .section __TEXT,__objc_methtype,cstring_literals
ty_v16:        .asciz "v16@0:8"
ty_at24:       .asciz "@24@0:8@16"
ty_at16:       .asciz "@16@0:8"

        .section __TEXT,__objc_classname,cstring_literals
cn_Rel:        .asciz "RelativeClass"

        .section __DATA,__objc_selrefs,literal_pointers,no_dead_strip
        .p2align 3
selref_ping:     .quad sel_ping
selref_pongWith: .quad sel_pongWith
selref_make:     .quad sel_make

        .section __TEXT,__text,regular,pure_instructions
        .p2align 2
imp_ping:  ret
imp_pong:  ret
imp_make:  ret

        .section __DATA,__objc_const
        .p2align 3
rel_methods_inst:
        .long 0x8000000c              // entsize 12 | smallMethodListFlag
        .long 2
        .long selref_ping - .
        .long ty_v16 - .
        .long imp_ping - .
        .long selref_pongWith - .
        .long ty_at24 - .
        .long imp_pong - .
        .p2align 3
rel_methods_class:
        .long 0x8000000c
        .long 1
        .long selref_make - .
        .long ty_at16 - .
        .long imp_make - .
        .p2align 3
ro_Rel:                               // class_ro_t
        .long 2                       // flags: RO_ROOT
        .long 8                       // instanceStart
        .long 8                       // instanceSize
        .long 0                       // reserved
        .quad 0                       // ivarLayout
        .quad cn_Rel                  // name
        .quad rel_methods_inst        // baseMethods
        .quad 0, 0, 0, 0              // protocols, ivars, weakIvarLayout, properties
ro_Rel_meta:
        .long 3                       // RO_META | RO_ROOT
        .long 40
        .long 40
        .long 0
        .quad 0
        .quad cn_Rel
        .quad rel_methods_class
        .quad 0, 0, 0, 0

        .section __DATA,__objc_data
        .p2align 3
cls_Rel:  .quad meta_Rel, 0, 0, 0, ro_Rel          // isa, super, cache, vtable, data
meta_Rel: .quad meta_Rel, cls_Rel, 0, 0, ro_Rel_meta

        .section __DATA,__objc_classlist,regular,no_dead_strip
        .p2align 3
        .quad cls_Rel
