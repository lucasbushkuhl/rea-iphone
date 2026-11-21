// Swift 5 runtime-metadata fixture for module "WalletKit" (arm64 Mach-O).
//
// swiftc is unavailable on Linux, so this lays out the genuine Swift 5
// metadata structures by hand: context descriptors, field descriptors,
// mangled type references (including symbolic references), protocol
// descriptors and protocol conformances. Every cross-structure link is a
// real 32-bit relative pointer resolved by the linker, exactly as in a
// swiftc-built binary. Layouts follow swift/ABI/Metadata.h.

// ---------------------------------------------------------------- names
        .section __TEXT,__const
        .p2align 2
str_WalletKit:        .asciz "WalletKit"
str_Account:          .asciz "Account"
str_TransferService:  .asciz "TransferService"
str_PremiumService:   .asciz "PremiumService"
str_TransferState:    .asciz "TransferState"
str_Transferable:     .asciz "Transferable"
str_ObjCWallet:       .asciz "Wallet"

// ------------------------------------------------------ context descriptors
        .p2align 2
desc_module:                          // ModuleContextDescriptor
        .long 0x00000000              // flags: kind=Module
        .long 0                       // parent: none
        .long str_WalletKit - .       // name

        .globl "_$s9WalletKit7AccountVMn"
"_$s9WalletKit7AccountVMn":
desc_Account:                         // StructDescriptor
        .long 0x00000051              // flags: kind=Struct, unique
        .long desc_module - .         // parent
        .long str_Account - .         // name
        .long 0                       // access function
        .long fmd_Account - .         // fields
        .long 4                       // NumFields
        .long 2                       // FieldOffsetVectorOffset

desc_TransferService:                 // ClassDescriptor
        .long 0x00000050              // flags: kind=Class, unique
        .long desc_module - .
        .long str_TransferService - .
        .long 0
        .long fmd_TransferService - .
        .long 0                       // SuperclassType: none (root)
        .long 0                       // MetadataNegativeSizeInWords
        .long 0                       // MetadataPositiveSizeInWords
        .long 0                       // NumImmediateMembers
        .long 5                       // NumFields
        .long 10                      // FieldOffsetVectorOffset

desc_PremiumService:                  // ClassDescriptor with a superclass
        .long 0x00000050
        .long desc_module - .
        .long str_PremiumService - .
        .long 0
        .long fmd_PremiumService - .
        .long tr_TransferService - .  // SuperclassType -> mangled name
        .long 0
        .long 0
        .long 0
        .long 2
        .long 15

desc_TransferState:                   // EnumDescriptor
        .long 0x00000052              // flags: kind=Enum, unique
        .long desc_module - .
        .long str_TransferState - .
        .long 0
        .long fmd_TransferState - .
        .long 1                       // NumPayloadCasesAndPayloadSizeOffset
        .long 2                       // NumEmptyCases

desc_Transferable:                    // ProtocolDescriptor
        .long 0x00000043              // flags: kind=Protocol, unique
        .long desc_module - .
        .long str_Transferable - .
        .long 0                       // NumRequirementsInSignature
        .long 0                       // NumRequirements
        .long 0                       // AssociatedTypeNames

// -------------------------------------------------- protocol conformances
conf_TS_Transferable:                 // TransferService : Transferable
        .long desc_Transferable - .   // protocol (direct)
        .long desc_TransferService - .// type: DirectTypeDescriptor
        .long 0                       // witness table pattern
        .long 0x00000000              // flags: TypeReferenceKind=0

conf_TS_Hashable:                     // TransferService : Swift.Hashable
        .long (got_SHMp - .) + 1      // protocol (indirect via bound GOT slot)
        .long desc_TransferService - .
        .long 0
        .long 0x00000000

conf_Wallet_Transferable:             // ObjC class Wallet : Transferable
        .long desc_Transferable - .
        .long str_ObjCWallet - .      // type: DirectObjCClassName
        .long 0
        .long 0x00000010              // flags: TypeReferenceKind=2

// --------------------------------------------------- mangled type refs
        .section __TEXT,__swift5_typeref
tr_Si:           .asciz "Si"
tr_SS:           .asciz "SS"
tr_Sd:           .asciz "Sd"
tr_SSSg:         .asciz "SSSg"
tr_SaySiG:       .asciz "SaySiG"
tr_SDySSSdG:     .asciz "SDySSSdG"
tr_Account:      .byte 1
                 .long desc_Account - .
                 .byte 0
tr_TransferService:
                 .byte 1
                 .long desc_TransferService - .
                 .byte 0
tr_PremiumService:
                 .byte 1
                 .long desc_PremiumService - .
                 .byte 0
tr_TransferState:
                 .byte 1
                 .long desc_TransferState - .
                 .byte 0
tr_OptAccount:   .byte 1                       // Account?
                 .long desc_Account - .
                 .ascii "Sg"
                 .byte 0

// ------------------------------------------------------- field names
        .section __TEXT,__swift5_reflstr
fn_id:        .asciz "id"
fn_owner:     .asciz "owner"
fn_balance:   .asciz "balance"
fn_nickname:  .asciz "nickname"
fn_endpoint:  .asciz "endpoint"
fn_retries:   .asciz "retries"
fn_account:   .asciz "account"
fn_history:   .asciz "history"
fn_limits:    .asciz "limits"
fn_tier:      .asciz "tier"
fn_backup:    .asciz "backup"
fn_failed:    .asciz "failed"
fn_pending:   .asciz "pending"
fn_completed: .asciz "completed"

// --------------------------------------------------- field descriptors
// FieldDescriptor: MangledTypeName, Superclass, Kind(u16), RecordSize(u16),
// NumFields, then records of {Flags, MangledTypeName, FieldName}.
// Record flags: 0x2 = var (otherwise let).
        .section __TEXT,__swift5_fieldmd
        .p2align 2
fmd_Account:
        .long tr_Account - .
        .long 0
        .short 0                      // Kind: Struct
        .short 12
        .long 4
        .long 0
        .long tr_Si - .
        .long fn_id - .
        .long 0
        .long tr_SS - .
        .long fn_owner - .
        .long 2
        .long tr_Sd - .
        .long fn_balance - .
        .long 2
        .long tr_SSSg - .
        .long fn_nickname - .
fmd_TransferService:
        .long tr_TransferService - .
        .long 0
        .short 1                      // Kind: Class
        .short 12
        .long 5
        .long 0
        .long tr_SS - .
        .long fn_endpoint - .
        .long 2
        .long tr_Si - .
        .long fn_retries - .
        .long 2
        .long tr_Account - .
        .long fn_account - .
        .long 2
        .long tr_SaySiG - .
        .long fn_history - .
        .long 2
        .long tr_SDySSSdG - .
        .long fn_limits - .
fmd_PremiumService:
        .long tr_PremiumService - .
        .long tr_TransferService - .  // superclass
        .short 1
        .short 12
        .long 2
        .long 0
        .long tr_Si - .
        .long fn_tier - .
        .long 2
        .long tr_OptAccount - .
        .long fn_backup - .
fmd_TransferState:
        .long tr_TransferState - .
        .long 0
        .short 2                      // Kind: Enum
        .short 12
        .long 3
        .long 0
        .long tr_SS - .               // failed(String)
        .long fn_failed - .
        .long 0
        .long 0                       // pending (no payload)
        .long fn_pending - .
        .long 0
        .long 0                       // completed (no payload)
        .long fn_completed - .

// ------------------------------------------------- metadata index lists
        .section __TEXT,__swift5_types
        .p2align 2
        .long desc_Account - .
        .long desc_TransferService - .
        .long desc_PremiumService - .
        .long desc_TransferState - .

        .section __TEXT,__swift5_protos
        .p2align 2
        .long desc_Transferable - .

        .section __TEXT,__swift5_proto
        .p2align 2
        .long conf_TS_Transferable - .
        .long conf_TS_Hashable - .
        .long conf_Wallet_Transferable - .

// --------------------------------------- GOT-style slot for external proto
        .section __DATA,__const
        .p2align 3
got_SHMp:
        .quad "_$sSHMp"               // protocol descriptor for Swift.Hashable

// ------------------------------------------------ mangled function symbols
        .section __TEXT,__text,regular,pure_instructions
        .p2align 2
        .globl "_$s9WalletKit7AccountV7balanceSdvg"
"_$s9WalletKit7AccountV7balanceSdvg":
        ret
        .globl "_$s9WalletKit7AccountV7balanceSdvs"
"_$s9WalletKit7AccountV7balanceSdvs":
        ret
        .globl "_$s9WalletKit7AccountV5ownerSSvM"
"_$s9WalletKit7AccountV5ownerSSvM":
        ret
        .globl "_$s9WalletKit7AccountV2id5owner7balanceACSi_SSSdtcfC"
"_$s9WalletKit7AccountV2id5owner7balanceACSi_SSSdtcfC":
        ret
        .globl "_$s9WalletKit7AccountVMa"
"_$s9WalletKit7AccountVMa":
        ret
        .globl "_$s9WalletKit15TransferServiceC4send6amountySd_tF"
"_$s9WalletKit15TransferServiceC4send6amountySd_tF":
        ret
        .globl "_$s9WalletKit15TransferServiceC5fetch3url7timeoutSSSgSS_SdtYaKF"
"_$s9WalletKit15TransferServiceC5fetch3url7timeoutSSSgSS_SdtYaKF":
        ret
        .globl "_$s9WalletKit15TransferServiceCACycfC"
"_$s9WalletKit15TransferServiceCACycfC":
        ret
        .globl "_$s9WalletKit15TransferServiceCfD"
"_$s9WalletKit15TransferServiceCfD":
        ret
        .globl "_$s9WalletKit0A5ErrorO11descriptionSSvg"
"_$s9WalletKit0A5ErrorO11descriptionSSvg":
        ret
        .globl "_$s9WalletKit15TransferServiceCAA12TransferablePAAMc"
"_$s9WalletKit15TransferServiceCAA12TransferablePAAMc":
        ret
