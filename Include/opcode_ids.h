// This file is generated by /home/firebird347/projects/python/build/../cpython/Tools/cases_generator/opcode_id_generator.py
// from:
//   ../cpython/Python/bytecodes.c
// Do not edit!

#ifndef Py_OPCODE_IDS_H
#define Py_OPCODE_IDS_H
#ifdef __cplusplus
extern "C" {
#endif

/* Instruction opcodes for compiled code */
#define CACHE                                    0
#define BINARY_SLICE                             1
#define BINARY_SUBSCR                            2
#define BINARY_OP_INPLACE_ADD_UNICODE            3
#define CHECK_EG_MATCH                           4
#define CHECK_EXC_MATCH                          5
#define CLEANUP_THROW                            6
#define DELETE_SUBSCR                            7
#define END_ASYNC_FOR                            8
#define END_FOR                                  9
#define END_SEND                                10
#define EXIT_INIT_CHECK                         11
#define FORMAT_SIMPLE                           12
#define FORMAT_WITH_SPEC                        13
#define GET_AITER                               14
#define GET_ANEXT                               15
#define GET_ITER                                16
#define RESERVED                                17
#define GET_LEN                                 18
#define GET_YIELD_FROM_ITER                     19
#define INTERPRETER_EXIT                        20
#define LOAD_BUILD_CLASS                        21
#define LOAD_LOCALS                             22
#define MAKE_FUNCTION                           23
#define MATCH_KEYS                              24
#define MATCH_MAPPING                           25
#define MATCH_SEQUENCE                          26
#define NOP                                     27
#define POP_EXCEPT                              28
#define POP_TOP                                 29
#define PUSH_EXC_INFO                           30
#define PUSH_NULL                               31
#define RETURN_GENERATOR                        32
#define RETURN_VALUE                            33
#define SETUP_ANNOTATIONS                       34
#define STORE_SLICE                             35
#define STORE_SUBSCR                            36
#define TO_BOOL                                 37
#define UNARY_INVERT                            38
#define UNARY_NEGATIVE                          39
#define UNARY_NOT                               40
#define WITH_EXCEPT_START                       41
#define BINARY_OP                               42
#define BUILD_LIST                              43
#define BUILD_MAP                               44
#define BUILD_SET                               45
#define BUILD_SLICE                             46
#define BUILD_STRING                            47
#define BUILD_TUPLE                             48
#define CALL                                    49
#define CALL_FUNCTION_EX                        50
#define CALL_INTRINSIC_1                        51
#define CALL_INTRINSIC_2                        52
#define CALL_KW                                 53
#define COMPARE_OP                              54
#define CONTAINS_OP                             55
#define CONVERT_VALUE                           56
#define COPY                                    57
#define COPY_FREE_VARS                          58
#define DELETE_ATTR                             59
#define DELETE_DEREF                            60
#define DELETE_FAST                             61
#define DELETE_GLOBAL                           62
#define DELETE_NAME                             63
#define DICT_MERGE                              64
#define DICT_UPDATE                             65
#define EXTENDED_ARG                            66
#define FOR_ITER                                67
#define GET_AWAITABLE                           68
#define IMPORT_FROM                             69
#define IMPORT_NAME                             70
#define IS_OP                                   71
#define JUMP_BACKWARD                           72
#define JUMP_BACKWARD_NO_INTERRUPT              73
#define JUMP_FORWARD                            74
#define LIST_APPEND                             75
#define LIST_EXTEND                             76
#define LOAD_ATTR                               77
#define LOAD_COMMON_CONSTANT                    78
#define LOAD_CONST                              79
#define LOAD_DEREF                              80
#define LOAD_FAST                               81
#define LOAD_FAST_AND_CLEAR                     82
#define LOAD_FAST_CHECK                         83
#define LOAD_FAST_LOAD_FAST                     84
#define LOAD_FROM_DICT_OR_DEREF                 85
#define LOAD_FROM_DICT_OR_GLOBALS               86
#define LOAD_GLOBAL                             87
#define LOAD_NAME                               88
#define LOAD_SPECIAL                            89
#define LOAD_SUPER_ATTR                         90
#define MAKE_CELL                               91
#define MAP_ADD                                 92
#define MATCH_CLASS                             93
#define POP_JUMP_IF_FALSE                       94
#define POP_JUMP_IF_NONE                        95
#define POP_JUMP_IF_NOT_NONE                    96
#define POP_JUMP_IF_TRUE                        97
#define RAISE_VARARGS                           98
#define RERAISE                                 99
#define RETURN_CONST                           100
#define SEND                                   101
#define SET_ADD                                102
#define SET_FUNCTION_ATTRIBUTE                 103
#define SET_UPDATE                             104
#define STORE_ATTR                             105
#define STORE_DEREF                            106
#define STORE_FAST                             107
#define STORE_FAST_LOAD_FAST                   108
#define STORE_FAST_STORE_FAST                  109
#define STORE_GLOBAL                           110
#define STORE_NAME                             111
#define SWAP                                   112
#define UNPACK_EX                              113
#define UNPACK_SEQUENCE                        114
#define YIELD_VALUE                            115
#define _DO_CALL_FUNCTION_EX                   116
#define RESUME                                 149
#define BINARY_OP_ADD_FLOAT                    150
#define BINARY_OP_ADD_INT                      151
#define BINARY_OP_ADD_UNICODE                  152
#define BINARY_OP_MULTIPLY_FLOAT               153
#define BINARY_OP_MULTIPLY_INT                 154
#define BINARY_OP_SUBTRACT_FLOAT               155
#define BINARY_OP_SUBTRACT_INT                 156
#define BINARY_SUBSCR_DICT                     157
#define BINARY_SUBSCR_GETITEM                  158
#define BINARY_SUBSCR_LIST_INT                 159
#define BINARY_SUBSCR_STR_INT                  160
#define BINARY_SUBSCR_TUPLE_INT                161
#define CALL_ALLOC_AND_ENTER_INIT              162
#define CALL_BOUND_METHOD_EXACT_ARGS           163
#define CALL_BOUND_METHOD_GENERAL              164
#define CALL_BUILTIN_CLASS                     165
#define CALL_BUILTIN_FAST                      166
#define CALL_BUILTIN_FAST_WITH_KEYWORDS        167
#define CALL_BUILTIN_O                         168
#define CALL_ISINSTANCE                        169
#define CALL_KW_BOUND_METHOD                   170
#define CALL_KW_NON_PY                         171
#define CALL_KW_PY                             172
#define CALL_LEN                               173
#define CALL_LIST_APPEND                       174
#define CALL_METHOD_DESCRIPTOR_FAST            175
#define CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS 176
#define CALL_METHOD_DESCRIPTOR_NOARGS          177
#define CALL_METHOD_DESCRIPTOR_O               178
#define CALL_NON_PY_GENERAL                    179
#define CALL_PY_EXACT_ARGS                     180
#define CALL_PY_GENERAL                        181
#define CALL_STR_1                             182
#define CALL_TUPLE_1                           183
#define CALL_TYPE_1                            184
#define COMPARE_OP_FLOAT                       185
#define COMPARE_OP_INT                         186
#define COMPARE_OP_STR                         187
#define CONTAINS_OP_DICT                       188
#define CONTAINS_OP_SET                        189
#define FOR_ITER_GEN                           190
#define FOR_ITER_LIST                          191
#define FOR_ITER_RANGE                         192
#define FOR_ITER_TUPLE                         193
#define LOAD_ATTR_CLASS                        194
#define LOAD_ATTR_CLASS_WITH_METACLASS_CHECK   195
#define LOAD_ATTR_GETATTRIBUTE_OVERRIDDEN      196
#define LOAD_ATTR_INSTANCE_VALUE               197
#define LOAD_ATTR_METHOD_LAZY_DICT             198
#define LOAD_ATTR_METHOD_NO_DICT               199
#define LOAD_ATTR_METHOD_WITH_VALUES           200
#define LOAD_ATTR_MODULE                       201
#define LOAD_ATTR_NONDESCRIPTOR_NO_DICT        202
#define LOAD_ATTR_NONDESCRIPTOR_WITH_VALUES    203
#define LOAD_ATTR_PROPERTY                     204
#define LOAD_ATTR_SLOT                         205
#define LOAD_ATTR_WITH_HINT                    206
#define LOAD_GLOBAL_BUILTIN                    207
#define LOAD_GLOBAL_MODULE                     208
#define LOAD_SUPER_ATTR_ATTR                   209
#define LOAD_SUPER_ATTR_METHOD                 210
#define RESUME_CHECK                           211
#define SEND_GEN                               212
#define STORE_ATTR_INSTANCE_VALUE              213
#define STORE_ATTR_SLOT                        214
#define STORE_ATTR_WITH_HINT                   215
#define STORE_SUBSCR_DICT                      216
#define STORE_SUBSCR_LIST_INT                  217
#define TO_BOOL_ALWAYS_TRUE                    218
#define TO_BOOL_BOOL                           219
#define TO_BOOL_INT                            220
#define TO_BOOL_LIST                           221
#define TO_BOOL_NONE                           222
#define TO_BOOL_STR                            223
#define UNPACK_SEQUENCE_LIST                   224
#define UNPACK_SEQUENCE_TUPLE                  225
#define UNPACK_SEQUENCE_TWO_TUPLE              226
#define INSTRUMENTED_END_FOR                   236
#define INSTRUMENTED_END_SEND                  237
#define INSTRUMENTED_LOAD_SUPER_ATTR           238
#define INSTRUMENTED_FOR_ITER                  239
#define INSTRUMENTED_CALL_KW                   240
#define INSTRUMENTED_CALL_FUNCTION_EX          241
#define INSTRUMENTED_INSTRUCTION               242
#define INSTRUMENTED_JUMP_FORWARD              243
#define INSTRUMENTED_POP_JUMP_IF_TRUE          244
#define INSTRUMENTED_POP_JUMP_IF_FALSE         245
#define INSTRUMENTED_POP_JUMP_IF_NONE          246
#define INSTRUMENTED_POP_JUMP_IF_NOT_NONE      247
#define INSTRUMENTED_RESUME                    248
#define INSTRUMENTED_RETURN_VALUE              249
#define INSTRUMENTED_RETURN_CONST              250
#define INSTRUMENTED_YIELD_VALUE               251
#define INSTRUMENTED_CALL                      252
#define INSTRUMENTED_JUMP_BACKWARD             253
#define INSTRUMENTED_LINE                      254
#define ENTER_EXECUTOR                         255
#define JUMP                                   256
#define JUMP_NO_INTERRUPT                      257
#define LOAD_CLOSURE                           258
#define POP_BLOCK                              259
#define SETUP_CLEANUP                          260
#define SETUP_FINALLY                          261
#define SETUP_WITH                             262
#define STORE_FAST_MAYBE_NULL                  263

#define HAVE_ARGUMENT                           41
#define MIN_SPECIALIZED_OPCODE                 150
#define MIN_INSTRUMENTED_OPCODE                236

#ifdef __cplusplus
}
#endif
#endif /* !Py_OPCODE_IDS_H */
