# Argument Clinic
# Copyright 2012-2013 by Larry Hastings.
# Licensed to the PSF under a contributor agreement.

from functools import partial
from test import support, test_tools
from test.support import force_not_colorized_test_class
from test.support import os_helper
from test.support.os_helper import TESTFN, unlink, rmtree
from textwrap import dedent
from unittest import TestCase
import ast
import difflib
import importlib
import inspect
import os.path
import re
import sys
import types
import unittest
import warnings

test_tools.skip_if_missing('clinic')
with test_tools.imports_under_tool('clinic'):
    import libclinic
    from libclinic import ClinicError, unspecified, NULL, fail
    from libclinic.converters import (
        int_converter, object_converter, str_converter, self_converter)
    from libclinic.function import (
        Module, Class, Function, FunctionKind, Parameter,
        permute_optional_groups, permute_right_option_groups,
        permute_left_option_groups)
    import clinic
    from libclinic.clanguage import CLanguage
    from libclinic.converter import converters, legacy_converters
    from libclinic.return_converters import return_converters, int_return_converter
    from libclinic.block_parser import Block, BlockParser
    from libclinic.codegen import BlockPrinter, Destination
    from libclinic.dsl_parser import DSLParser
    from libclinic.cli import parse_file, Clinic
    from libclinic.errors import SpecError, SpecErrorKind
    from libclinic.pyspec import runtime as pyspec_runtime
    from libclinic.pyspec import (builtin_types as pyspec_builtin_types,
                                  call_table as pyspec_call_table,
                                  facts as pyspec_facts,
                                  frontend as pyspec_frontend,
                                  partial_eval as pyspec_partial_eval,
                                  slots as pyspec_slots,
                                  specfiles as pyspec_specfiles,
                                  subset as pyspec_subset)


def repeat_fn(*functions):
    def wrapper(test):
        def wrapped(self):
            for fn in functions:
                with self.subTest(fn=fn):
                    test(self, fn)
        return wrapped
    return wrapper

def _make_clinic(*, filename='clinic_tests', limited_capi=False):
    clang = CLanguage(filename)
    c = Clinic(clang, filename=filename, limited_capi=limited_capi)
    c.block_parser = BlockParser('', clang)
    return c


def _expect_failure(tc, parser, code, errmsg, *, filename=None, lineno=None,
                    strip=True):
    """Helper for the parser tests.

    tc: unittest.TestCase; passed self in the wrapper
    parser: the clinic parser used for this test case
    code: a str with input text (clinic code)
    errmsg: the expected error message
    filename: str, optional filename
    lineno: int, optional line number
    """
    code = dedent(code)
    if strip:
        code = code.strip()
    errmsg = re.escape(errmsg)
    with tc.assertRaisesRegex(ClinicError, errmsg) as cm:
        parser(code)
    if filename is not None:
        tc.assertEqual(cm.exception.filename, filename)
    if lineno is not None:
        tc.assertEqual(cm.exception.lineno, lineno)
    return cm.exception


def restore_dict(converters, old_converters):
    converters.clear()
    converters.update(old_converters)


def save_restore_converters(testcase):
    testcase.addCleanup(restore_dict, converters,
                        converters.copy())
    testcase.addCleanup(restore_dict, legacy_converters,
                        legacy_converters.copy())
    testcase.addCleanup(restore_dict, return_converters,
                        return_converters.copy())


class ClinicWholeFileTest(TestCase):
    maxDiff = None

    def expect_failure(self, raw, errmsg, *, filename=None, lineno=None):
        _expect_failure(self, self.clinic.parse, raw, errmsg,
                        filename=filename, lineno=lineno)

    def setUp(self):
        save_restore_converters(self)
        self.clinic = _make_clinic(filename="test.c")

    def test_eol(self):
        # regression test:
        # clinic's block parser didn't recognize
        # the "end line" for the block if it
        # didn't end in "\n" (as in, the last)
        # byte of the file was '/'.
        # so it would spit out an end line for you.
        # and since you really already had one,
        # the last line of the block got corrupted.
        raw = "/*[clinic]\nfoo\n[clinic]*/"
        cooked = self.clinic.parse(raw).splitlines()
        end_line = cooked[2].rstrip()
        # this test is redundant, it's just here explicitly to catch
        # the regression test so we don't forget what it looked like
        self.assertNotEqual(end_line, "[clinic]*/[clinic]*/")
        self.assertEqual(end_line, "[clinic]*/")

    def test_mangled_marker_line(self):
        raw = """
            /*[clinic input]
            [clinic start generated code]*/
            /*[clinic end generated code: foo]*/
        """
        err = (
            "Mangled Argument Clinic marker line: "
            "'/*[clinic end generated code: foo]*/'"
        )
        self.expect_failure(raw, err, filename="test.c", lineno=3)

    def test_checksum_mismatch(self):
        raw = """
            /*[clinic input]
            [clinic start generated code]*/
            /*[clinic end generated code: output=0123456789abcdef input=fedcba9876543210]*/
        """
        err = ("Checksum mismatch! "
               "Expected '0123456789abcdef', computed 'da39a3ee5e6b4b0d'")
        self.expect_failure(raw, err, filename="test.c", lineno=3)

    def test_garbage_after_stop_line(self):
        raw = """
            /*[clinic input]
            [clinic start generated code]*/foobarfoobar!
        """
        err = "Garbage after stop line: 'foobarfoobar!'"
        self.expect_failure(raw, err, filename="test.c", lineno=2)

    def test_whitespace_before_stop_line(self):
        raw = """
            /*[clinic input]
             [clinic start generated code]*/
        """
        err = (
            "Whitespace is not allowed before the stop line: "
            "' [clinic start generated code]*/'"
        )
        self.expect_failure(raw, err, filename="test.c", lineno=2)

    def test_parse_with_body_prefix(self):
        clang = CLanguage(None)
        clang.body_prefix = "//"
        clang.start_line = "//[{dsl_name} start]"
        clang.stop_line = "//[{dsl_name} stop]"
        cl = Clinic(clang, filename="test.c", limited_capi=False)
        raw = dedent("""
            //[clinic start]
            //module test
            //[clinic stop]
        """).strip()
        out = cl.parse(raw)
        expected = dedent("""
            //[clinic start]
            //module test
            //
            //[clinic stop]
            /*[clinic end generated code: output=da39a3ee5e6b4b0d input=65fab8adff58cf08]*/
        """).lstrip()  # Note, lstrip() because of the newline
        self.assertEqual(out, expected)

    def test_cpp_monitor_fail_nested_block_comment(self):
        raw = """
            /* start
            /* nested
            */
            */
        """
        err = 'Nested block comment!'
        self.expect_failure(raw, err, filename="test.c", lineno=2)

    def test_cpp_monitor_fail_invalid_format_noarg(self):
        raw = """
            #if
            a()
            #endif
        """
        err = 'Invalid format for #if line: no argument!'
        self.expect_failure(raw, err, filename="test.c", lineno=1)

    def test_cpp_monitor_fail_invalid_format_toomanyargs(self):
        raw = """
            #ifdef A B
            a()
            #endif
        """
        err = 'Invalid format for #ifdef line: should be exactly one argument!'
        self.expect_failure(raw, err, filename="test.c", lineno=1)

    def test_cpp_monitor_fail_no_matching_if(self):
        raw = '#else'
        err = '#else without matching #if / #ifdef / #ifndef!'
        self.expect_failure(raw, err, filename="test.c", lineno=1)

    def test_directive_output_unknown_preset(self):
        raw = """
            /*[clinic input]
            output preset nosuchpreset
            [clinic start generated code]*/
        """
        err = "Unknown preset 'nosuchpreset'"
        self.expect_failure(raw, err)

    def test_directive_output_cant_pop(self):
        raw = """
            /*[clinic input]
            output pop
            [clinic start generated code]*/
        """
        err = "Can't 'output pop', stack is empty"
        self.expect_failure(raw, err)

    def test_directive_output_print(self):
        raw = dedent("""
            /*[clinic input]
            output print 'I told you once.'
            [clinic start generated code]*/
        """)
        out = self.clinic.parse(raw)
        # The generated output will differ for every run, but we can check that
        # it starts with the clinic block, we check that it contains all the
        # expected fields, and we check that it contains the checksum line.
        self.assertStartsWith(out, dedent("""
            /*[clinic input]
            output print 'I told you once.'
            [clinic start generated code]*/
        """))
        fields = {
            "cpp_endif",
            "cpp_if",
            "docstring_definition",
            "docstring_prototype",
            "impl_definition",
            "impl_prototype",
            "methoddef_define",
            "methoddef_ifndef",
            "parser_definition",
            "parser_prototype",
        }
        for field in fields:
            with self.subTest(field=field):
                self.assertIn(field, out)
        last_line = out.rstrip().split("\n")[-1]
        self.assertStartsWith(last_line, "/*[clinic end generated code: output=")

    def test_directive_wrong_arg_number(self):
        raw = dedent("""
            /*[clinic input]
            preserve foo bar baz eggs spam ham mushrooms
            [clinic start generated code]*/
        """)
        err = "takes 1 positional argument but 8 were given"
        self.expect_failure(raw, err)

    def test_unknown_destination_command(self):
        raw = """
            /*[clinic input]
            destination buffer nosuchcommand
            [clinic start generated code]*/
        """
        err = "unknown destination command 'nosuchcommand'"
        self.expect_failure(raw, err)

    def test_no_access_to_members_in_converter_init(self):
        raw = """
            /*[python input]
            class Custom_converter(CConverter):
                converter = "some_c_function"
                def converter_init(self):
                    self.function.noaccess
            [python start generated code]*/
            /*[clinic input]
            module test
            test.fn
                a: Custom
            [clinic start generated code]*/
        """
        err = (
            "accessing self.function inside converter_init is disallowed!"
        )
        self.expect_failure(raw, err)

    def test_clone_mismatch(self):
        err = "'kind' of function and cloned function don't match!"
        block = """
            /*[clinic input]
            module m
            @classmethod
            m.f1
                a: object
            [clinic start generated code]*/
            /*[clinic input]
            @staticmethod
            m.f2 = m.f1
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=9)

    def test_badly_formed_return_annotation(self):
        err = "Badly formed annotation for 'm.f': 'Custom'"
        block = """
            /*[python input]
            class Custom_return_converter(CReturnConverter):
                def __init__(self):
                    raise ValueError("abc")
            [python start generated code]*/
            /*[clinic input]
            module m
            m.f -> Custom
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=8)

    def test_ambiguous_group_and_optional_parameters(self):
        err = ("Function 'my_test_func' has an ambiguous group configuration: "
               "a call with 2 argument(s) can be parsed in more than one way.")
        block = """
            /*[clinic input]
            my_test_func

                [
                a: object
                b: object
                ]
                c: object = None
                d: object = None
                /
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=2)

    def test_star_after_vararg(self):
        err = "'my_test_func' uses '*' more than once."
        block = """
            /*[clinic input]
            my_test_func

                pos_arg: object
                *args: tuple
                *
                kw_arg: object
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=6)

    def test_vararg_after_star(self):
        err = "'my_test_func' uses '*' more than once."
        block = """
            /*[clinic input]
            my_test_func

                pos_arg: object
                *
                *args: tuple
                kw_arg: object
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=6)

    def test_double_star_after_var_keyword(self):
        err = "Function 'my_test_func' has an invalid parameter declaration (**kwargs?): '**kwds: dict'"
        block = """
            /*[clinic input]
            my_test_func

                pos_arg: object
                **kwds: dict
                **
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=5)

    def test_var_keyword_after_star(self):
        err = "Function 'my_test_func' has an invalid parameter declaration: '**'"
        block = """
            /*[clinic input]
            my_test_func

                pos_arg: object
                **
                **kwds: dict
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=5)

    def test_module_already_got_one(self):
        err = "Already defined module 'm'!"
        block = """
            /*[clinic input]
            module m
            module m
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=3)

    def test_destination_already_got_one(self):
        err = "Destination already exists: 'test'"
        block = """
            /*[clinic input]
            destination test new buffer
            destination test new buffer
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=3)

    def test_destination_does_not_exist(self):
        err = "Destination does not exist: '/dev/null'"
        block = """
            /*[clinic input]
            output everything /dev/null
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=2)

    def test_class_already_got_one(self):
        err = "Already defined class 'C'!"
        block = """
            /*[clinic input]
            class C "" ""
            class C "" ""
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=3)

    def test_cant_nest_module_inside_class(self):
        err = "Can't nest a module inside a class!"
        block = """
            /*[clinic input]
            class C "" ""
            module C.m
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=3)

    def test_dest_buffer_not_empty_at_eof(self):
        expected_warning = ("Destination buffer 'buffer' not empty at "
                            "end of file, emptying.")
        expected_generated = dedent("""
            /*[clinic input]
            output everything buffer
            fn
                a: object
                /
            [clinic start generated code]*/
            /*[clinic end generated code: output=da39a3ee5e6b4b0d input=1c4668687f5fd002]*/

            /*[clinic input]
            dump buffer
            [clinic start generated code]*/

            PyDoc_VAR(fn__doc__);

            PyDoc_STRVAR(fn__doc__,
            "fn($module, a, /)\\n"
            "--\\n"
            "\\n");

            #define FN_METHODDEF    \\
                {"fn", (PyCFunction)fn, METH_O, fn__doc__},

            static PyObject *
            fn(PyObject *module, PyObject *a)
            /*[clinic end generated code: output=be6798b148ab4e53 input=524ce2e021e4eba6]*/
        """)
        block = dedent("""
            /*[clinic input]
            output everything buffer
            fn
                a: object
                /
            [clinic start generated code]*/
        """)
        with support.captured_stdout() as stdout:
            generated = self.clinic.parse(block)
        self.assertIn(expected_warning, stdout.getvalue())
        self.assertEqual(generated, expected_generated)

    def test_dest_clear(self):
        err = "Can't clear destination 'file': it's not of type 'buffer'"
        block = """
            /*[clinic input]
            destination file clear
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=2)

    def test_directive_set_misuse(self):
        err = "unknown variable 'ets'"
        block = """
            /*[clinic input]
            set ets tse
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=2)

    def test_directive_set_prefix(self):
        block = dedent("""
            /*[clinic input]
            set line_prefix '// '
            output everything suppress
            output docstring_prototype buffer
            fn
                a: object
                /
            [clinic start generated code]*/
            /* We need to dump the buffer.
             * If not, Argument Clinic will emit a warning */
            /*[clinic input]
            dump buffer
            [clinic start generated code]*/
        """)
        generated = self.clinic.parse(block)
        expected_docstring_prototype = "// PyDoc_VAR(fn__doc__);"
        self.assertIn(expected_docstring_prototype, generated)

    def test_directive_set_suffix(self):
        block = dedent("""
            /*[clinic input]
            set line_suffix '  // test'
            output everything suppress
            output docstring_prototype buffer
            fn
                a: object
                /
            [clinic start generated code]*/
            /* We need to dump the buffer.
             * If not, Argument Clinic will emit a warning */
            /*[clinic input]
            dump buffer
            [clinic start generated code]*/
        """)
        generated = self.clinic.parse(block)
        expected_docstring_prototype = "PyDoc_VAR(fn__doc__);  // test"
        self.assertIn(expected_docstring_prototype, generated)

    def test_directive_set_prefix_and_suffix(self):
        block = dedent("""
            /*[clinic input]
            set line_prefix '{block comment start} '
            set line_suffix ' {block comment end}'
            output everything suppress
            output docstring_prototype buffer
            fn
                a: object
                /
            [clinic start generated code]*/
            /* We need to dump the buffer.
             * If not, Argument Clinic will emit a warning */
            /*[clinic input]
            dump buffer
            [clinic start generated code]*/
        """)
        generated = self.clinic.parse(block)
        expected_docstring_prototype = "/* PyDoc_VAR(fn__doc__); */"
        self.assertIn(expected_docstring_prototype, generated)

    def test_directive_printout(self):
        block = dedent("""
            /*[clinic input]
            output everything buffer
            printout test
            [clinic start generated code]*/
        """)
        expected = dedent("""
            /*[clinic input]
            output everything buffer
            printout test
            [clinic start generated code]*/
            test
            /*[clinic end generated code: output=4e1243bd22c66e76 input=898f1a32965d44ca]*/
        """)
        generated = self.clinic.parse(block)
        self.assertEqual(generated, expected)

    def test_directive_preserve_twice(self):
        err = "Can't have 'preserve' twice in one block!"
        block = """
            /*[clinic input]
            preserve
            preserve
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=3)

    def test_directive_preserve_input(self):
        err = "'preserve' only works for blocks that don't produce any output!"
        block = """
            /*[clinic input]
            preserve
            fn
                a: object
                /
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=6)

    def test_directive_preserve_output(self):
        block = dedent("""
            /*[clinic input]
            output everything buffer
            preserve
            [clinic start generated code]*/
            // Preserve this
            /*[clinic end generated code: output=eaa49677ae4c1f7d input=559b5db18fddae6a]*/
            /*[clinic input]
            dump buffer
            [clinic start generated code]*/
            /*[clinic end generated code: output=da39a3ee5e6b4b0d input=524ce2e021e4eba6]*/
        """)
        generated = self.clinic.parse(block)
        self.assertEqual(generated, block)

    def test_directive_output_invalid_command(self):
        err = dedent("""
            Invalid command or destination name 'cmd'. Must be one of:
             - 'preset'
             - 'push'
             - 'pop'
             - 'print'
             - 'everything'
             - 'cpp_if'
             - 'docstring_prototype'
             - 'docstring_definition'
             - 'methoddef_define'
             - 'impl_prototype'
             - 'parser_prototype'
             - 'parser_helper'
             - 'parser_definition'
             - 'vectorcall_definition'
             - 'cpp_endif'
             - 'methoddef_ifndef'
             - 'impl_definition'
        """).strip()
        block = """
            /*[clinic input]
            output cmd buffer
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=2)

    def test_validate_cloned_init(self):
        block = """
            /*[clinic input]
            class C "void *" ""
            C.meth
              a: int
            [clinic start generated code]*/
            /*[clinic input]
            @classmethod
            C.__init__ = C.meth
            [clinic start generated code]*/
        """
        err = "'__init__' must be a normal method; got 'FunctionKind.CLASS_METHOD'!"
        self.expect_failure(block, err, lineno=8)

    def test_validate_cloned_new(self):
        block = """
            /*[clinic input]
            class C "void *" ""
            C.meth
              a: int
            [clinic start generated code]*/
            /*[clinic input]
            C.__new__ = C.meth
            [clinic start generated code]*/
        """
        err = "'__new__' must be a class method"
        self.expect_failure(block, err, lineno=7)

    def test_no_c_basename_cloned(self):
        block = """
            /*[clinic input]
            foo2
            [clinic start generated code]*/
            /*[clinic input]
            foo as = foo2
            [clinic start generated code]*/
        """
        err = "No C basename provided after 'as' keyword"
        self.expect_failure(block, err, lineno=5)

    def test_cloned_with_custom_c_basename(self):
        raw = dedent("""
            /*[clinic input]
            # Make sure we don't create spurious clinic/ directories.
            output everything suppress
            foo2
            [clinic start generated code]*/

            /*[clinic input]
            foo as foo1 = foo2
            [clinic start generated code]*/
        """)
        self.clinic.parse(raw)
        funcs = self.clinic.functions
        self.assertEqual(len(funcs), 2)
        self.assertEqual(funcs[1].name, "foo")
        self.assertEqual(funcs[1].c_basename, "foo1")

    def test_cloned_with_illegal_c_basename(self):
        block = """
            /*[clinic input]
            class C "void *" ""
            foo1
            [clinic start generated code]*/

            /*[clinic input]
            foo2 as .illegal. = foo1
            [clinic start generated code]*/
        """
        err = "Illegal C basename: '.illegal.'"
        self.expect_failure(block, err, lineno=7)

    def test_cloned_forced_text_signature(self):
        block = dedent("""
            /*[clinic input]
            @text_signature "($module, a[, b])"
            src
                a: object
                    param a
                b: object = NULL
                /

            docstring
            [clinic start generated code]*/

            /*[clinic input]
            dst = src
            [clinic start generated code]*/
        """)
        self.clinic.parse(block)
        self.addCleanup(rmtree, "clinic")
        funcs = self.clinic.functions
        self.assertEqual(len(funcs), 2)

        src_docstring_lines = funcs[0].docstring.split("\n")
        dst_docstring_lines = funcs[1].docstring.split("\n")

        # Signatures are copied.
        self.assertEqual(src_docstring_lines[0], "src($module, a[, b])")
        self.assertEqual(dst_docstring_lines[0], "dst($module, a[, b])")

        # Param docstrings are copied.
        self.assertIn("    param a", src_docstring_lines)
        self.assertIn("    param a", dst_docstring_lines)

        # Docstrings are not copied.
        self.assertIn("docstring", src_docstring_lines)
        self.assertNotIn("docstring", dst_docstring_lines)

    def test_cloned_forced_text_signature_illegal(self):
        block = """
            /*[clinic input]
            @text_signature "($module, a[, b])"
            src
                a: object
                b: object = NULL
                /
            [clinic start generated code]*/

            /*[clinic input]
            @text_signature "($module, a_override[, b])"
            dst = src
            [clinic start generated code]*/
        """
        err = "Cannot use @text_signature when cloning a function"
        self.expect_failure(block, err, lineno=11)

    def test_ignore_preprocessor_in_comments(self):
        for dsl in "clinic", "python":
            raw = dedent(f"""\
                /*[{dsl} input]
                # CPP directives, valid or not, should be ignored in C comments.
                #
                [{dsl} start generated code]*/
            """)
            self.clinic.parse(raw)

    def test_var_keyword_non_dict(self):
        err = "'var_keyword_object' is not a valid converter"
        block = """
            /*[clinic input]
            my_test_func

                **kwds: object
            [clinic start generated code]*/
        """
        self.expect_failure(block, err, lineno=4)

    def test_getset_in_ifdef(self):
        block = """
            /*[clinic input]
            output everything block
            output methoddef_ifndef buffer
            class Foo "FooObject *" "&Foo_Type"
            [clinic start generated code]*/
            #ifdef CONDITION
            /*[clinic input]
            @getter
            Foo.property
            [clinic start generated code]*/
            /*[clinic input]
            @setter
            Foo.property
                value: object
            [clinic start generated code]*/
            #endif
            /*[clinic input]
            dump buffer
            [clinic start generated code]*/
        """
        generated = self.clinic.parse(dedent(block))
        self.assertIn("#if defined(CONDITION)", generated)
        # The getset is undefined if the condition is false.
        self.assertIn("#else\n"
                      "#  define FOO_PROPERTY_GETSETDEF\n"
                      "#endif",
                      generated)

    def test_getset_partially_in_ifdef(self):
        block = """
            /*[clinic input]
            output everything block
            output methoddef_ifndef buffer
            class Foo "FooObject *" "&Foo_Type"
            [clinic start generated code]*/
            #ifdef CONDITION
            /*[clinic input]
            @getter
            Foo.property
            [clinic start generated code]*/
            #endif
            /*[clinic input]
            @setter
            Foo.property
                value: object
            [clinic start generated code]*/
            /*[clinic input]
            dump buffer
            [clinic start generated code]*/
        """
        generated = self.clinic.parse(dedent(block))
        # Only the conditional getter announces itself.
        self.assertIn("#if defined(CONDITION)\n"
                      "\n"
                      "#define FOO_PROPERTY_GETTER Foo_property_get\n",
                      generated)
        self.assertIn("#define FOO_PROPERTY_SETTER Foo_property_set\n"
                      "#if defined(FOO_PROPERTY_GETTER) "
                      "|| defined(FOO_PROPERTY_SETTER)",
                      generated)
        self.assertIn('#  define FOO_PROPERTY_GETSETDEF {"property", '
                      '(getter)FOO_PROPERTY_GETTER, '
                      '(setter)FOO_PROPERTY_SETTER, FOO_PROPERTY_DOCSTR},',
                      generated)

    def test_getset_several_implementations(self):
        block = """
            /*[clinic input]
            output everything block
            output methoddef_ifndef buffer
            class Foo "FooObject *" "&Foo_Type"
            [clinic start generated code]*/
            #ifdef CONDITION
            /*[clinic input]
            @getter
            Foo.property as foo_property_special
            [clinic start generated code]*/
            #else
            /*[clinic input]
            @getter
            Foo.property as foo_property_generic
            [clinic start generated code]*/
            #endif
            /*[clinic input]
            dump buffer
            [clinic start generated code]*/
        """
        # Implementations guarded by preprocessor conditions can share the
        # entry; which of them is compiled is only known to the preprocessor.
        generated = self.clinic.parse(dedent(block))
        self.assertIn("#if defined(CONDITION)\n"
                      "\n"
                      "#define FOO_PROPERTY_GETTER "
                      "foo_property_special_get\n",
                      generated)
        self.assertIn("#if !defined(CONDITION)\n"
                      "\n"
                      "#define FOO_PROPERTY_GETTER "
                      "foo_property_generic_get\n",
                      generated)

    def test_getset_after_dump(self):
        block = """
            /*[clinic input]
            output everything block
            output methoddef_ifndef buffer
            class Foo "FooObject *" "&Foo_Type"
            [clinic start generated code]*/
            /*[clinic input]
            @getter
            Foo.property
            [clinic start generated code]*/
            /*[clinic input]
            dump buffer
            [clinic start generated code]*/
            /*[clinic input]
            @setter
            Foo.property
                value: object
            [clinic start generated code]*/
        """
        err = ("All accessors of 'Foo.property' must be defined before "
               "its PyGetSetDef entry is dumped")
        self.expect_failure(block, err, lineno=15)

    def test_setter_deletion_check(self):
        block = """
            /*[clinic input]
            output everything block
            class Foo "FooObject *" "&Foo_Type"
            [clinic start generated code]*/
            /*[clinic input]
            @setter
            Foo.property
                value: object
            [clinic start generated code]*/
        """
        generated = self.clinic.parse(dedent(block))
        self.assertIn("if (arg == NULL) {", generated)
        self.assertIn("\"attribute 'property' of '%.100s' objects "
                      "cannot be deleted\"", generated)

    def test_deleter(self):
        # @deleter means that the setter is called with NULL to delete
        # the attribute, so it checks the value itself.
        block = """
            /*[clinic input]
            output everything block
            class Foo "FooObject *" "&Foo_Type"
            [clinic start generated code]*/
            /*[clinic input]
            @setter
            @deleter
            Foo.property
                value: object = NULL
            [clinic start generated code]*/
        """
        generated = self.clinic.parse(dedent(block))
        self.assertNotIn("if (arg == NULL) {", generated)

    def test_getset_duplicate(self):
        # Only a setter defines the new value.
        for annotation, parameter, err in (
            ("@getter", "", "Cannot apply @getter to 'Foo.property' twice"),
            ("@setter", "value: object",
             "The setter of 'Foo.property' is already defined"),
        ):
            with self.subTest(annotation=annotation):
                self.clinic = _make_clinic(filename="test.c")
                block = f"""
                    /*[clinic input]
                    class Foo "FooObject *" "&Foo_Type"
                    [clinic start generated code]*/
                    /*[clinic input]
                    {annotation}
                    Foo.property
                        {parameter}
                    [clinic start generated code]*/
                    /*[clinic input]
                    {annotation}
                    Foo.property
                        {parameter}
                    [clinic start generated code]*/
                """
                self.expect_failure(block, err, lineno=11)

    def test_getset_different_c_basename(self):
        block = """
            /*[clinic input]
            output everything block
            output methoddef_ifndef buffer
            class Foo "FooObject *" "&Foo_Type"
            [clinic start generated code]*/
            /*[clinic input]
            @getter
            Foo.property as foo_get
            [clinic start generated code]*/
            /*[clinic input]
            @setter
            Foo.property as foo_set
                value: object
            [clinic start generated code]*/
            /*[clinic input]
            dump buffer
            [clinic start generated code]*/
        """
        # The accessors are identified by the Python name, not by the
        # C basename.
        generated = self.clinic.parse(dedent(block))
        self.assertIn('#define FOO_PROPERTY_GETSETDEF {"property", '
                      '(getter)foo_get_get, (setter)foo_set_set, NULL},',
                      generated)


class ParseFileUnitTest(TestCase):
    def expect_parsing_failure(
        self, *, filename, expected_error, verify=True, output=None
    ):
        errmsg = re.escape(dedent(expected_error).strip())
        with self.assertRaisesRegex(ClinicError, errmsg):
            parse_file(filename, limited_capi=False)

    def test_parse_file_no_extension(self) -> None:
        self.expect_parsing_failure(
            filename="foo",
            expected_error="Can't extract file type for file 'foo'"
        )

    def test_parse_file_strange_extension(self) -> None:
        filenames_to_errors = {
            "foo.rs": "Can't identify file type for file 'foo.rs'",
            "foo.hs": "Can't identify file type for file 'foo.hs'",
            "foo.js": "Can't identify file type for file 'foo.js'",
        }
        for filename, errmsg in filenames_to_errors.items():
            with self.subTest(filename=filename):
                self.expect_parsing_failure(filename=filename, expected_error=errmsg)


class ClinicGroupPermuterTest(TestCase):
    def _test(self, l, m, r, output):
        computed = permute_optional_groups(l, m, r)
        self.assertEqual(output, computed)

    def test_range(self):
        self._test([[['start']]], ['stop'], [[['step']]],
          (
            ('stop',),
            ('start', 'stop',),
            ('start', 'stop', 'step',),
          ))

    def test_add_window(self):
        self._test([[['x', 'y']]], ['ch'], [[['attr']]],
          (
            ('ch',),
            ('ch', 'attr'),
            ('x', 'y', 'ch',),
            ('x', 'y', 'ch', 'attr'),
          ))

    def test_ludicrous(self):
        self._test([[['a1', 'a2', 'a3'], ['b1', 'b2']]], ['c1'],
                   [[['d1', 'd2'], ['e1', 'e2', 'e3']]],
          (
          ('c1',),
          ('b1', 'b2', 'c1'),
          ('b1', 'b2', 'c1', 'd1', 'd2'),
          ('a1', 'a2', 'a3', 'b1', 'b2', 'c1'),
          ('a1', 'a2', 'a3', 'b1', 'b2', 'c1', 'd1', 'd2'),
          ('a1', 'a2', 'a3', 'b1', 'b2', 'c1', 'd1', 'd2', 'e1', 'e2', 'e3'),
          ))

    def test_right_only(self):
        self._test([], [], [[['a'],['b'],['c']]],
          (
          (),
          ('a',),
          ('a', 'b'),
          ('a', 'b', 'c')
          ))

    def test_chgat(self):
        # Two independent groups on the left.
        self._test([[['y', 'x']], [['n']]], ['attr'], [],
          (
          ('attr',),
          ('n', 'attr'),
          ('y', 'x', 'attr'),
          ('y', 'x', 'n', 'attr'),
          ))

    def test_independent_groups_on_the_right(self):
        self._test([], ['a'], [[['b']], [['c', 'd']]],
          (
          ('a',),
          ('a', 'b'),
          ('a', 'c', 'd'),
          ('a', 'b', 'c', 'd'),
          ))

    def test_have_left_options_but_required_is_empty(self):
        def fn():
            permute_optional_groups([[['a']]], [], [])
        self.assertRaises(ValueError, fn)


class ClinicLinearFormatTest(TestCase):
    def _test(self, input, output, **kwargs):
        computed = libclinic.linear_format(input, **kwargs)
        self.assertEqual(output, computed)

    def test_empty_strings(self):
        self._test('', '')

    def test_solo_newline(self):
        self._test('\n', '\n')

    def test_no_substitution(self):
        self._test("""
          abc
        """, """
          abc
        """)

    def test_empty_substitution(self):
        self._test("""
          abc
          {name}
          def
        """, """
          abc
          def
        """, name='')

    def test_single_line_substitution(self):
        self._test("""
          abc
          {name}
          def
        """, """
          abc
          GARGLE
          def
        """, name='GARGLE')

    def test_multiline_substitution(self):
        self._test("""
          abc
          {name}
          def
        """, """
          abc
          bingle
          bungle

          def
        """, name='bingle\nbungle\n')

    def test_text_before_block_marker(self):
        regex = re.escape("found before '{marker}'")
        with self.assertRaisesRegex(ClinicError, regex):
            libclinic.linear_format("no text before marker for you! {marker}",
                                    marker="not allowed!")

    def test_text_after_block_marker(self):
        regex = re.escape("found after '{marker}'")
        with self.assertRaisesRegex(ClinicError, regex):
            libclinic.linear_format("{marker} no text after marker for you!",
                                    marker="not allowed!")


class InertParser:
    def __init__(self, clinic):
        pass

    def parse(self, block):
        pass

class CopyParser:
    def __init__(self, clinic):
        pass

    def parse(self, block):
        block.output = block.input


class ClinicBlockParserTest(TestCase):
    def _test(self, input, output):
        language = CLanguage(None)

        blocks = list(BlockParser(input, language))
        writer = BlockPrinter(language)
        for block in blocks:
            writer.print_block(block)
        output = writer.f.getvalue()
        assert output == input, "output != input!\n\noutput " + repr(output) + "\n\n input " + repr(input)

    def round_trip(self, input):
        return self._test(input, input)

    def test_round_trip_1(self):
        self.round_trip("""
            verbatim text here
            lah dee dah
        """)
    def test_round_trip_2(self):
        self.round_trip("""
    verbatim text here
    lah dee dah
/*[inert]
abc
[inert]*/
def
/*[inert checksum: 7b18d017f89f61cf17d47f92749ea6930a3f1deb]*/
xyz
""")

    def _test_clinic(self, input, output):
        language = CLanguage(None)
        c = Clinic(language, filename="file", limited_capi=False)
        c.parsers['inert'] = InertParser(c)
        c.parsers['copy'] = CopyParser(c)
        computed = c.parse(input)
        self.assertEqual(output, computed)

    def test_clinic_1(self):
        self._test_clinic("""
    verbatim text here
    lah dee dah
/*[copy input]
def
[copy start generated code]*/
abc
/*[copy end generated code: output=03cfd743661f0797 input=7b18d017f89f61cf]*/
xyz
""", """
    verbatim text here
    lah dee dah
/*[copy input]
def
[copy start generated code]*/
def
/*[copy end generated code: output=7b18d017f89f61cf input=7b18d017f89f61cf]*/
xyz
""")


class ClinicParserTest(TestCase):

    def parse(self, text):
        c = _make_clinic()
        parser = DSLParser(c)
        block = Block(text)
        parser.parse(block)
        return block

    def parse_function(self, text, signatures_in_block=2, function_index=1):
        block = self.parse(text)
        s = block.signatures
        self.assertEqual(len(s), signatures_in_block)
        assert isinstance(s[0], Module)
        assert isinstance(s[function_index], Function)
        return s[function_index]

    def expect_failure(self, block, err, *,
                       filename=None, lineno=None, strip=True):
        return _expect_failure(self, self.parse_function, block, err,
                               filename=filename, lineno=lineno, strip=strip)

    def checkDocstring(self, fn, expected):
        self.assertTrue(hasattr(fn, "docstring"))
        self.assertEqual(dedent(expected).strip(),
                         fn.docstring.strip())

    def test_trivial(self):
        parser = DSLParser(_make_clinic())
        block = Block("""
            module os
            os.access
        """)
        parser.parse(block)
        module, function = block.signatures
        self.assertEqual("access", function.name)
        self.assertEqual("os", module.name)

    def test_ignore_line(self):
        block = self.parse(dedent("""
            #
            module os
            os.access
        """))
        module, function = block.signatures
        self.assertEqual("access", function.name)
        self.assertEqual("os", module.name)

    def test_param(self):
        function = self.parse_function("""
            module os
            os.access
                path: int
        """)
        self.assertEqual("access", function.name)
        self.assertEqual(2, len(function.parameters))
        p = function.parameters['path']
        self.assertEqual('path', p.name)
        self.assertIsInstance(p.converter, int_converter)

    def test_param_default(self):
        function = self.parse_function("""
            module os
            os.access
                follow_symlinks: bool = True
        """)
        p = function.parameters['follow_symlinks']
        self.assertEqual(True, p.default)

    def test_param_with_continuations(self):
        function = self.parse_function(r"""
            module os
            os.access
                follow_symlinks: \
                bool \
                = \
                True
        """)
        p = function.parameters['follow_symlinks']
        self.assertEqual(True, p.default)

    def test_param_default_none(self):
        function = self.parse_function(r"""
            module test
            test.func
                obj: object = None
                str: str(accept={str, NoneType}) = None
                buf: Py_buffer(accept={str, buffer, NoneType}) = None
            """)
        p = function.parameters['obj']
        self.assertIs(p.default, None)
        self.assertEqual(p.converter.py_default, 'None')
        self.assertEqual(p.converter.c_default, 'Py_None')

        p = function.parameters['str']
        self.assertIs(p.default, None)
        self.assertEqual(p.converter.py_default, 'None')
        self.assertEqual(p.converter.c_default, 'NULL')

        p = function.parameters['buf']
        self.assertIs(p.default, None)
        self.assertEqual(p.converter.py_default, 'None')
        self.assertEqual(p.converter.c_default, '{NULL, NULL}')

    def test_param_default_null(self):
        function = self.parse_function(r"""
            module test
            test.func
                obj: object = NULL
                str: str = NULL
                buf: Py_buffer = NULL
                fsencoded: unicode_fs_encoded = NULL
                fsdecoded: unicode_fs_decoded = NULL
            """)
        p = function.parameters['obj']
        self.assertIs(p.default, NULL)
        self.assertEqual(p.converter.py_default, '<unrepresentable>')
        self.assertEqual(p.converter.c_default, 'NULL')

        p = function.parameters['str']
        self.assertIs(p.default, NULL)
        self.assertEqual(p.converter.py_default, '<unrepresentable>')
        self.assertEqual(p.converter.c_default, 'NULL')

        p = function.parameters['buf']
        self.assertIs(p.default, NULL)
        self.assertEqual(p.converter.py_default, '<unrepresentable>')
        self.assertEqual(p.converter.c_default, '{NULL, NULL}')

        p = function.parameters['fsencoded']
        self.assertIs(p.default, NULL)
        self.assertEqual(p.converter.py_default, '<unrepresentable>')
        self.assertEqual(p.converter.c_default, 'NULL')

        p = function.parameters['fsdecoded']
        self.assertIs(p.default, NULL)
        self.assertEqual(p.converter.py_default, '<unrepresentable>')
        self.assertEqual(p.converter.c_default, 'NULL')

    def test_param_default_str_literal(self):
        function = self.parse_function(r"""
            module test
            test.func
                str: str = ' \t\n\r\v\f\xa0'
                buf: Py_buffer(accept={str, buffer}) = ' \t\n\r\v\f\xa0'
            """)
        p = function.parameters['str']
        self.assertEqual(p.default, ' \t\n\r\v\f\xa0')
        self.assertEqual(p.converter.py_default, r"' \t\n\r\x0b\x0c\xa0'")
        self.assertEqual(p.converter.c_default, r'" \t\n\r\v\f\u00a0"')

        p = function.parameters['buf']
        self.assertEqual(p.default, ' \t\n\r\v\f\xa0')
        self.assertEqual(p.converter.py_default, r"' \t\n\r\x0b\x0c\xa0'")
        self.assertEqual(p.converter.c_default,
                         r'{.buf = " \t\n\r\v\f\302\240", .obj = NULL, .len = 8}')

    def test_param_default_bytes_literal(self):
        function = self.parse_function(r"""
            module test
            test.func
                str: str(accept={robuffer}) = b' \t\n\r\v\f\xa0'
                buf: Py_buffer = b' \t\n\r\v\f\xa0'
            """)
        p = function.parameters['str']
        self.assertEqual(p.default, b' \t\n\r\v\f\xa0')
        self.assertEqual(p.converter.py_default, r"b' \t\n\r\x0b\x0c\xa0'")
        self.assertEqual(p.converter.c_default, r'" \t\n\r\v\f\240"')

        p = function.parameters['buf']
        self.assertEqual(p.default, b' \t\n\r\v\f\xa0')
        self.assertEqual(p.converter.py_default, r"b' \t\n\r\x0b\x0c\xa0'")
        self.assertEqual(p.converter.c_default,
                         r'{.buf = " \t\n\r\v\f\240", .obj = NULL, .len = 7}')

    def test_param_default_byte_literal(self):
        function = self.parse_function(r"""
            module test
            test.func
                zero: char = b'\0'
                one: char = b'\1'
                lf: char = b'\n'
                nbsp: char = b'\xa0'
            """)
        p = function.parameters['zero']
        self.assertEqual(p.default, b'\0')
        self.assertEqual(p.converter.py_default, r"b'\x00'")
        self.assertEqual(p.converter.c_default, r"'\0'")

        p = function.parameters['one']
        self.assertEqual(p.default, b'\1')
        self.assertEqual(p.converter.py_default, r"b'\x01'")
        self.assertEqual(p.converter.c_default, r"'\001'")

        p = function.parameters['lf']
        self.assertEqual(p.default, b'\n')
        self.assertEqual(p.converter.py_default, r"b'\n'")
        self.assertEqual(p.converter.c_default, r"'\n'")

        p = function.parameters['nbsp']
        self.assertEqual(p.default, b'\xa0')
        self.assertEqual(p.converter.py_default, r"b'\xa0'")
        self.assertEqual(p.converter.c_default, r"'\240'")

    def test_param_default_unicode_char(self):
        function = self.parse_function(r"""
            module test
            test.func
                zero: int(accept={str}) = '\0'
                one: int(accept={str}) = '\1'
                lf: int(accept={str}) = '\n'
                nbsp: int(accept={str}) = '\xa0'
                snake: int(accept={str}) = '\U0001f40d'
            """)
        p = function.parameters['zero']
        self.assertEqual(p.default, '\0')
        self.assertEqual(p.converter.py_default, r"'\x00'")
        self.assertEqual(p.converter.c_default, '0')

        p = function.parameters['one']
        self.assertEqual(p.default, '\1')
        self.assertEqual(p.converter.py_default, r"'\x01'")
        self.assertEqual(p.converter.c_default, '0x01')

        p = function.parameters['lf']
        self.assertEqual(p.default, '\n')
        self.assertEqual(p.converter.py_default, r"'\n'")
        self.assertEqual(p.converter.c_default, r"'\n'")

        p = function.parameters['nbsp']
        self.assertEqual(p.default, '\xa0')
        self.assertEqual(p.converter.py_default, r"'\xa0'")
        self.assertEqual(p.converter.c_default, '0xa0')

        p = function.parameters['snake']
        self.assertEqual(p.default, '\U0001f40d')
        self.assertEqual(p.converter.py_default, "'\U0001f40d'")
        self.assertEqual(p.converter.c_default, '0x1f40d')

    def test_param_default_bool(self):
        function = self.parse_function(r"""
            module test
            test.func
                bool: bool = True
                intbool: bool(accept={int}) = True
                intbool2: bool(accept={int}) = 2
            """)
        p = function.parameters['bool']
        self.assertIs(p.default, True)
        self.assertEqual(p.converter.py_default, 'True')
        self.assertEqual(p.converter.c_default, '1')

        p = function.parameters['intbool']
        self.assertIs(p.default, True)
        self.assertEqual(p.converter.py_default, 'True')
        self.assertEqual(p.converter.c_default, '1')

        p = function.parameters['intbool2']
        self.assertEqual(p.default, 2)
        self.assertEqual(p.converter.py_default, '2')
        self.assertEqual(p.converter.c_default, '2')

    def test_param_default_expr_named_constant(self):
        function = self.parse_function("""
            module os
            os.access
                follow_symlinks: int(c_default='MAXSIZE') = sys.maxsize
            """)
        p = function.parameters['follow_symlinks']
        self.assertEqual(sys.maxsize, p.default)
        self.assertEqual("MAXSIZE", p.converter.c_default)

        err = (
            "When you specify a named constant ('sys.maxsize') as your default value, "
            "you MUST specify a valid c_default."
        )
        block = """
            module os
            os.access
                follow_symlinks: int = sys.maxsize
        """
        self.expect_failure(block, err, lineno=2)

    def test_param_with_bizarre_default_fails_correctly(self):
        template = """
            module os
            os.access
                follow_symlinks: int = {default}
        """
        err = "Unsupported expression as default value"
        for bad_default_value in (
            "{1, 2, 3}",
            "3 if bool() else 4",
            "[x for x in range(42)]"
        ):
            with self.subTest(bad_default=bad_default_value):
                block = template.format(default=bad_default_value)
                self.expect_failure(block, err, lineno=2)

    def test_unspecified_not_allowed_as_default_value(self):
        block = """
            module os
            os.access
                follow_symlinks: int(c_default='MAXSIZE') = unspecified
        """
        err = "'unspecified' is not a legal default value!"
        exc = self.expect_failure(block, err, lineno=2)
        self.assertNotIn('Malformed expression given as default value', str(exc))

    def test_malformed_expression_as_default_value(self):
        block = """
            module os
            os.access
                follow_symlinks: int(c_default='MAXSIZE') = 1/0
        """
        err = "Malformed expression given as default value"
        self.expect_failure(block, err, lineno=2)

    def test_param_default_expr_binop(self):
        err = (
            "When you specify an expression ('a + b') as your default value, "
            "you MUST specify a valid c_default."
        )
        block = """
            fn
                follow_symlinks: int = a + b
        """
        self.expect_failure(block, err, lineno=1)

    def test_param_no_docstring(self):
        function = self.parse_function("""
            module os
            os.access
                follow_symlinks: bool = True
                something_else: str = ''
        """)
        self.assertEqual(3, len(function.parameters))
        conv = function.parameters['something_else'].converter
        self.assertIsInstance(conv, str_converter)

    def test_param_default_parameters_out_of_order(self):
        err = (
            "Can't have a parameter without a default ('something_else') "
            "after a parameter with a default!"
        )
        block = """
            module os
            os.access
                follow_symlinks: bool = True
                something_else: str
        """
        self.expect_failure(block, err, lineno=3)

    def disabled_test_converter_arguments(self):
        function = self.parse_function("""
            module os
            os.access
                path: path_t(allow_fd=1)
        """)
        p = function.parameters['path']
        self.assertEqual(1, p.converter.args['allow_fd'])

    def test_function_docstring(self):
        function = self.parse_function("""
            module os
            os.stat as os_stat_fn

               path: str
                   Path to be examined
                   Ensure that multiple lines are indented correctly.

            Perform a stat system call on the given path.

            Ensure that multiple lines are indented correctly.
            Ensure that multiple lines are indented correctly.
        """)
        self.checkDocstring(function, """
            stat($module, /, path)
            --

            Perform a stat system call on the given path.

              path
                Path to be examined
                Ensure that multiple lines are indented correctly.

            Ensure that multiple lines are indented correctly.
            Ensure that multiple lines are indented correctly.
        """)

    def test_docstring_trailing_whitespace(self):
        function = self.parse_function(
            "module t\n"
            "t.s\n"
            "   a: object\n"
            "      Param docstring with trailing whitespace  \n"
            "Func docstring summary with trailing whitespace  \n"
            "  \n"
            "Func docstring body with trailing whitespace  \n"
        )
        self.checkDocstring(function, """
            s($module, /, a)
            --

            Func docstring summary with trailing whitespace

              a
                Param docstring with trailing whitespace

            Func docstring body with trailing whitespace
        """)

    def test_explicit_parameters_in_docstring(self):
        function = self.parse_function(dedent("""
            module foo
            foo.bar
              x: int
                 Documentation for x.
              y: int

            This is the documentation for foo.

            Okay, we're done here.
        """))
        self.checkDocstring(function, """
            bar($module, /, x, y)
            --

            This is the documentation for foo.

              x
                Documentation for x.

            Okay, we're done here.
        """)

    def test_docstring_with_comments(self):
        function = self.parse_function(dedent("""
            module foo
            foo.bar
              x: int
                 # We're about to have
                 # the documentation for x.
                 Documentation for x.
                 # We've just had
                 # the documentation for x.
              y: int

            # We're about to have
            # the documentation for foo.
            This is the documentation for foo.
            # We've just had
            # the documentation for foo.

            Okay, we're done here.
        """))
        self.checkDocstring(function, """
            bar($module, /, x, y)
            --

            This is the documentation for foo.

              x
                Documentation for x.

            Okay, we're done here.
        """)

    def test_parser_regression_special_character_in_parameter_column_of_docstring_first_line(self):
        function = self.parse_function(dedent("""
            module os
            os.stat
                path: str
            This/used to break Clinic!
        """))
        self.checkDocstring(function, """
            stat($module, /, path)
            --

            This/used to break Clinic!
        """)

    def test_c_name(self):
        function = self.parse_function("""
            module os
            os.stat as os_stat_fn
        """)
        self.assertEqual("os_stat_fn", function.c_basename)

    def test_base_invalid_syntax(self):
        block = """
            module os
            os.stat
                invalid syntax: int = 42
        """
        err = "Function 'stat' has an invalid parameter declaration: 'invalid syntax: int = 42'"
        self.expect_failure(block, err, lineno=2)

    def test_param_default_invalid_syntax(self):
        block = """
            module os
            os.stat
                x: int = invalid syntax
        """
        err = "Function 'stat' has an invalid parameter declaration:"
        self.expect_failure(block, err, lineno=2)

    def test_cloning_nonexistent_function_correctly_fails(self):
        block = """
            cloned = fooooooooooooooooo
            This is trying to clone a nonexistent function!!
        """
        err = "Couldn't find existing function 'fooooooooooooooooo'!"
        with support.captured_stderr() as stderr:
            self.expect_failure(block, err, lineno=0)
        expected_debug_print = dedent("""\
            cls=None, module=<clinic.Clinic object>, existing='fooooooooooooooooo'
            (cls or module).functions=[]
        """)
        stderr = stderr.getvalue()
        self.assertIn(expected_debug_print, stderr)

    def test_return_converter(self):
        function = self.parse_function("""
            module os
            os.stat -> int
        """)
        self.assertIsInstance(function.return_converter, int_return_converter)

    def test_return_converter_invalid_syntax(self):
        block = """
            module os
            os.stat -> invalid syntax
        """
        err = "Badly formed annotation for 'os.stat': 'invalid syntax'"
        self.expect_failure(block, err)

    def test_legacy_converter_disallowed_in_return_annotation(self):
        block = """
            module os
            os.stat -> "s"
        """
        err = "Legacy converter 's' not allowed as a return converter"
        self.expect_failure(block, err)

    def test_unknown_return_converter(self):
        block = """
            module os
            os.stat -> fooooooooooooooooooooooo
        """
        err = "No available return converter called 'fooooooooooooooooooooooo'"
        self.expect_failure(block, err)

    def test_star(self):
        function = self.parse_function("""
            module os
            os.access
                *
                follow_symlinks: bool = True
        """)
        p = function.parameters['follow_symlinks']
        self.assertEqual(inspect.Parameter.KEYWORD_ONLY, p.kind)
        self.assertEqual(0, p.group)

    def test_group(self):
        function = self.parse_function("""
            module window
            window.border
                [
                ls: int
                ]
                /
        """)
        p = function.parameters['ls']
        self.assertEqual(1, p.group)

    def test_left_group(self):
        function = self.parse_function("""
            module curses
            curses.addch
                [
                y: int
                    Y-coordinate.
                x: int
                    X-coordinate.
                ]
                ch: char
                    Character to add.
                [
                attr: long
                    Attributes for the character.
                ]
                /
        """)
        dataset = (
            ('y', -1), ('x', -1),
            ('ch', 0),
            ('attr', 1),
        )
        for name, group in dataset:
            with self.subTest(name=name, group=group):
                p = function.parameters[name]
                self.assertEqual(p.group, group)
                self.assertEqual(p.kind, inspect.Parameter.POSITIONAL_ONLY)
        self.checkDocstring(function, """
            addch([y, x,] ch, [attr])


              y
                Y-coordinate.
              x
                X-coordinate.
              ch
                Character to add.
              attr
                Attributes for the character.
        """)

    def test_nested_groups(self):
        function = self.parse_function("""
            module curses
            curses.imaginary
               [
               [
               y1: int
                 Y-coordinate.
               y2: int
                 Y-coordinate.
               ]
               x1: int
                 X-coordinate.
               x2: int
                 X-coordinate.
               ]
               ch: char
                 Character to add.
               [
               attr1: long
                 Attributes for the character.
               attr2: long
                 Attributes for the character.
               attr3: long
                 Attributes for the character.
               [
               attr4: long
                 Attributes for the character.
               attr5: long
                 Attributes for the character.
               attr6: long
                 Attributes for the character.
               ]
               ]
               /
        """)
        dataset = (
            ('y1', -2), ('y2', -2),
            ('x1', -1), ('x2', -1),
            ('ch', 0),
            ('attr1', 1), ('attr2', 1), ('attr3', 1),
            ('attr4', 2), ('attr5', 2), ('attr6', 2),
        )
        for name, group in dataset:
            with self.subTest(name=name, group=group):
                p = function.parameters[name]
                self.assertEqual(p.group, group)
                self.assertEqual(p.kind, inspect.Parameter.POSITIONAL_ONLY)

        self.checkDocstring(function, """
            imaginary([[y1, y2,] x1, x2,] ch, [attr1, attr2, attr3, [attr4, attr5,
                      attr6]])


              y1
                Y-coordinate.
              y2
                Y-coordinate.
              x1
                X-coordinate.
              x2
                X-coordinate.
              ch
                Character to add.
              attr1
                Attributes for the character.
              attr2
                Attributes for the character.
              attr3
                Attributes for the character.
              attr4
                Attributes for the character.
              attr5
                Attributes for the character.
              attr6
                Attributes for the character.
        """)

    def test_two_top_groups_on_left(self):
        function = self.parse_function("""
            module curses
            curses.chgat
                [
                y: int
                    Y-coordinate.
                x: int
                    X-coordinate.
                ]
                [
                num: int
                    Number of characters.
                ]
                attr: long
                    Attributes for the characters.
                /
        """)
        dataset = (
            ('y', -1), ('x', -1),
            ('num', -2),
            ('attr', 0),
        )
        for name, group in dataset:
            with self.subTest(name=name, group=group):
                p = function.parameters[name]
                self.assertEqual(p.group, group)
                self.assertEqual(p.kind, inspect.Parameter.POSITIONAL_ONLY)
        self.checkDocstring(function, """
            chgat([y, x,] [num,] attr)


              y
                Y-coordinate.
              x
                X-coordinate.
              num
                Number of characters.
              attr
                Attributes for the characters.
        """)

    def test_two_top_groups_on_right(self):
        function = self.parse_function("""
            module foo
            foo.two_top_groups_on_right
                param: int
                [
                group1: int
                ]
                [
                group2: int
                ]
                /
        """)
        dataset = (
            ('param', 0),
            ('group1', 1),
            ('group2', 2),
        )
        for name, group in dataset:
            with self.subTest(name=name, group=group):
                p = function.parameters[name]
                self.assertEqual(p.group, group)
                self.assertEqual(p.kind, inspect.Parameter.POSITIONAL_ONLY)
        self.checkDocstring(function, """
            two_top_groups_on_right(param, [group1,] [group2])
        """)

    def test_disallowed_grouping__parameter_after_group_on_right(self):
        block = """
            module foo
            foo.parameter_after_group_on_right
                param: int
                [
                [
                group1 : int
                ]
                group2 : int
                ]
        """
        err = (
            "Function parameter_after_group_on_right has an unsupported group "
            "configuration. (Unexpected state 6.a)"
        )
        self.expect_failure(block, err)

    def test_disallowed_grouping__group_after_parameter_on_left(self):
        block = """
            module foo
            foo.group_after_parameter_on_left
                [
                group2 : int
                [
                group1 : int
                ]
                ]
                param: int
        """
        err = (
            "Function 'group_after_parameter_on_left' has an unsupported group "
            "configuration. (Unexpected state 2.b)"
        )
        self.expect_failure(block, err)

    def test_disallowed_grouping__empty_group_on_left(self):
        block = """
            module foo
            foo.empty_group
                [
                [
                ]
                group2 : int
                ]
                param: int
        """
        err = (
            "Function 'empty_group' has an empty group. "
            "All groups must contain at least one parameter."
        )
        self.expect_failure(block, err)

    def test_disallowed_grouping__empty_group_on_right(self):
        block = """
            module foo
            foo.empty_group
                param: int
                [
                [
                ]
                group2 : int
                ]
        """
        err = (
            "Function 'empty_group' has an empty group. "
            "All groups must contain at least one parameter."
        )
        self.expect_failure(block, err)

    def test_disallowed_grouping__no_matching_bracket(self):
        block = """
            module foo
            foo.empty_group
                param: int
                ]
                group2: int
                ]
        """
        err = "Function 'empty_group' has a ']' without a matching '['"
        self.expect_failure(block, err)

    def test_disallowed_grouping__must_be_position_only(self):
        dataset = ("""
            with_kwds
                [
                *
                a: object
                ]
        """, """
            with_kwds
                [
                a: object
                ]
        """, """
            with_kwds
                [
                **kwds: dict
                ]
        """)
        err = (
            "You cannot use optional groups ('[' and ']') unless all "
            "parameters are positional-only ('/')"
        )
        for block in dataset:
            with self.subTest(block=block):
                self.expect_failure(block, err)

    def test_no_parameters(self):
        function = self.parse_function("""
            module foo
            foo.bar

            Docstring

        """)
        self.assertEqual("bar($module, /)\n--\n\nDocstring", function.docstring)
        self.assertEqual(1, len(function.parameters)) # self!

    def test_init_with_no_parameters(self):
        function = self.parse_function("""
            module foo
            class foo.Bar "unused" "notneeded"
            foo.Bar.__init__

            Docstring

        """, signatures_in_block=3, function_index=2)

        # self is not in the signature
        self.assertEqual("Bar()\n--\n\nDocstring", function.docstring)
        # but it *is* a parameter
        self.assertEqual(1, len(function.parameters))

    def test_illegal_module_line(self):
        block = """
            module foo
            foo.bar => int
                /
        """
        err = "Illegal function name: 'foo.bar => int'"
        self.expect_failure(block, err)

    def test_illegal_c_basename(self):
        block = """
            module foo
            foo.bar as 935
                /
        """
        err = "Illegal C basename: '935'"
        self.expect_failure(block, err)

    def test_no_c_basename(self):
        block = "foo as "
        err = "No C basename provided after 'as' keyword"
        self.expect_failure(block, err, strip=False)

    def test_single_star(self):
        block = """
            module foo
            foo.bar
                *
                *
        """
        err = "Function 'bar' uses '*' more than once."
        self.expect_failure(block, err)

    def test_parameters_required_after_star(self):
        dataset = (
            "module foo\nfoo.bar\n  *",
            "module foo\nfoo.bar\n  *\nDocstring here.",
            "module foo\nfoo.bar\n  this: int\n  *",
            "module foo\nfoo.bar\n  this: int\n  *\nDocstring.",
        )
        err = "Function 'bar' specifies '*' without following parameters."
        for block in dataset:
            with self.subTest(block=block):
                self.expect_failure(block, err)

    def test_fulldisplayname_class(self):
        dataset = (
            ("T", """
                class T "void *" ""
                T.__init__
            """),
            ("m.T", """
                module m
                class m.T "void *" ""
                @classmethod
                m.T.__new__
            """),
            ("m.T.C", """
                module m
                class m.T "void *" ""
                class m.T.C "void *" ""
                m.T.C.__init__
            """),
        )
        for name, code in dataset:
            with self.subTest(name=name, code=code):
                block = self.parse(code)
                func = block.signatures[-1]
                self.assertEqual(func.fulldisplayname, name)

    def test_fulldisplayname_meth(self):
        dataset = (
            ("func", "func"),
            ("m.func", """
                module m
                m.func
            """),
            ("T.meth", """
                class T "void *" ""
                T.meth
            """),
            ("m.T.meth", """
                module m
                class m.T "void *" ""
                m.T.meth
            """),
            ("m.T.C.meth", """
                module m
                class m.T "void *" ""
                class m.T.C "void *" ""
                m.T.C.meth
            """),
        )
        for name, code in dataset:
            with self.subTest(name=name, code=code):
                block = self.parse(code)
                func = block.signatures[-1]
                self.assertEqual(func.fulldisplayname, name)

    def test_depr_star_invalid_format_1(self):
        block = """
            module foo
            foo.bar
                this: int
                * [from 3]
            Docstring.
        """
        err = (
            "Function 'bar': expected format '[from major.minor]' "
            "where 'major' and 'minor' are integers; got '3'"
        )
        self.expect_failure(block, err, lineno=3)

    def test_depr_star_invalid_format_2(self):
        block = """
            module foo
            foo.bar
                this: int
                * [from a.b]
            Docstring.
        """
        err = (
            "Function 'bar': expected format '[from major.minor]' "
            "where 'major' and 'minor' are integers; got 'a.b'"
        )
        self.expect_failure(block, err, lineno=3)

    def test_depr_star_invalid_format_3(self):
        block = """
            module foo
            foo.bar
                this: int
                * [from 1.2.3]
            Docstring.
        """
        err = (
            "Function 'bar': expected format '[from major.minor]' "
            "where 'major' and 'minor' are integers; got '1.2.3'"
        )
        self.expect_failure(block, err, lineno=3)

    def test_parameters_required_after_depr_star(self):
        block = """
            module foo
            foo.bar
                this: int
                * [from 3.14]
            Docstring.
        """
        err = (
            "Function 'bar' specifies '* [from ...]' without "
            "following parameters."
        )
        self.expect_failure(block, err, lineno=4)

    def test_parameters_required_after_depr_star2(self):
        block = """
            module foo
            foo.bar
                a: int
                * [from 3.14]
                *
                b: int
            Docstring.
        """
        err = (
            "Function 'bar' specifies '* [from ...]' without "
            "following parameters."
        )
        self.expect_failure(block, err, lineno=4)

    def test_parameters_required_after_depr_star3(self):
        block = """
            module foo
            foo.bar
                a: int
                * [from 3.14]
                *args: tuple
                b: int
            Docstring.
        """
        err = (
            "Function 'bar' specifies '* [from ...]' without "
            "following parameters."
        )
        self.expect_failure(block, err, lineno=4)

    def test_depr_star_must_come_before_star(self):
        block = """
            module foo
            foo.bar
                a: int
                *
                * [from 3.14]
                b: int
            Docstring.
        """
        err = "Function 'bar': '* [from ...]' must precede '*'"
        self.expect_failure(block, err, lineno=4)

    def test_depr_star_must_come_before_vararg(self):
        block = """
            module foo
            foo.bar
                a: int
                *args: tuple
                * [from 3.14]
                b: int
            Docstring.
        """
        err = "Function 'bar': '* [from ...]' must precede '*'"
        self.expect_failure(block, err, lineno=4)

    def test_depr_star_duplicate(self):
        block = """
            module foo
            foo.bar
                a: int
                * [from 3.14]
                b: int
                * [from 3.14]
                c: int
            Docstring.
        """
        err = "Function 'bar' uses '* [from 3.14]' more than once."
        self.expect_failure(block, err, lineno=5)

    def test_depr_star_duplicate2(self):
        block = """
            module foo
            foo.bar
                a: int
                * [from 3.14]
                b: int
                * [from 3.15]
                c: int
            Docstring.
        """
        err = "Function 'bar': '* [from 3.15]' must precede '* [from 3.14]'"
        self.expect_failure(block, err, lineno=5)

    def test_depr_slash_duplicate(self):
        block = """
            module foo
            foo.bar
                a: int
                / [from 3.14]
                b: int
                / [from 3.14]
                c: int
            Docstring.
        """
        err = "Function 'bar' uses '/ [from 3.14]' more than once."
        self.expect_failure(block, err, lineno=5)

    def test_depr_slash_duplicate2(self):
        block = """
            module foo
            foo.bar
                a: int
                / [from 3.15]
                b: int
                / [from 3.14]
                c: int
            Docstring.
        """
        err = "Function 'bar': '/ [from 3.14]' must precede '/ [from 3.15]'"
        self.expect_failure(block, err, lineno=5)

    def test_alias(self):
        function = self.parse_function("""
            module foo
            foo.bar
                a: int
                *
                b as a: int = 0
            Docstring.
        """)
        _, a, b = function.parameters.values()
        self.assertIsNone(a.converter.alias_of)
        self.assertIs(b.converter.alias_of, a)
        self.assertEqual(function.docstring.splitlines()[0],
                         "bar($module, /, a)")

    def test_alias_must_be_keyword_only(self):
        block = """
            module foo
            foo.bar
                a: int
                b as a: int = 0
            Docstring.
        """
        err = "Alias 'b' of the parameter 'a' must be keyword-only."
        self.expect_failure(block, err, lineno=3)

    def test_alias_must_have_default(self):
        block = """
            module foo
            foo.bar
                a: int
                *
                b as a: int
            Docstring.
        """
        err = "Alias 'b' of the parameter 'a' must have a default value."
        self.expect_failure(block, err, lineno=4)

    def test_alias_deprecated(self):
        function = self.parse_function("""
            module foo
            foo.bar
                a: int
                *
                [until 3.14] b as a: int = 0
            Docstring.
        """)
        _, a, b = function.parameters.values()
        self.assertIsNone(a.deprecated_until)
        self.assertEqual(b.deprecated_until, (3, 14))

    def test_deprecated_last_positional_only_parameters(self):
        function = self.parse_function("""
            module foo
            foo.bar
                a: int = 0
                [until 3.14] b: int = 0
                [until 3.14] c: int = 0
                /
                d: int = 0
            Docstring.
        """)
        _, a, b, c, d = function.parameters.values()
        self.assertIsNone(a.deprecated_until)
        self.assertEqual(b.deprecated_until, (3, 14))
        self.assertEqual(c.deprecated_until, (3, 14))
        self.assertIsNone(d.deprecated_until)

    def test_deprecated_non_last_positional_only_parameter(self):
        block = """
            module foo
            foo.bar
                [until 3.14] a: int = 0
                b: int = 0
                /
            Docstring.
        """
        err = ("Parameter 'b' cannot follow the deprecated parameter 'a': "
               "only the last positional-only parameters can be deprecated.")
        self.expect_failure(block, err, lineno=4)

    def test_deprecated_non_positional_only_parameters(self):
        # The following parameters can still be passed by keyword.
        function = self.parse_function("""
            module foo
            foo.bar
                [until 3.14] a: int = 0
                b: int = 0
                *
                [until 3.14] c: int = 0
                d: int = 0
            Docstring.
        """)
        _, a, b, c, d = function.parameters.values()
        self.assertEqual(a.deprecated_until, (3, 14))
        self.assertIsNone(b.deprecated_until)
        self.assertEqual(c.deprecated_until, (3, 14))
        self.assertIsNone(d.deprecated_until)

    def test_deprecated_parameter_without_default(self):
        block = """
            module foo
            foo.bar
                [until 3.14] a: int
            Docstring.
        """
        err = "Deprecated parameter 'a' must have a default value."
        self.expect_failure(block, err, lineno=2)

    def test_deprecated_invalid_format(self):
        block = """
            module foo
            foo.bar
                [until 3] a: int = 0
            Docstring.
        """
        err = (
            "Function 'bar': expected format '[until major.minor]' "
            "where 'major' and 'minor' are integers; got '3'"
        )
        self.expect_failure(block, err, lineno=2)

    def test_single_slash(self):
        block = """
            module foo
            foo.bar
                /
                /
        """
        err = (
            "Function 'bar' has an unsupported group configuration. "
            "(Unexpected state 0.d)"
        )
        self.expect_failure(block, err)

    def test_parameters_required_before_depr_slash(self):
        block = """
            module foo
            foo.bar
                / [from 3.14]
            Docstring.
        """
        err = (
            "Function 'bar' specifies '/ [from ...]' without "
            "preceding parameters."
        )
        self.expect_failure(block, err, lineno=2)

    def test_parameters_required_before_depr_slash2(self):
        block = """
            module foo
            foo.bar
                a: int
                /
                / [from 3.14]
            Docstring.
        """
        err = (
            "Function 'bar' specifies '/ [from ...]' without "
            "preceding parameters."
        )
        self.expect_failure(block, err, lineno=4)

    def test_double_slash(self):
        block = """
            module foo
            foo.bar
                a: int
                /
                b: int
                /
        """
        err = "Function 'bar' uses '/' more than once."
        self.expect_failure(block, err)

    def test_slash_after_star(self):
        block = """
            module foo
            foo.bar
               x: int
               y: int
               *
               z: int
               /
        """
        err = "Function 'bar': '/' must precede '*'"
        self.expect_failure(block, err)

    def test_slash_after_vararg(self):
        block = """
            module foo
            foo.bar
               x: int
               y: int
               *args: tuple
               z: int
               /
        """
        err = "Function 'bar': '/' must precede '*'"
        self.expect_failure(block, err)

    def test_slash_after_var_keyword(self):
        block = """
            module foo
            foo.bar
               x: int
               y: int
               **kwds: dict
               z: int
               /
        """
        err = "Function 'bar' has an invalid parameter declaration (**kwargs?): '**kwds: dict'"
        self.expect_failure(block, err)

    def test_star_after_var_keyword(self):
        block = """
            module foo
            foo.bar
               x: int
               y: int
               **kwds: dict
               z: int
               *
        """
        err = "Function 'bar' has an invalid parameter declaration (**kwargs?): '**kwds: dict'"
        self.expect_failure(block, err)

    def test_parameter_after_var_keyword(self):
        block = """
            module foo
            foo.bar
               x: int
               y: int
               **kwds: dict
               z: int
        """
        err = "Function 'bar' has an invalid parameter declaration (**kwargs?): '**kwds: dict'"
        self.expect_failure(block, err)

    def test_depr_star_must_come_after_slash(self):
        block = """
            module foo
            foo.bar
                a: int
                * [from 3.14]
                /
                b: int
            Docstring.
        """
        err = "Function 'bar': '/' must precede '* [from ...]'"
        self.expect_failure(block, err, lineno=4)

    def test_depr_star_must_come_after_depr_slash(self):
        block = """
            module foo
            foo.bar
                a: int
                * [from 3.14]
                / [from 3.14]
                b: int
            Docstring.
        """
        err = "Function 'bar': '/ [from ...]' must precede '* [from ...]'"
        self.expect_failure(block, err, lineno=4)

    def test_star_must_come_after_depr_slash(self):
        block = """
            module foo
            foo.bar
                a: int
                *
                / [from 3.14]
                b: int
            Docstring.
        """
        err = "Function 'bar': '/ [from ...]' must precede '*'"
        self.expect_failure(block, err, lineno=4)

    def test_vararg_must_come_after_depr_slash(self):
        block = """
            module foo
            foo.bar
                a: int
                *args: tuple
                / [from 3.14]
                b: int
            Docstring.
        """
        err = "Function 'bar': '/ [from ...]' must precede '*'"
        self.expect_failure(block, err, lineno=4)

    def test_depr_slash_must_come_after_slash(self):
        block = """
            module foo
            foo.bar
                a: int
                / [from 3.14]
                /
                b: int
            Docstring.
        """
        err = "Function 'bar': '/' must precede '/ [from ...]'"
        self.expect_failure(block, err, lineno=4)

    def test_parameters_not_permitted_after_slash_for_now(self):
        block = """
            module foo
            foo.bar
                /
                x: int
        """
        err = (
            "Function 'bar' has an unsupported group configuration. "
            "(Unexpected state 0.d)"
        )
        self.expect_failure(block, err)

    def test_parameters_no_more_than_one_vararg(self):
        err = "Function 'bar' uses '*' more than once."
        block = """
            module foo
            foo.bar
               *vararg1: tuple
               *vararg2: tuple
        """
        self.expect_failure(block, err, lineno=3)

    def test_parameters_no_more_than_one_var_keyword(self):
        err = "Encountered parameter line when not expecting parameters: **var_keyword_2: dict"
        block = """
            module foo
            foo.bar
               **var_keyword_1: dict
               **var_keyword_2: dict
        """
        self.expect_failure(block, err, lineno=3)

    def test_function_not_at_column_0(self):
        function = self.parse_function("""
              module foo
              foo.bar
                x: int
                  Nested docstring here, goeth.
                *
                y: str
              Not at column 0!
        """)
        self.checkDocstring(function, """
            bar($module, /, x, *, y)
            --

            Not at column 0!

              x
                Nested docstring here, goeth.
        """)

    def test_docstring_only_summary(self):
        function = self.parse_function("""
              module m
              m.f
              summary
        """)
        self.checkDocstring(function, """
            f($module, /)
            --

            summary
        """)

    def test_docstring_empty_lines(self):
        function = self.parse_function("""
              module m
              m.f


        """)
        self.checkDocstring(function, """
            f($module, /)
            --
        """)

    def test_docstring_explicit_params_placement(self):
        function = self.parse_function("""
              module m
              m.f
                a: int
                    Param docstring for 'a' will be included
                b: int
                c: int
                    Param docstring for 'c' will be included
              This is the summary line.

              We'll now place the params section here:
              {parameters}
              And now for something completely different!
              (Note the added newline)
        """)
        self.checkDocstring(function, """
            f($module, /, a, b, c)
            --

            This is the summary line.

            We'll now place the params section here:
              a
                Param docstring for 'a' will be included
              c
                Param docstring for 'c' will be included

            And now for something completely different!
            (Note the added newline)
        """)

    def test_indent_stack_no_tabs(self):
        block = """
            module foo
            foo.bar
               *vararg1: tuple
            \t*vararg2: tuple
        """
        err = ("Tab characters are illegal in the Clinic DSL: "
               r"'\t*vararg2: tuple'")
        self.expect_failure(block, err)

    def test_indent_stack_illegal_outdent(self):
        block = """
            module foo
            foo.bar
              a: object
             b: object
        """
        err = "Illegal outdent"
        self.expect_failure(block, err)

    def test_directive(self):
        parser = DSLParser(_make_clinic())
        parser.flag = False
        parser.directives['setflag'] = lambda : setattr(parser, 'flag', True)
        block = Block("setflag")
        parser.parse(block)
        self.assertTrue(parser.flag)

    def test_legacy_converters(self):
        block = self.parse('module os\nos.access\n   path: "s"')
        module, function = block.signatures
        conv = (function.parameters['path']).converter
        self.assertIsInstance(conv, str_converter)

    def test_legacy_converters_non_string_constant_annotation(self):
        err = "Annotations must be either a name, a function call, or a string"
        dataset = (
            'module os\nos.access\n   path: 42',
            'module os\nos.access\n   path: 42.42',
            'module os\nos.access\n   path: 42j',
            'module os\nos.access\n   path: b"42"',
        )
        for block in dataset:
            with self.subTest(block=block):
                self.expect_failure(block, err, lineno=2)

    def test_other_bizarre_things_in_annotations_fail(self):
        err = "Annotations must be either a name, a function call, or a string"
        dataset = (
            'module os\nos.access\n   path: {"some": "dictionary"}',
            'module os\nos.access\n   path: ["list", "of", "strings"]',
            'module os\nos.access\n   path: (x for x in range(42))',
        )
        for block in dataset:
            with self.subTest(block=block):
                self.expect_failure(block, err, lineno=2)

    def test_kwarg_splats_disallowed_in_function_call_annotations(self):
        err = "Cannot use a kwarg splat in a function-call annotation"
        dataset = (
            'module fo\nfo.barbaz\n   o: bool(**{None: "bang!"})',
            'module fo\nfo.barbaz -> bool(**{None: "bang!"})',
            'module fo\nfo.barbaz -> bool(**{"bang": 42})',
            'module fo\nfo.barbaz\n   o: bool(**{"bang": None})',
        )
        for block in dataset:
            with self.subTest(block=block):
                self.expect_failure(block, err)

    def test_self_param_placement(self):
        err = (
            "A 'self' parameter, if specified, must be the very first thing "
            "in the parameter block."
        )
        block = """
            module foo
            foo.func
                a: int
                self: self(type="PyObject *")
        """
        self.expect_failure(block, err, lineno=3)

    def test_self_param_cannot_be_optional(self):
        err = "A 'self' parameter cannot be marked optional."
        block = """
            module foo
            foo.func
                self: self(type="PyObject *") = None
        """
        self.expect_failure(block, err, lineno=2)

    def test_defining_class_param_placement(self):
        err = (
            "A 'defining_class' parameter, if specified, must either be the "
            "first thing in the parameter block, or come just after 'self'."
        )
        block = """
            module foo
            foo.func
                self: self(type="PyObject *")
                a: int
                cls: defining_class
        """
        self.expect_failure(block, err, lineno=4)

    def test_defining_class_param_cannot_be_optional(self):
        err = "A 'defining_class' parameter cannot be marked optional."
        block = """
            module foo
            foo.func
                cls: defining_class(type="PyObject *") = None
        """
        self.expect_failure(block, err, lineno=2)

    def test_slot_methods_cannot_access_defining_class(self):
        block = """
            module foo
            class Foo "" ""
            Foo.__init__
                cls: defining_class
                a: object
        """
        err = "Slot methods cannot access their defining class."
        with self.assertRaisesRegex(ValueError, err):
            self.parse_function(block)

    def test_new_must_be_a_class_method(self):
        err = "'__new__' must be a class method!"
        block = """
            module foo
            class Foo "" ""
            Foo.__new__
        """
        self.expect_failure(block, err, lineno=2)

    def test_init_must_be_a_normal_method(self):
        err_template = "'__init__' must be a normal method; got 'FunctionKind.{}'!"
        annotations = {
            "@classmethod": "CLASS_METHOD",
            "@staticmethod": "STATIC_METHOD",
            "@getter": "GETTER",
        }
        for annotation, invalid_kind in annotations.items():
            with self.subTest(annotation=annotation, invalid_kind=invalid_kind):
                block = f"""
                    module foo
                    class Foo "" ""
                    {annotation}
                    Foo.__init__
                """
                expected_error = err_template.format(invalid_kind)
                self.expect_failure(block, expected_error, lineno=3)

    def test_init_cannot_define_a_return_type(self):
        block = """
            class Foo "" ""
            Foo.__init__ -> long
        """
        expected_error = "__init__ methods cannot define a return type"
        self.expect_failure(block, expected_error, lineno=1)

    def test_invalid_getset(self):
        block = """
            module foo
            class Foo "" ""
            @setter
            Foo.property -> int
        """
        expected_error = "@setter methods cannot define a return type"
        self.expect_failure(block, expected_error, lineno=3)

        block = """
           module foo
           class Foo "" ""
           @getter
           Foo.property
               obj: int
               /
        """
        expected_error = "@getter methods cannot define parameters"
        self.expect_failure(block, expected_error)

        block = """
           module foo
           class Foo "" ""
           @setter
           Foo.property
               obj: int
               value: int
               /
        """
        expected_error = "@setter methods must define exactly one parameter"
        self.expect_failure(block, expected_error)

    def test_setter_value_default(self):
        block = """
            module m
            class Foo "" ""
            @setter
            Foo.property
                value: object = None
        """
        expected_error = "the value of @setter cannot have a default value"
        self.expect_failure(block, expected_error)

        block = """
            module m
            class Foo "" ""
            @setter
            @deleter
            Foo.property
                value: object
        """
        expected_error = ("the value of @setter with @deleter must have "
                          "a default value, used to delete the attribute")
        self.expect_failure(block, expected_error)

        block = """
            module m
            class Foo "" ""
            @setter
            @deleter
            Foo.property
                value: object = None
        """
        expected_error = ("the value of @setter with @deleter can only have "
                          "NULL as a default value")
        self.expect_failure(block, expected_error)

    def test_setter_value_kind(self):
        expected_error = "the value of @setter must be a positional parameter"
        block = """
            module m
            class Foo "" ""
            @setter
            Foo.property

                *
                value: object
        """
        self.expect_failure(block, expected_error)

        for parameter in "*args: tuple", "**kwargs: dict":
            with self.subTest(parameter=parameter):
                block = f"""
                    module m
                    class Foo "" ""
                    @setter
                    Foo.property

                        {parameter}
                """
                self.expect_failure(block, expected_error)

    def test_setter_implicit_parameter(self):
        function = self.parse_function("""
            module foo
            class Foo "" ""
            @setter
            Foo.property
        """, signatures_in_block=3, function_index=2)
        self.assertEqual(function.kind, FunctionKind.SETTER)
        value = function.parameters['value']
        self.assertIsInstance(value.converter, object_converter)
        self.assertIs(value.default, unspecified)

    def test_setter_and_deleter_implicit_parameter(self):
        function = self.parse_function("""
            module foo
            class Foo "" ""
            @setter
            @deleter
            Foo.property
        """, signatures_in_block=3, function_index=2)
        self.assertEqual(function.kind, FunctionKind.SETTER_AND_DELETER)
        value = function.parameters['value']
        self.assertIsInstance(value.converter, object_converter)
        self.assertIs(value.default, NULL)

    def test_getter_return_converter(self):
        function = self.parse_function("""
            module foo
            class Foo "" ""
            @getter
            Foo.property -> int
        """, signatures_in_block=3, function_index=2)
        self.assertEqual(function.return_converter.type, "int")

    def test_setter_docstring(self):
        block = """
            module foo
            class Foo "" ""
            @setter
            Foo.property

            foo

            bar
            [clinic start generated code]*/
        """
        expected_error = "docstrings are only supported for @getter"
        self.expect_failure(block, expected_error)

    def test_duplicate_getset(self):
        annotations = ["@getter", "@setter"]
        for annotation in annotations:
            with self.subTest(annotation=annotation):
                block = f"""
                    module foo
                    class Foo "" ""
                    {annotation}
                    {annotation}
                    Foo.property -> int
                """
                expected_error = f"Cannot apply {annotation} twice to the same function!"
                self.expect_failure(block, expected_error, lineno=3)

    def test_getter_and_setter_disallowed_on_same_function(self):
        dup_annotations = [("@getter", "@setter"), ("@setter", "@getter")]
        for dup in dup_annotations:
            with self.subTest(dup=dup):
                block = f"""
                    module foo
                    class Foo "" ""
                    {dup[0]}
                    {dup[1]}
                    Foo.property -> int
                """
                expected_error = (f"Can't set {dup[1]}, function is not "
                                  f"a normal callable")
                self.expect_failure(block, expected_error, lineno=3)

    def test_deleter_without_setter(self):
        block = """
            module foo
            class Foo "" ""
            @deleter
            Foo.property
        """
        expected_error = "Can't set @deleter, @setter is not applied"
        self.expect_failure(block, expected_error, lineno=2)

        block = """
            module foo
            class Foo "" ""
            @deleter
            @setter
            Foo.property
        """
        self.expect_failure(block, expected_error, lineno=2)

    def test_deleter_twice(self):
        block = """
            module foo
            class Foo "" ""
            @setter
            @deleter
            @deleter
            Foo.property
        """
        expected_error = "Cannot apply @deleter twice to the same function!"
        self.expect_failure(block, expected_error, lineno=4)

    def test_getset_no_class(self):
        for annotation in "@getter", "@setter":
            with self.subTest(annotation=annotation):
                block = f"""
                    module m
                    {annotation}
                    m.func
                """
                expected_error = "@getter and @setter must be methods"
                self.expect_failure(block, expected_error, lineno=2)

    def test_duplicate_coexist(self):
        err = "Called @coexist twice"
        block = """
            module m
            @coexist
            @coexist
            m.fn
        """
        self.expect_failure(block, err, lineno=2)

    def test_duplicate_vectorcall(self):
        err = "Called @vectorcall twice"
        block = """
            module m
            class Foo "FooObject *" ""
            @vectorcall
            @vectorcall
            Foo.__init__
        """
        self.expect_failure(block, err, lineno=3)

    def test_vectorcall_on_regular_method(self):
        err = "@vectorcall can only be used with __init__ and __new__ methods"
        block = """
            module m
            class Foo "FooObject *" ""
            @vectorcall
            Foo.some_method
        """
        self.expect_failure(block, err, lineno=3)

    def test_vectorcall_on_module_function(self):
        err = "@vectorcall can only be used with __init__ and __new__ methods"
        block = """
            module m
            @vectorcall
            m.fn
        """
        self.expect_failure(block, err, lineno=2)

    def test_vectorcall_on_init(self):
        block = """
            module m
            class Foo "FooObject *" "Foo_Type"
            @vectorcall
            Foo.__init__
                iterable: object = NULL
                /
        """
        func = self.parse_function(block, signatures_in_block=3,
                                   function_index=2)
        self.assertTrue(func.vectorcall)

    def test_vectorcall_on_new(self):
        block = """
            module m
            class Foo "FooObject *" "Foo_Type"
            @classmethod
            @vectorcall
            Foo.__new__
                x: object = NULL
                /
        """
        func = self.parse_function(block, signatures_in_block=3,
                                   function_index=2)
        self.assertTrue(func.vectorcall)

    def test_vectorcall_takes_no_arguments(self):
        err = "at_vectorcall() takes 1 positional argument but 2 were given"
        block = """
            module m
            class Foo "FooObject *" "Foo_Type"
            @vectorcall bogus=True
            Foo.__init__
        """
        self.expect_failure(block, err, lineno=2)

    def test_vectorcall_without_type_object(self):
        err = "@vectorcall requires the type object of 'Foo'"
        block = """
            module m
            class Foo "FooObject *" ""
            @vectorcall
            Foo.__init__
        """
        self.expect_failure(block, err, lineno=3)

    def test_vectorcall_unsupported_converter(self):
        # str(encoding=...) has no parse_arg() implementation.
        err = ("@vectorcall requires all converters to support "
               "parse_arg(); parameter 's' does not")
        block = """
            module m
            class Foo "FooObject *" "Foo_Type"
            @classmethod
            @vectorcall
            Foo.__new__
                s: str(encoding="utf-8")
                /
        """
        self.expect_failure(block, err, lineno=6)

    def test_vectorcall_with_option_groups(self):
        err = "@vectorcall does not support optional groups"
        block = """
            module m
            class Foo "FooObject *" "Foo_Type"
            @vectorcall
            Foo.__init__
                [
                a: object
                ]
                /
        """
        self.expect_failure(block, err, lineno=7)

    def test_unused_param(self):
        block = self.parse("""
            module foo
            foo.func
                fn: object
                k: float
                i: float(unused=True)
                /
                *
                flag: bool(unused=True) = False
        """)
        sig = block.signatures[1]  # Function index == 1
        params = sig.parameters
        conv = lambda fn: params[fn].converter
        dataset = (
            {"name": "fn", "unused": False},
            {"name": "k", "unused": False},
            {"name": "i", "unused": True},
            {"name": "flag", "unused": True},
        )
        for param in dataset:
            name, unused = param.values()
            with self.subTest(name=name, unused=unused):
                p = conv(name)
                # Verify that the unused flag is parsed correctly.
                self.assertEqual(unused, p.unused)

                # Now, check that we'll produce correct code.
                decl = p.simple_declaration(in_parser=False)
                if unused:
                    self.assertIn("Py_UNUSED", decl)
                else:
                    self.assertNotIn("Py_UNUSED", decl)

                # Make sure the Py_UNUSED macro is not used in the parser body.
                parser_decl = p.simple_declaration(in_parser=True)
                self.assertNotIn("Py_UNUSED", parser_decl)

    def test_scaffolding(self):
        # test repr on special values
        self.assertEqual(repr(unspecified), '<Unspecified>')
        self.assertEqual(repr(NULL), '<Null>')

        # test that fail fails
        with support.captured_stdout() as stdout:
            errmsg = 'The igloos are melting'
            with self.assertRaisesRegex(ClinicError, errmsg) as cm:
                fail(errmsg, filename='clown.txt', line_number=69)
            exc = cm.exception
            self.assertEqual(exc.filename, 'clown.txt')
            self.assertEqual(exc.lineno, 69)
            self.assertEqual(stdout.getvalue(), "")

    def test_non_ascii_character_in_docstring(self):
        block = """
            module test
            test.fn
                a: int
                    á param docstring
            docstring fü bár baß
        """
        with support.captured_stdout() as stdout:
            self.parse(block)
        # The line numbers are off; this is a known limitation.
        expected = dedent("""\
            warning: Non-ascii characters are not allowed in docstrings: 'á'
            warning: Non-ascii characters are not allowed in docstrings: 'ü', 'á', 'ß'
        """)
        self.assertEqual(stdout.getvalue(), expected)

    def test_illegal_c_identifier(self):
        err = "Illegal C identifier: 17a"
        block = """
            module test
            test.fn
                a as 17a: int
        """
        self.expect_failure(block, err, lineno=2)

    def test_cannot_convert_special_method(self):
        err = "'__len__' is a special method and cannot be converted"
        block = """
            class T "" ""
            T.__len__
        """
        self.expect_failure(block, err, lineno=1)

    def test_cannot_specify_pydefault_without_default(self):
        err = "You can't specify py_default without specifying a default value!"
        block = """
            fn
                a: object(py_default='NULL')
        """
        self.expect_failure(block, err, lineno=1)

    def test_vararg_cannot_take_default_value(self):
        err = "Function 'fn' has an invalid parameter declaration:"
        block = """
            fn
                *args: tuple = None
        """
        self.expect_failure(block, err, lineno=1)

    def test_var_keyword_cannot_take_default_value(self):
        err = "Function 'fn' has an invalid parameter declaration:"
        block = """
            fn
                **kwds: dict = None
        """
        self.expect_failure(block, err, lineno=1)

    def test_default_is_not_of_correct_type(self):
        err = ("int_converter: default value 2.5 for field 'a' "
               "is not of type 'int'")
        block = """
            fn
                a: int = 2.5
        """
        self.expect_failure(block, err, lineno=1)

    def test_invalid_legacy_converter(self):
        err = "'fhi' is not a valid legacy converter"
        block = """
            fn
                a: 'fhi'
        """
        self.expect_failure(block, err, lineno=1)

    def test_parent_class_or_module_does_not_exist(self):
        err = "Parent class or module 'baz' does not exist"
        block = """
            module m
            baz.func
        """
        self.expect_failure(block, err, lineno=1)

    def test_duplicate_param_name(self):
        err = "You can't have two parameters named 'a'"
        block = """
            module m
            m.func
                a: int
                a: float
        """
        self.expect_failure(block, err, lineno=3)

    def test_param_requires_custom_c_name(self):
        err = "Parameter 'module' requires a custom C name"
        block = """
            module m
            m.func
                module: int
        """
        self.expect_failure(block, err, lineno=2)

    def test_state_func_docstring_assert_no_group(self):
        err = "Function 'func' has a ']' without a matching '['"
        block = """
            module m
            m.func
                ]
            docstring
        """
        self.expect_failure(block, err, lineno=2)

    def test_state_func_docstring_no_summary(self):
        err = "Docstring for 'm.func' does not have a summary line!"
        block = """
            module m
            m.func
            docstring1
            docstring2
            docstring3
        """
        # The line which should have been left blank.
        self.expect_failure(block, err, lineno=3)

    def test_state_func_docstring_long_summary(self):
        err = "Summary line for 'm.func' is too long!"
        block = f"""
            module m
            m.func
            {'x' * 100}

            Body.
        """
        self.expect_failure(block, err, lineno=2)

    def test_state_func_docstring_only_one_param_template(self):
        err = "You may not specify {parameters} more than once in a docstring!"
        block = """
            module m
            m.func
            docstring summary

            these are the params:
                {parameters}
            these are the params again:
                {parameters}
            and this is the end of the docstring
        """
        self.expect_failure(block, err, lineno=7)

    def test_kind_defining_class(self):
        function = self.parse_function("""
            module m
            class m.C "PyObject *" ""
            m.C.meth
                cls: defining_class
        """, signatures_in_block=3, function_index=2)
        p = function.parameters['cls']
        self.assertEqual(p.kind, inspect.Parameter.POSITIONAL_ONLY)

    def test_disallow_defining_class_at_module_level(self):
        err = "A 'defining_class' parameter cannot be defined at module level."
        block = """
            module m
            m.func
                cls: defining_class
        """
        self.expect_failure(block, err, lineno=2)

    def test_var_keyword_with_pos_or_kw(self):
        block = """
            module foo
            foo.bar
               x: int
               **kwds: dict
        """
        err = "Function 'bar' has an invalid parameter declaration (**kwargs?): '**kwds: dict'"
        self.expect_failure(block, err)

    def test_var_keyword_with_kw_only(self):
        block = """
            module foo
            foo.bar
               x: int
               /
               *
               y: int
               **kwds: dict
        """
        err = "Function 'bar' has an invalid parameter declaration (**kwargs?): '**kwds: dict'"
        self.expect_failure(block, err)

    def test_var_keyword_with_pos_or_kw_and_kw_only(self):
        block = """
            module foo
            foo.bar
               x: int
               /
               y: int
               *
               z: int
               **kwds: dict
        """
        err = "Function 'bar' has an invalid parameter declaration (**kwargs?): '**kwds: dict'"
        self.expect_failure(block, err)

    def test_allow_negative_accepted_by_py_ssize_t_converter_only(self):
        errmsg = re.escape("converter_init() got an unexpected keyword argument 'allow_negative'")
        unsupported_converters = [converter_name for converter_name in converters.keys()
                                  if converter_name != "Py_ssize_t"]
        for converter in unsupported_converters:
            with self.subTest(converter=converter):
                block = f"""
                    module m
                    m.func
                        a: {converter}(allow_negative=True)
                """
                with self.assertRaisesRegex((AssertionError, TypeError), errmsg):
                    self.parse_function(block)

@force_not_colorized_test_class
class ClinicExternalTest(TestCase):
    maxDiff = None

    def setUp(self):
        save_restore_converters(self)

    def run_clinic(self, *args):
        with (
            support.captured_stdout() as out,
            support.captured_stderr() as err,
            self.assertRaises(SystemExit) as cm
        ):
            clinic.main(args)
        return out.getvalue(), err.getvalue(), cm.exception.code

    def expect_success(self, *args):
        out, err, code = self.run_clinic(*args)
        if code != 0:
            self.fail("\n".join([f"Unexpected failure: {args=}", out, err]))
        self.assertEqual(err, "")
        return out

    def expect_failure(self, *args):
        out, err, code = self.run_clinic(*args)
        self.assertNotEqual(code, 0, f"Unexpected success: {args=}")
        return out, err

    def test_external(self):
        CLINIC_TEST = 'clinic.test.c'
        source = support.findfile(CLINIC_TEST)
        with open(source, encoding='utf-8') as f:
            orig_contents = f.read()

        # Run clinic CLI and verify that it does not complain.
        self.addCleanup(unlink, TESTFN)
        out = self.expect_success("-f", "-o", TESTFN, source)
        self.assertEqual(out, "")

        with open(TESTFN, encoding='utf-8') as f:
            new_contents = f.read()

        self.assertEqual(new_contents, orig_contents)

    def test_no_change(self):
        # bpo-42398: Test that the destination file is left unchanged if the
        # content does not change. Moreover, check also that the file
        # modification time does not change in this case.
        code = dedent("""
            /*[clinic input]
            [clinic start generated code]*/
            /*[clinic end generated code: output=da39a3ee5e6b4b0d input=da39a3ee5e6b4b0d]*/
        """)
        with os_helper.temp_dir() as tmp_dir:
            fn = os.path.join(tmp_dir, "test.c")
            with open(fn, "w", encoding="utf-8") as f:
                f.write(code)
            pre_mtime = os.stat(fn).st_mtime_ns
            self.expect_success(fn)
            post_mtime = os.stat(fn).st_mtime_ns
        # Don't change the file modification time
        # if the content does not change
        self.assertEqual(pre_mtime, post_mtime)

    TOUCH_CODE = dedent("""
        /*[clinic input]
        module m
        [clinic start generated code]*/

        /*[clinic input]
        output everything file
        m.func
            a: int
            /

        Docstring.
        [clinic start generated code]*/
    """)

    def test_touch_source(self):
        # gh-64595: The build system does not know that the source file
        # depends on the file generated from it, so the modification
        # times are updated to force the recompilation.
        def mtimes():
            return os.stat(fn).st_mtime_ns, os.stat(dest).st_mtime_ns

        def set_mtimes(source, generated):
            os.utime(fn, ns=(source, source))
            os.utime(dest, ns=(generated, generated))

        with os_helper.temp_dir() as tmp_dir:
            fn = os.path.join(tmp_dir, "test.c")
            with open(fn, "w", encoding="utf-8") as f:
                f.write(self.TOUCH_CODE)
            dest = self.dest_file(fn)
            self.expect_success(fn)
            source_mtime, generated_mtime = mtimes()
            self.assertGreaterEqual(generated_mtime, source_mtime)

            # The generated file is changed, so both files are touched.
            os.unlink(dest)
            old = source_mtime - 10**10
            os.utime(fn, ns=(old, old))
            self.expect_success(fn)
            source_mtime, generated_mtime = mtimes()
            self.assertGreater(source_mtime, old)
            self.assertGreaterEqual(generated_mtime, source_mtime)

            # Nothing is changed, but the source file is newer, so only
            # the generated file is touched.
            set_mtimes(source_mtime - 10**10, source_mtime - 2 * 10**10)
            old_source_mtime = os.stat(fn).st_mtime_ns
            self.expect_success(fn)
            source_mtime, generated_mtime = mtimes()
            self.assertEqual(source_mtime, old_source_mtime)
            self.assertGreaterEqual(generated_mtime, source_mtime)

            # Nothing is changed and the generated file is newer,
            # so no file is touched.
            self.expect_success(fn)
            self.assertEqual(mtimes(), (source_mtime, generated_mtime))

    def test_cli_force(self):
        invalid_input = dedent("""
            /*[clinic input]
            output preset block
            module test
            test.fn
                a: int
            [clinic start generated code]*/

            const char *hand_edited = "output block is overwritten";
            /*[clinic end generated code: output=bogus input=bogus]*/
        """)
        fail_msg = (
            "Checksum mismatch! Expected 'bogus', computed '2ed19'. "
            "Suggested fix: remove all generated code including the end marker, "
            "or use the '-f' option.\n"
        )
        with os_helper.temp_dir() as tmp_dir:
            fn = os.path.join(tmp_dir, "test.c")
            with open(fn, "w", encoding="utf-8") as f:
                f.write(invalid_input)
            # First, run the CLI without -f and expect failure.
            # Note, we cannot check the entire fail msg, because the path to
            # the tmp file will change for every run.
            _, err = self.expect_failure(fn)
            self.assertEndsWith(err, fail_msg)
            # Then, force regeneration; success expected.
            out = self.expect_success("-f", fn)
            self.assertEqual(out, "")
            # Verify by checking the checksum.
            checksum = (
                "/*[clinic end generated code: "
                "output=a2957bc4d43a3c2f input=9543a8d2da235301]*/\n"
            )
            with open(fn, encoding='utf-8') as f:
                generated = f.read()
            self.assertEndsWith(generated, checksum)

    DRY_RUN_CODE = dedent("""
        /*[clinic input]
        func
            a: int
            /

        Docstring.
        [clinic start generated code]*/
    """)

    def make_dry_run_file(self, tmp_dir):
        fn = os.path.join(tmp_dir, "test.c")
        with open(fn, "w", encoding="utf-8") as f:
            f.write(self.DRY_RUN_CODE)
        return fn

    @staticmethod
    def dest_file(fn):
        # The default destination for the generated code.  Its path is
        # built from the "{dirname}/clinic/{basename}.h" template, so it
        # always uses forward slashes, even on Windows.
        dirname, basename = os.path.split(fn)
        return f"{dirname}/clinic/{basename}.h"

    def check_unchanged(self, tmp_dir, fn, pre_mtime):
        # Neither the source file nor the destination file
        # nor its directory is created or modified.
        with open(fn, encoding="utf-8") as f:
            self.assertEqual(f.read(), self.DRY_RUN_CODE)
        self.assertEqual(os.stat(fn).st_mtime_ns, pre_mtime)
        self.assertEqual(os.listdir(tmp_dir), ["test.c"])

    def test_cli_dry_run(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = self.make_dry_run_file(tmp_dir)
            pre_mtime = os.stat(fn).st_mtime_ns
            out = self.expect_success("--dry-run", fn)
            self.assertEqual(out.splitlines(), [
                f"would create {self.dest_file(fn)}",
                f"would update {fn}",
            ])
            self.check_unchanged(tmp_dir, fn, pre_mtime)

    def test_cli_dry_run_no_change(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = self.make_dry_run_file(tmp_dir)
            self.expect_success(fn)
            self.assertEqual(self.expect_success("--dry-run", fn), "")
            self.assertEqual(self.expect_success("--diff", fn), "")

    def test_cli_dry_run_no_clinic_block(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = os.path.join(tmp_dir, "test.c")
            with open(fn, "w", encoding="utf-8") as f:
                f.write("int x;\n")
            self.assertEqual(self.expect_success("--dry-run", fn), "")

    def test_cli_dry_run_output(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = self.make_dry_run_file(tmp_dir)
            out_fn = os.path.join(tmp_dir, "output.c")
            out = self.expect_success("--dry-run", "-o", out_fn, fn)
            self.assertIn(f"would create {out_fn}", out)
            self.assertNotIn(f"would update {fn}", out)
            self.assertFalse(os.path.exists(out_fn))

    def test_cli_dry_run_make(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = self.make_dry_run_file(tmp_dir)
            pre_mtime = os.stat(fn).st_mtime_ns
            out = self.expect_success("--dry-run", "--make", "--srcdir", tmp_dir)
            self.assertIn(f"would update {fn}", out)
            self.check_unchanged(tmp_dir, fn, pre_mtime)

    def test_cli_dry_run_verbose(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = self.make_dry_run_file(tmp_dir)
            out, err, code = self.run_clinic("-v", "--dry-run", fn)
            self.assertEqual(code, 0)
            # The progress goes to stderr, so that the standard output
            # contains only the report.
            self.assertEqual(err.splitlines(), [fn])
            self.assertEqual(out.splitlines(), [
                f"would create {self.dest_file(fn)}",
                f"would update {fn}",
            ])

    def test_cli_dry_run_checksum_mismatch(self):
        invalid_input = dedent("""
            /*[clinic input]
            output preset block
            module test
            test.fn
                a: int
            [clinic start generated code]*/
            /*[clinic end generated code: output=bogus input=bogus]*/
        """)
        with os_helper.temp_dir() as tmp_dir:
            fn = os.path.join(tmp_dir, "test.c")
            with open(fn, "w", encoding="utf-8") as f:
                f.write(invalid_input)
            pre_mtime = os.stat(fn).st_mtime_ns
            # The dry run does not disable the checksum verification.
            _, err = self.expect_failure("--dry-run", fn)
            self.assertIn("Checksum mismatch!", err)
            # With -f the change is reported, but still not written.
            out = self.expect_success("--dry-run", "-f", fn)
            self.assertIn(f"would update {fn}", out)
            with open(fn, encoding="utf-8") as f:
                self.assertEqual(f.read(), invalid_input)
            self.assertEqual(os.stat(fn).st_mtime_ns, pre_mtime)

    def test_cli_diff(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = self.make_dry_run_file(tmp_dir)
            pre_mtime = os.stat(fn).st_mtime_ns
            out = self.expect_success("--diff", fn)
            self.check_unchanged(tmp_dir, fn, pre_mtime)

            # A new file is created by the patch.
            dest_fn = self.dest_file(fn)
            self.assertStartsWith(out, f"--- /dev/null\n+++ {dest_fn}\n@@ -0,0 +1,")
            self.assertIn(f"--- {fn}\n+++ {fn}\n", out)
            self.assertIn("+/*[clinic end generated code:", out)

            # The patch is what clinic would have written.
            self.expect_success(fn)
            with open(fn, encoding="utf-8") as f:
                new_contents = f.read()
            expected = "".join(difflib.unified_diff(
                self.DRY_RUN_CODE.splitlines(keepends=True),
                new_contents.splitlines(keepends=True),
                fromfile=fn, tofile=fn))
            self.assertEndsWith(out, expected)

    def test_cli_fail_converters_and_dry_run(self):
        for opt in "--dry-run", "--diff":
            with self.subTest(opt=opt):
                _, err = self.expect_failure("--converters", opt)
                msg = "can't use --dry-run or --diff with --converters"
                self.assertIn(msg, err)

    def test_cli_make(self):
        c_code = dedent("""
            /*[clinic input]
            [clinic start generated code]*/
        """)
        py_code = "pass"
        c_files = "file1.c", "file2.c"
        py_files = "file1.py", "file2.py"

        def create_files(files, srcdir, code):
            for fn in files:
                path = os.path.join(srcdir, fn)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(code)

        with os_helper.temp_dir() as tmp_dir:
            # add some folders, some C files and a Python file
            create_files(c_files, tmp_dir, c_code)
            create_files(py_files, tmp_dir, py_code)

            # create C files in externals/ dir
            ext_path = os.path.join(tmp_dir, "externals")
            with os_helper.temp_dir(path=ext_path) as externals:
                create_files(c_files, externals, c_code)

                # run clinic in verbose mode with --make on tmpdir
                out = self.expect_success("-v", "--make", "--srcdir", tmp_dir)

            # expect verbose mode to only mention the C files in tmp_dir
            for filename in c_files:
                with self.subTest(filename=filename):
                    path = os.path.join(tmp_dir, filename)
                    self.assertIn(path, out)
            for filename in py_files:
                with self.subTest(filename=filename):
                    path = os.path.join(tmp_dir, filename)
                    self.assertNotIn(path, out)
            # don't expect C files from the externals dir
            for filename in c_files:
                with self.subTest(filename=filename):
                    path = os.path.join(ext_path, filename)
                    self.assertNotIn(path, out)

    def test_cli_make_exclude(self):
        code = dedent("""
            /*[clinic input]
            [clinic start generated code]*/
        """)
        with os_helper.temp_dir(quiet=False) as tmp_dir:
            # add some folders, some C files and a Python file
            for fn in "file1.c", "file2.c", "file3.c", "file4.c":
                path = os.path.join(tmp_dir, fn)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(code)

            # Run clinic in verbose mode with --make on tmpdir.
            # Exclude file2.c and file3.c.
            out = self.expect_success(
                "-v", "--make", "--srcdir", tmp_dir,
                "--exclude", os.path.join(tmp_dir, "file2.c"),
                # The added ./ should be normalised away.
                "--exclude", os.path.join(tmp_dir, "./file3.c"),
                # Relative paths should also work.
                "--exclude", "file4.c"
            )

            # expect verbose mode to only mention the C files in tmp_dir
            self.assertIn("file1.c", out)
            self.assertNotIn("file2.c", out)
            self.assertNotIn("file3.c", out)
            self.assertNotIn("file4.c", out)

    def test_cli_verbose(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = os.path.join(tmp_dir, "test.c")
            with open(fn, "w", encoding="utf-8") as f:
                f.write("")
            out = self.expect_success("-v", fn)
            self.assertEqual(out.strip(), fn)

    @support.force_not_colorized
    def test_cli_help(self):
        out = self.expect_success("-h")
        self.assertIn("usage: clinic.py", out)

    def test_cli_converters(self):
        prelude = dedent("""
            Legacy converters:
                B C D L O S U Y Z Z#
                b c d f h i l p s s# s* u u# w* y y# y* z z# z*

            Converters:
        """)
        expected_converters = (
            "bool",
            "BOOL",
            "byte",
            "char",
            "defining_class",
            "double",
            "DWORD",
            "fildes",
            "float",
            "HANDLE",
            "int",
            "long",
            "long_long",
            "object",
            "pid_t",
            "Py_buffer",
            "Py_complex",
            "Py_off_t",
            "Py_ssize_t",
            "Py_UNICODE",
            "PyByteArrayObject",
            "PyBytesObject",
            "self",
            "short",
            "size_t",
            "slice_index",
            "str",
            "uint16",
            "uint32",
            "uint64",
            "uint8",
            "unicode",
            "unicode_fs_decoded",
            "unicode_fs_encoded",
            "unsigned_char",
            "unsigned_int",
            "unsigned_long",
            "unsigned_long_long",
            "unsigned_short",
        )
        finale = dedent("""
            Return converters:
                bool()
                double()
                float()
                int()
                long()
                object()
                Py_ssize_t()
                size_t()
                unsigned_int()
                unsigned_long()

            All converters also accept (c_default=None, py_default=None, annotation=None).
            All return converters also accept (py_default=None).
        """)
        out = self.expect_success("--converters")
        # We cannot simply compare the output, because the repr of the *accept*
        # param may change (it's a set, thus unordered). So, let's compare the
        # start and end of the expected output, and then assert that the
        # converters appear lined up in alphabetical order.
        self.assertStartsWith(out, prelude)
        self.assertEndsWith(out, finale)

        out = out.removeprefix(prelude)
        out = out.removesuffix(finale)
        lines = out.split("\n")
        for converter, line in zip(expected_converters, lines):
            line = line.lstrip()
            with self.subTest(converter=converter):
                self.assertStartsWith(line, converter)

    def test_cli_converters_file(self):
        code = dedent("""
            /*[python input]
            class my_type_converter(CConverter):
                type = 'my_type'
                converter = 'my_type_converter'

                def converter_init(self, *, strict=False):
                    pass

            class my_result_return_converter(CReturnConverter):
                type = 'my_result'
            [python start generated code]*/
        """)
        with os_helper.temp_dir() as tmp_dir:
            fn = os.path.join(tmp_dir, "test.c")
            with open(fn, "w", encoding="utf-8") as f:
                f.write(code)
            out = self.expect_success("--converters", fn)
            self.assertIn("Converters:\n    my_type(strict=False)\n", out)
            self.assertIn("Return converters:\n    my_result()\n", out)
            # Only the converters defined in the file are listed.
            self.assertNotIn("Legacy converters:", out)
            self.assertNotIn("bool(", out)
            # Listing the converters does not write anything.
            with open(fn, encoding="utf-8") as f:
                self.assertEqual(f.read(), code)
            self.assertEqual(os.listdir(tmp_dir), ["test.c"])

    def test_cli_converters_make(self):
        code = dedent("""
            /*[python input]
            class my_type_converter(CConverter):
                type = 'my_type'
                converter = 'my_type_converter'
            [python start generated code]*/
        """)
        with os_helper.temp_dir() as tmp_dir:
            fn = os.path.join(tmp_dir, "test.c")
            with open(fn, "w", encoding="utf-8") as f:
                f.write(code)
            out = self.expect_success("--converters", "--make",
                                      "--srcdir", tmp_dir)
            self.assertIn("Converters:\n    my_type()\n", out)
            with open(fn, encoding="utf-8") as f:
                self.assertEqual(f.read(), code)

    def test_cli_converters_no_converters(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = os.path.join(tmp_dir, "test.c")
            with open(fn, "w", encoding="utf-8") as f:
                f.write("/*[clinic input]\n[clinic start generated code]*/\n")
            self.assertEqual(self.expect_success("--converters", fn), "")

    LIST_CODE = dedent("""
        /*[clinic input]
        func
            a: int
            /

        Docstring.
        [clinic start generated code]*/

        /*[clinic input]
        cloned = func
        [clinic start generated code]*/

        /*[clinic input]
        module m
        class m.C "void *" ""
        class m.C.D "void *" ""
        [clinic start generated code]*/

        /*[clinic input]
        m.C.meth
            self: self(type="void *")
            a: object
            [
            b: object
            ]
            /

        Docstring.
        [clinic start generated code]*/

        /*[clinic input]
        @classmethod
        m.C.__new__
            a: object

        Docstring.
        [clinic start generated code]*/

        /*[clinic input]
        @getter
        m.C.prop
        [clinic start generated code]*/

        /*[clinic input]
        @setter
        m.C.prop
        [clinic start generated code]*/

        /*[clinic input]
        m.C.D.meth
            self: self(type="void *")

        Docstring.
        [clinic start generated code]*/
    """)

    def make_list_file(self, tmp_dir):
        fn = os.path.join(tmp_dir, "test.c")
        with open(fn, "w", encoding="utf-8") as f:
            f.write(self.LIST_CODE)
        return fn

    LIST_OUTPUT = [
        "  func($module, a, /)",
        "  cloned($module, a, /)",
        "  module m",
        "    class m.C",
        # A signature with an option group is only for the docstring.
        "      m.C.meth(a, [b])",
        "      m.C(a)",
        "      getter m.C.prop",
        "      setter m.C.prop",
        "      class m.C.D",
        "        m.C.D.meth($self, /)",
    ]

    def test_cli_list(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = self.make_list_file(tmp_dir)
            pre_mtime = os.stat(fn).st_mtime_ns
            out = self.expect_success("--list", fn)
            self.assertEqual(out.splitlines(), [fn] + self.LIST_OUTPUT)
            # Nothing is written.
            with open(fn, encoding="utf-8") as f:
                self.assertEqual(f.read(), self.LIST_CODE)
            self.assertEqual(os.stat(fn).st_mtime_ns, pre_mtime)
            self.assertEqual(os.listdir(tmp_dir), ["test.c"])

    def test_cli_list_no_clinic_block(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = os.path.join(tmp_dir, "test.c")
            with open(fn, "w", encoding="utf-8") as f:
                f.write("int x;\n")
            self.assertEqual(self.expect_success("--list", fn), "")

    def test_cli_list_no_definitions(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = os.path.join(tmp_dir, "test.c")
            with open(fn, "w", encoding="utf-8") as f:
                f.write("/*[clinic input]\n[clinic start generated code]*/\n")
            self.assertEqual(self.expect_success("--list", fn), "")

    def test_cli_list_make(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = self.make_list_file(tmp_dir)
            out = self.expect_success("--list", "--make", "--srcdir", tmp_dir)
            self.assertEqual(out.splitlines(), [fn] + self.LIST_OUTPUT)
            self.assertEqual(os.listdir(tmp_dir), ["test.c"])

    def test_cli_list_verbose(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = self.make_list_file(tmp_dir)
            # The progress does not mix with the report.
            out, err, code = self.run_clinic("-v", "--list", fn)
            self.assertEqual(code, 0)
            self.assertEqual(err.splitlines(), [fn])
            self.assertEqual(out.splitlines(), [fn] + self.LIST_OUTPUT)

    def test_cli_list_checksum_mismatch(self):
        with os_helper.temp_dir() as tmp_dir:
            fn = self.make_list_file(tmp_dir)
            with open(fn, "a", encoding="utf-8") as f:
                f.write("/*[clinic end generated code: "
                        "output=0123456789abcdef input=fedcba9876543210]*/\n")
            _, err = self.expect_failure("--list", fn)
            self.assertIn("Checksum mismatch!", err)
            # The check is skipped with --force.
            out = self.expect_success("-f", "--list", fn)
            self.assertEqual(out.splitlines(), [fn] + self.LIST_OUTPUT)
            self.assertEqual(os.listdir(tmp_dir), ["test.c"])

    def test_cli_list_external(self):
        # A file which uses getters, setters and nested classes.
        source = support.findfile('clinic.test.c')
        out = self.expect_success("--list", source)
        lines = out.splitlines()
        self.assertEqual(lines[0], source)
        for line in ("  class Test",
                     "    getter Test.property",
                     "    setter Test.property",
                     "    Test.class_method($type, /)",
                     "  module m",
                     "    class m.T"):
            with self.subTest(line=line):
                self.assertIn(line, lines)

    def test_cli_fail_list_and_dry_run(self):
        for opt in "--dry-run", "--diff":
            with self.subTest(opt=opt):
                _, err = self.expect_failure("--list", opt, "test.c")
                self.assertIn("can't use --dry-run or --diff with --list", err)

    def test_cli_fail_list_and_converters(self):
        _, err = self.expect_failure("--list", "--converters", "test.c")
        self.assertIn("can't use --converters with --list", err)

    def test_cli_fail_directory(self):
        with os_helper.temp_dir() as tmp_dir:
            subdir = os.path.join(tmp_dir, "test.c")
            os.mkdir(subdir)
            _, err = self.expect_failure(subdir)
            self.assertIn(f"Can't read file {subdir!r}: it is a directory", err)

    def test_cli_fail_no_filename(self):
        _, err = self.expect_failure()
        self.assertIn("no input files", err)

    def test_cli_fail_output_and_multiple_files(self):
        _, err = self.expect_failure("-o", "out.c", "input.c", "moreinput.c")
        msg = "error: can't use -o with multiple filenames"
        self.assertIn(msg, err)

    def test_cli_fail_filename_or_output_and_make(self):
        msg = "can't use -o or filenames with --make"
        for opts in ("-o", "out.c"), ("filename.c",):
            with self.subTest(opts=opts):
                _, err = self.expect_failure("--make", *opts)
                self.assertIn(msg, err)

    def test_cli_fail_make_without_srcdir(self):
        _, err = self.expect_failure("--make", "--srcdir", "")
        msg = "error: --srcdir must not be empty with --make"
        self.assertIn(msg, err)

    def test_file_dest(self):
        block = dedent("""
            /*[clinic input]
            destination test new file {path}.h
            output everything test
            func
                a: object
                /
            [clinic start generated code]*/
        """)
        expected_checksum_line = (
            "/*[clinic end generated code: "
            "output=da39a3ee5e6b4b0d input=b602ab8e173ac3bd]*/\n"
        )
        expected_output = dedent("""\
            /*[clinic input]
            preserve
            [clinic start generated code]*/

            PyDoc_VAR(func__doc__);

            PyDoc_STRVAR(func__doc__,
            "func($module, a, /)\\n"
            "--\\n"
            "\\n");

            #define FUNC_METHODDEF    \\
                {"func", (PyCFunction)func, METH_O, func__doc__},

            static PyObject *
            func(PyObject *module, PyObject *a)
            /*[clinic end generated code: output=3dde2d13002165b9 input=a9049054013a1b77]*/
        """)
        with os_helper.temp_dir() as tmp_dir:
            in_fn = os.path.join(tmp_dir, "test.c")
            out_fn = os.path.join(tmp_dir, "test.c.h")
            with open(in_fn, "w", encoding="utf-8") as f:
                f.write(block)
            with open(out_fn, "w", encoding="utf-8") as f:
                f.write("")  # Write an empty output file!
            # Clinic should complain about the empty output file.
            _, err = self.expect_failure(in_fn)
            expected_err = (f"Modified destination file {out_fn!r}; "
                            "not overwriting!")
            self.assertIn(expected_err, err)
            # Run clinic again, this time with the -f option.
            _ = self.expect_success("-f", in_fn)
            # Read back the generated output.
            with open(in_fn, encoding="utf-8") as f:
                data = f.read()
                expected_block = f"{block}{expected_checksum_line}"
                self.assertEqual(data, expected_block)
            with open(out_fn, encoding="utf-8") as f:
                data = f.read()
                self.assertEqual(data, expected_output)

try:
    import _testclinic as ac_tester
except ImportError:
    ac_tester = None

@unittest.skipIf(ac_tester is None, "_testclinic is missing")
class ClinicFunctionalTest(unittest.TestCase):
    locals().update((name, getattr(ac_tester, name))
                    for name in dir(ac_tester) if name.startswith('test_'))

    def check_depr(self, regex, fn, /, *args, **kwds):
        with self.assertWarnsRegex(DeprecationWarning, regex) as cm:
            # Record the line number, so we're sure we've got the correct stack
            # level on the deprecation warning.
            _, lineno = fn(*args, **kwds), sys._getframe().f_lineno
        self.assertEqual(cm.filename, __file__)
        self.assertEqual(cm.lineno, lineno)

    def check_depr_star(self, pnames, fn, /, *args, name=None, **kwds):
        if name is None:
            name = fn.__qualname__
            if isinstance(fn, type):
                name = f'{fn.__module__}.{name}'
        regex = (
            fr"Passing( more than)?( [0-9]+)? positional argument(s)? to "
            fr"{re.escape(name)}\(\) is deprecated. Parameters? {pnames} will "
            fr"become( a)? keyword-only parameters? in Python 3\.14"
        )
        self.check_depr(regex, fn, *args, **kwds)

    def check_depr_kwd(self, pnames, fn, *args, name=None, **kwds):
        if name is None:
            name = fn.__qualname__
            if isinstance(fn, type):
                name = f'{fn.__module__}.{name}'
        pl = 's' if ' ' in pnames else ''
        regex = (
            fr"Passing keyword argument{pl} {pnames} to "
            fr"{re.escape(name)}\(\) is deprecated. Parameter{pl} {pnames} "
            fr"will become positional-only in Python 3\.14."
        )
        self.check_depr(regex, fn, *args, **kwds)

    def test_objects_converter(self):
        with self.assertRaises(TypeError):
            ac_tester.objects_converter()
        self.assertEqual(ac_tester.objects_converter(1, 2), (1, 2))
        self.assertEqual(ac_tester.objects_converter([], 'whatever class'), ([], 'whatever class'))
        self.assertEqual(ac_tester.objects_converter(1), (1, None))

    def test_bytes_object_converter(self):
        with self.assertRaises(TypeError):
            ac_tester.bytes_object_converter(1)
        self.assertEqual(ac_tester.bytes_object_converter(b'BytesObject'), (b'BytesObject',))

    def test_byte_array_object_converter(self):
        with self.assertRaises(TypeError):
            ac_tester.byte_array_object_converter(1)
        byte_arr = bytearray(b'ByteArrayObject')
        self.assertEqual(ac_tester.byte_array_object_converter(byte_arr), (byte_arr,))

    def test_unicode_converter(self):
        with self.assertRaises(TypeError):
            ac_tester.unicode_converter(1)
        self.assertEqual(ac_tester.unicode_converter('unicode'), ('unicode',))

    def test_bool_converter(self):
        with self.assertRaises(TypeError):
            ac_tester.bool_converter(False, False, 'not a int')
        self.assertEqual(ac_tester.bool_converter(), (True, True, True))
        self.assertEqual(ac_tester.bool_converter('', [], 5), (False, False, True))
        self.assertEqual(ac_tester.bool_converter(('not empty',), {1: 2}, 0), (True, True, False))

    def test_bool_converter_c_default(self):
        self.assertEqual(ac_tester.bool_converter_c_default(), (1, 0, -2, -3))
        self.assertEqual(ac_tester.bool_converter_c_default(False, True, False, True),
                         (0, 1, 0, 1))

    def test_char_converter(self):
        with self.assertRaises(TypeError):
            ac_tester.char_converter(1)
        with self.assertRaises(TypeError):
            ac_tester.char_converter(b'ab')
        chars = [b'A', b'\a', b'\b', b'\t', b'\n', b'\v', b'\f', b'\r', b'"', b"'", b'?', b'\\', b'\000', b'\377']
        expected = tuple(ord(c) for c in chars)
        self.assertEqual(ac_tester.char_converter(), expected)
        chars = [b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'a', b'b', b'c', b'd']
        expected = tuple(ord(c) for c in chars)
        self.assertEqual(ac_tester.char_converter(*chars), expected)

    def test_unsigned_char_converter(self):
        from _testcapi import UCHAR_MAX
        SCHAR_MAX = UCHAR_MAX // 2
        SCHAR_MIN = SCHAR_MAX - UCHAR_MAX
        with self.assertRaises(OverflowError):
            ac_tester.unsigned_char_converter(-1)
        with self.assertRaises(OverflowError):
            ac_tester.unsigned_char_converter(UCHAR_MAX + 1)
        with self.assertRaises(OverflowError):
            ac_tester.unsigned_char_converter(0, UCHAR_MAX + 1)
        with self.assertRaises(TypeError):
            ac_tester.unsigned_char_converter([])
        self.assertEqual(ac_tester.unsigned_char_converter(), (12, 34, 56))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_char_converter(0, 0, UCHAR_MAX + 1), (0, 0, 0))
        self.assertEqual(ac_tester.unsigned_char_converter(0, 0, SCHAR_MIN), (0, 0, SCHAR_MAX + 1))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_char_converter(0, 0, SCHAR_MIN - 1), (0, 0, SCHAR_MAX))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_char_converter(0, 0, (UCHAR_MAX + 1) * 3 + 123), (0, 0, 123))

    def test_short_converter(self):
        from _testcapi import SHRT_MIN, SHRT_MAX
        with self.assertRaises(OverflowError):
            ac_tester.short_converter(SHRT_MIN - 1)
        with self.assertRaises(OverflowError):
            ac_tester.short_converter(SHRT_MAX + 1)
        with self.assertRaises(TypeError):
            ac_tester.short_converter([])
        self.assertEqual(ac_tester.short_converter(-1234), (-1234,))
        self.assertEqual(ac_tester.short_converter(4321), (4321,))

    def test_unsigned_short_converter(self):
        from _testcapi import SHRT_MIN, SHRT_MAX, USHRT_MAX
        with self.assertRaises(ValueError):
            ac_tester.unsigned_short_converter(-1)
        with self.assertRaises(OverflowError):
            ac_tester.unsigned_short_converter(USHRT_MAX + 1)
        with self.assertRaises(OverflowError):
            ac_tester.unsigned_short_converter(0, USHRT_MAX + 1)
        with self.assertRaises(TypeError):
            ac_tester.unsigned_short_converter([])
        self.assertEqual(ac_tester.unsigned_short_converter(), (12, 34, 56))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_short_converter(0, 0, USHRT_MAX + 1), (0, 0, 0))
        self.assertEqual(ac_tester.unsigned_short_converter(0, 0, SHRT_MIN), (0, 0, SHRT_MAX + 1))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_short_converter(0, 0, SHRT_MIN - 1), (0, 0, SHRT_MAX))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_short_converter(0, 0, (USHRT_MAX + 1) * 3 + 123), (0, 0, 123))

    def test_int_converter(self):
        from _testcapi import INT_MIN, INT_MAX
        with self.assertRaises(OverflowError):
            ac_tester.int_converter(INT_MIN - 1)
        with self.assertRaises(OverflowError):
            ac_tester.int_converter(INT_MAX + 1)
        with self.assertRaises(TypeError):
            ac_tester.int_converter(1, 2, 3)
        with self.assertRaises(TypeError):
            ac_tester.int_converter([])
        self.assertEqual(ac_tester.int_converter(), (12, 34, 45))
        self.assertEqual(ac_tester.int_converter(1, 2, '3'), (1, 2, ord('3')))

    def test_unsigned_int_converter(self):
        from _testcapi import INT_MIN, INT_MAX, UINT_MAX
        with self.assertRaises(ValueError):
            ac_tester.unsigned_int_converter(-1)
        with self.assertRaises(OverflowError):
            ac_tester.unsigned_int_converter(UINT_MAX + 1)
        with self.assertRaises(OverflowError):
            ac_tester.unsigned_int_converter(0, UINT_MAX + 1)
        with self.assertRaises(TypeError):
            ac_tester.unsigned_int_converter([])
        self.assertEqual(ac_tester.unsigned_int_converter(), (12, 34, 56))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_int_converter(0, 0, UINT_MAX + 1), (0, 0, 0))
        self.assertEqual(ac_tester.unsigned_int_converter(0, 0, INT_MIN), (0, 0, INT_MAX + 1))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_int_converter(0, 0, INT_MIN - 1), (0, 0, INT_MAX))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_int_converter(0, 0, (UINT_MAX + 1) * 3 + 123), (0, 0, 123))

    def test_long_converter(self):
        from _testcapi import LONG_MIN, LONG_MAX
        with self.assertRaises(OverflowError):
            ac_tester.long_converter(LONG_MIN - 1)
        with self.assertRaises(OverflowError):
            ac_tester.long_converter(LONG_MAX + 1)
        with self.assertRaises(TypeError):
            ac_tester.long_converter([])
        self.assertEqual(ac_tester.long_converter(), (12,))
        self.assertEqual(ac_tester.long_converter(-1234), (-1234,))

    def test_unsigned_long_converter(self):
        from _testcapi import LONG_MIN, LONG_MAX, ULONG_MAX
        with self.assertRaises(ValueError):
            ac_tester.unsigned_long_converter(-1)
        with self.assertRaises(OverflowError):
            ac_tester.unsigned_long_converter(ULONG_MAX + 1)
        with self.assertRaises(OverflowError):
            ac_tester.unsigned_long_converter(0, ULONG_MAX + 1)
        with self.assertRaises(TypeError):
            ac_tester.unsigned_long_converter([])
        self.assertEqual(ac_tester.unsigned_long_converter(), (12, 34, 56))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_long_converter(0, 0, ULONG_MAX + 1), (0, 0, 0))
        self.assertEqual(ac_tester.unsigned_long_converter(0, 0, LONG_MIN), (0, 0, LONG_MAX + 1))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_long_converter(0, 0, LONG_MIN - 1), (0, 0, LONG_MAX))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_long_converter(0, 0, (ULONG_MAX + 1) * 3 + 123), (0, 0, 123))

    def test_long_long_converter(self):
        from _testcapi import LLONG_MIN, LLONG_MAX
        with self.assertRaises(OverflowError):
            ac_tester.long_long_converter(LLONG_MIN - 1)
        with self.assertRaises(OverflowError):
            ac_tester.long_long_converter(LLONG_MAX + 1)
        with self.assertRaises(TypeError):
            ac_tester.long_long_converter([])
        self.assertEqual(ac_tester.long_long_converter(), (12,))
        self.assertEqual(ac_tester.long_long_converter(-1234), (-1234,))

    def test_unsigned_long_long_converter(self):
        from _testcapi import LLONG_MIN, LLONG_MAX, ULLONG_MAX
        with self.assertRaises(ValueError):
            ac_tester.unsigned_long_long_converter(-1)
        with self.assertRaises(OverflowError):
            ac_tester.unsigned_long_long_converter(ULLONG_MAX + 1)
        with self.assertRaises(OverflowError):
            ac_tester.unsigned_long_long_converter(0, ULLONG_MAX + 1)
        with self.assertRaises(TypeError):
            ac_tester.unsigned_long_long_converter([])
        self.assertEqual(ac_tester.unsigned_long_long_converter(), (12, 34, 56))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_long_long_converter(0, 0, ULLONG_MAX + 1), (0, 0, 0))
        self.assertEqual(ac_tester.unsigned_long_long_converter(0, 0, LLONG_MIN), (0, 0, LLONG_MAX + 1))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_long_long_converter(0, 0, LLONG_MIN - 1), (0, 0, LLONG_MAX))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(ac_tester.unsigned_long_long_converter(0, 0, (ULLONG_MAX + 1) * 3 + 123), (0, 0, 123))

    def test_py_ssize_t_converter(self):
        from _testcapi import PY_SSIZE_T_MIN, PY_SSIZE_T_MAX
        with self.assertRaises(OverflowError):
            ac_tester.py_ssize_t_converter(PY_SSIZE_T_MIN - 1)
        with self.assertRaises(OverflowError):
            ac_tester.py_ssize_t_converter(PY_SSIZE_T_MAX + 1)
        with self.assertRaises(TypeError):
            ac_tester.py_ssize_t_converter([])
        with self.assertRaises(ValueError):
            ac_tester.py_ssize_t_converter(12, 34, 56, -1)
        with self.assertRaises(ValueError):
            ac_tester.py_ssize_t_converter(12, 34, 56, 78, -1)
        self.assertEqual(ac_tester.py_ssize_t_converter(), (12, 34, 56, 78, 90, -12, -34))
        self.assertEqual(ac_tester.py_ssize_t_converter(1, 2, None, 3, None, 4, None), (1, 2, 56, 3, 90, 4, -34))

    def test_slice_index_converter(self):
        from _testcapi import PY_SSIZE_T_MIN, PY_SSIZE_T_MAX
        with self.assertRaises(TypeError):
            ac_tester.slice_index_converter([])
        self.assertEqual(ac_tester.slice_index_converter(), (12, 34, 56))
        self.assertEqual(ac_tester.slice_index_converter(1, 2, None), (1, 2, 56))
        self.assertEqual(ac_tester.slice_index_converter(PY_SSIZE_T_MAX, PY_SSIZE_T_MAX + 1, PY_SSIZE_T_MAX + 1234),
                         (PY_SSIZE_T_MAX, PY_SSIZE_T_MAX, PY_SSIZE_T_MAX))
        self.assertEqual(ac_tester.slice_index_converter(PY_SSIZE_T_MIN, PY_SSIZE_T_MIN - 1, PY_SSIZE_T_MIN - 1234),
                         (PY_SSIZE_T_MIN, PY_SSIZE_T_MIN, PY_SSIZE_T_MIN))

    def test_size_t_converter(self):
        with self.assertRaises(ValueError):
            ac_tester.size_t_converter(-1)
        with self.assertRaises(TypeError):
            ac_tester.size_t_converter([])
        self.assertEqual(ac_tester.size_t_converter(), (12,))

    def test_float_converter(self):
        with self.assertRaises(TypeError):
            ac_tester.float_converter([])
        self.assertEqual(ac_tester.float_converter(), (12.5,))
        self.assertEqual(ac_tester.float_converter(-0.5), (-0.5,))

    def test_double_converter(self):
        with self.assertRaises(TypeError):
            ac_tester.double_converter([])
        self.assertEqual(ac_tester.double_converter(), (12.5,))
        self.assertEqual(ac_tester.double_converter(-0.5), (-0.5,))

    def test_py_complex_converter(self):
        with self.assertRaises(TypeError):
            ac_tester.py_complex_converter([])
        self.assertEqual(ac_tester.py_complex_converter(complex(1, 2)), (complex(1, 2),))
        self.assertEqual(ac_tester.py_complex_converter(complex('-1-2j')), (complex('-1-2j'),))
        self.assertEqual(ac_tester.py_complex_converter(-0.5), (-0.5,))
        self.assertEqual(ac_tester.py_complex_converter(10), (10,))

    def test_str_converter(self):
        with self.assertRaises(TypeError):
            ac_tester.str_converter(1)
        with self.assertRaises(TypeError):
            ac_tester.str_converter('a', 'b', 'c')
        with self.assertRaises(ValueError):
            ac_tester.str_converter('a', b'b\0b', 'c')
        self.assertEqual(ac_tester.str_converter('a', b'b', 'c'), ('a', 'b', 'c'))
        self.assertEqual(ac_tester.str_converter('a', b'b', b'c'), ('a', 'b', 'c'))
        self.assertEqual(ac_tester.str_converter('a', b'b', 'c\0c'), ('a', 'b', 'c\0c'))

    def test_str_converter_encoding(self):
        with self.assertRaises(TypeError):
            ac_tester.str_converter_encoding(1)
        self.assertEqual(ac_tester.str_converter_encoding('a', 'b', 'c'), ('a', 'b', 'c'))
        with self.assertRaises(TypeError):
            ac_tester.str_converter_encoding('a', b'b\0b', 'c')
        self.assertEqual(ac_tester.str_converter_encoding('a', b'b', bytearray([ord('c')])), ('a', 'b', 'c'))
        self.assertEqual(ac_tester.str_converter_encoding('a', b'b', bytearray([ord('c'), 0, ord('c')])),
                         ('a', 'b', 'c\x00c'))
        self.assertEqual(ac_tester.str_converter_encoding('a', b'b', b'c\x00c'), ('a', 'b', 'c\x00c'))

    def test_py_buffer_converter(self):
        with self.assertRaises(TypeError):
            ac_tester.py_buffer_converter('a', 'b')
        self.assertEqual(ac_tester.py_buffer_converter('abc', bytearray([1, 2, 3])), (b'abc', b'\x01\x02\x03'))

    def test_keywords(self):
        self.assertEqual(ac_tester.keywords(1, 2), (1, 2))
        self.assertEqual(ac_tester.keywords(1, b=2), (1, 2))
        self.assertEqual(ac_tester.keywords(a=1, b=2), (1, 2))

    def test_keywords_kwonly(self):
        with self.assertRaises(TypeError):
            ac_tester.keywords_kwonly(1, 2)
        self.assertEqual(ac_tester.keywords_kwonly(1, b=2), (1, 2))
        self.assertEqual(ac_tester.keywords_kwonly(a=1, b=2), (1, 2))

    def test_keywords_opt(self):
        self.assertEqual(ac_tester.keywords_opt(1), (1, None, None))
        self.assertEqual(ac_tester.keywords_opt(1, 2), (1, 2, None))
        self.assertEqual(ac_tester.keywords_opt(1, 2, 3), (1, 2, 3))
        self.assertEqual(ac_tester.keywords_opt(1, b=2), (1, 2, None))
        self.assertEqual(ac_tester.keywords_opt(1, 2, c=3), (1, 2, 3))
        self.assertEqual(ac_tester.keywords_opt(a=1, c=3), (1, None, 3))
        self.assertEqual(ac_tester.keywords_opt(a=1, b=2, c=3), (1, 2, 3))

    def test_keywords_opt_kwonly(self):
        self.assertEqual(ac_tester.keywords_opt_kwonly(1), (1, None, None, None))
        self.assertEqual(ac_tester.keywords_opt_kwonly(1, 2), (1, 2, None, None))
        with self.assertRaises(TypeError):
            ac_tester.keywords_opt_kwonly(1, 2, 3)
        self.assertEqual(ac_tester.keywords_opt_kwonly(1, b=2), (1, 2, None, None))
        self.assertEqual(ac_tester.keywords_opt_kwonly(1, 2, c=3), (1, 2, 3, None))
        self.assertEqual(ac_tester.keywords_opt_kwonly(a=1, c=3), (1, None, 3, None))
        self.assertEqual(ac_tester.keywords_opt_kwonly(a=1, b=2, c=3, d=4), (1, 2, 3, 4))

    def test_keywords_kwonly_opt(self):
        self.assertEqual(ac_tester.keywords_kwonly_opt(1), (1, None, None))
        with self.assertRaises(TypeError):
            ac_tester.keywords_kwonly_opt(1, 2)
        self.assertEqual(ac_tester.keywords_kwonly_opt(1, b=2), (1, 2, None))
        self.assertEqual(ac_tester.keywords_kwonly_opt(a=1, c=3), (1, None, 3))
        self.assertEqual(ac_tester.keywords_kwonly_opt(a=1, b=2, c=3), (1, 2, 3))

    def test_posonly_keywords(self):
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords(1)
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords(a=1, b=2)
        self.assertEqual(ac_tester.posonly_keywords(1, 2), (1, 2))
        self.assertEqual(ac_tester.posonly_keywords(1, b=2), (1, 2))

    def test_posonly_kwonly(self):
        with self.assertRaises(TypeError):
            ac_tester.posonly_kwonly(1)
        with self.assertRaises(TypeError):
            ac_tester.posonly_kwonly(1, 2)
        with self.assertRaises(TypeError):
            ac_tester.posonly_kwonly(a=1, b=2)
        self.assertEqual(ac_tester.posonly_kwonly(1, b=2), (1, 2))

    def test_posonly_keywords_kwonly(self):
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_kwonly(1)
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_kwonly(1, 2, 3)
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_kwonly(a=1, b=2, c=3)
        self.assertEqual(ac_tester.posonly_keywords_kwonly(1, 2, c=3), (1, 2, 3))
        self.assertEqual(ac_tester.posonly_keywords_kwonly(1, b=2, c=3), (1, 2, 3))

    def test_posonly_keywords_opt(self):
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_opt(1)
        self.assertEqual(ac_tester.posonly_keywords_opt(1, 2), (1, 2, None, None))
        self.assertEqual(ac_tester.posonly_keywords_opt(1, 2, 3), (1, 2, 3, None))
        self.assertEqual(ac_tester.posonly_keywords_opt(1, 2, 3, 4), (1, 2, 3, 4))
        self.assertEqual(ac_tester.posonly_keywords_opt(1, b=2), (1, 2, None, None))
        self.assertEqual(ac_tester.posonly_keywords_opt(1, 2, c=3), (1, 2, 3, None))
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_opt(a=1, b=2, c=3, d=4)
        self.assertEqual(ac_tester.posonly_keywords_opt(1, b=2, c=3, d=4), (1, 2, 3, 4))

    def test_posonly_opt_keywords_opt(self):
        self.assertEqual(ac_tester.posonly_opt_keywords_opt(1), (1, None, None, None))
        self.assertEqual(ac_tester.posonly_opt_keywords_opt(1, 2), (1, 2, None, None))
        self.assertEqual(ac_tester.posonly_opt_keywords_opt(1, 2, 3), (1, 2, 3, None))
        self.assertEqual(ac_tester.posonly_opt_keywords_opt(1, 2, 3, 4), (1, 2, 3, 4))
        with self.assertRaises(TypeError):
            ac_tester.posonly_opt_keywords_opt(1, b=2)
        self.assertEqual(ac_tester.posonly_opt_keywords_opt(1, 2, c=3), (1, 2, 3, None))
        self.assertEqual(ac_tester.posonly_opt_keywords_opt(1, 2, c=3, d=4), (1, 2, 3, 4))
        with self.assertRaises(TypeError):
            ac_tester.posonly_opt_keywords_opt(a=1, b=2, c=3, d=4)

    def test_posonly_kwonly_opt(self):
        with self.assertRaises(TypeError):
            ac_tester.posonly_kwonly_opt(1)
        with self.assertRaises(TypeError):
            ac_tester.posonly_kwonly_opt(1, 2)
        self.assertEqual(ac_tester.posonly_kwonly_opt(1, b=2), (1, 2, None, None))
        self.assertEqual(ac_tester.posonly_kwonly_opt(1, b=2, c=3), (1, 2, 3, None))
        self.assertEqual(ac_tester.posonly_kwonly_opt(1, b=2, c=3, d=4), (1, 2, 3, 4))
        with self.assertRaises(TypeError):
            ac_tester.posonly_kwonly_opt(a=1, b=2, c=3, d=4)

    def test_posonly_opt_kwonly_opt(self):
        self.assertEqual(ac_tester.posonly_opt_kwonly_opt(1), (1, None, None, None))
        self.assertEqual(ac_tester.posonly_opt_kwonly_opt(1, 2), (1, 2, None, None))
        with self.assertRaises(TypeError):
            ac_tester.posonly_opt_kwonly_opt(1, 2, 3)
        with self.assertRaises(TypeError):
            ac_tester.posonly_opt_kwonly_opt(1, b=2)
        self.assertEqual(ac_tester.posonly_opt_kwonly_opt(1, 2, c=3), (1, 2, 3, None))
        self.assertEqual(ac_tester.posonly_opt_kwonly_opt(1, 2, c=3, d=4), (1, 2, 3, 4))

    def test_posonly_keywords_kwonly_opt(self):
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_kwonly_opt(1)
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_kwonly_opt(1, 2)
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_kwonly_opt(1, b=2)
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_kwonly_opt(1, 2, 3)
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_kwonly_opt(a=1, b=2, c=3)
        self.assertEqual(ac_tester.posonly_keywords_kwonly_opt(1, 2, c=3), (1, 2, 3, None, None))
        self.assertEqual(ac_tester.posonly_keywords_kwonly_opt(1, b=2, c=3), (1, 2, 3, None, None))
        self.assertEqual(ac_tester.posonly_keywords_kwonly_opt(1, 2, c=3, d=4), (1, 2, 3, 4, None))
        self.assertEqual(ac_tester.posonly_keywords_kwonly_opt(1, 2, c=3, d=4, e=5), (1, 2, 3, 4, 5))

    def test_posonly_keywords_opt_kwonly_opt(self):
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_opt_kwonly_opt(1)
        self.assertEqual(ac_tester.posonly_keywords_opt_kwonly_opt(1, 2), (1, 2, None, None, None))
        self.assertEqual(ac_tester.posonly_keywords_opt_kwonly_opt(1, b=2), (1, 2, None, None, None))
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_opt_kwonly_opt(1, 2, 3, 4)
        with self.assertRaises(TypeError):
            ac_tester.posonly_keywords_opt_kwonly_opt(a=1, b=2)
        self.assertEqual(ac_tester.posonly_keywords_opt_kwonly_opt(1, 2, c=3), (1, 2, 3, None, None))
        self.assertEqual(ac_tester.posonly_keywords_opt_kwonly_opt(1, b=2, c=3), (1, 2, 3, None, None))
        self.assertEqual(ac_tester.posonly_keywords_opt_kwonly_opt(1, 2, 3, d=4), (1, 2, 3, 4, None))
        self.assertEqual(ac_tester.posonly_keywords_opt_kwonly_opt(1, 2, c=3, d=4), (1, 2, 3, 4, None))
        self.assertEqual(ac_tester.posonly_keywords_opt_kwonly_opt(1, 2, 3, d=4, e=5), (1, 2, 3, 4, 5))
        self.assertEqual(ac_tester.posonly_keywords_opt_kwonly_opt(1, 2, c=3, d=4, e=5), (1, 2, 3, 4, 5))

    def test_posonly_opt_keywords_opt_kwonly_opt(self):
        self.assertEqual(ac_tester.posonly_opt_keywords_opt_kwonly_opt(1), (1, None, None, None))
        self.assertEqual(ac_tester.posonly_opt_keywords_opt_kwonly_opt(1, 2), (1, 2, None, None))
        with self.assertRaises(TypeError):
            ac_tester.posonly_opt_keywords_opt_kwonly_opt(1, b=2)
        self.assertEqual(ac_tester.posonly_opt_keywords_opt_kwonly_opt(1, 2, 3), (1, 2, 3, None))
        self.assertEqual(ac_tester.posonly_opt_keywords_opt_kwonly_opt(1, 2, c=3), (1, 2, 3, None))
        self.assertEqual(ac_tester.posonly_opt_keywords_opt_kwonly_opt(1, 2, 3, d=4), (1, 2, 3, 4))
        self.assertEqual(ac_tester.posonly_opt_keywords_opt_kwonly_opt(1, 2, c=3, d=4), (1, 2, 3, 4))
        with self.assertRaises(TypeError):
            ac_tester.posonly_opt_keywords_opt_kwonly_opt(1, 2, 3, 4)

    def test_keyword_only_parameter(self):
        with self.assertRaises(TypeError):
            ac_tester.keyword_only_parameter()
        with self.assertRaises(TypeError):
            ac_tester.keyword_only_parameter(1)
        self.assertEqual(ac_tester.keyword_only_parameter(a=1), (1,))

    if ac_tester is not None:
        @repeat_fn(ac_tester.varpos,
                   ac_tester.varpos_array,
                   ac_tester.TestClass.varpos_no_fastcall,
                   ac_tester.TestClass.varpos_array_no_fastcall)
        def test_varpos(self, fn):
            # fn(*args)
            self.assertEqual(fn(), ())
            self.assertEqual(fn(1, 2), (1, 2))

        @repeat_fn(ac_tester.posonly_varpos,
                   ac_tester.posonly_varpos_array,
                   ac_tester.TestClass.posonly_varpos_no_fastcall,
                   ac_tester.TestClass.posonly_varpos_array_no_fastcall)
        def test_posonly_varpos(self, fn):
            # fn(a, b, /, *args)
            self.assertRaises(TypeError, fn)
            self.assertRaises(TypeError, fn, 1)
            self.assertRaises(TypeError, fn, 1, b=2)
            self.assertEqual(fn(1, 2), (1, 2, ()))
            self.assertEqual(fn(1, 2, 3, 4), (1, 2, (3, 4)))

        @repeat_fn(ac_tester.posonly_req_opt_varpos,
                   ac_tester.posonly_req_opt_varpos_array,
                   ac_tester.TestClass.posonly_req_opt_varpos_no_fastcall,
                   ac_tester.TestClass.posonly_req_opt_varpos_array_no_fastcall)
        def test_posonly_req_opt_varpos(self, fn):
            # fn(a, b=False, /, *args)
            self.assertRaises(TypeError, fn)
            self.assertRaises(TypeError, fn, a=1)
            self.assertEqual(fn(1), (1, False, ()))
            self.assertEqual(fn(1, 2), (1, 2, ()))
            self.assertEqual(fn(1, 2, 3, 4), (1, 2, (3, 4)))

        @repeat_fn(ac_tester.posonly_poskw_varpos,
                   ac_tester.posonly_poskw_varpos_array,
                   ac_tester.TestClass.posonly_poskw_varpos_no_fastcall,
                   ac_tester.TestClass.posonly_poskw_varpos_array_no_fastcall)
        def test_posonly_poskw_varpos(self, fn):
            # fn(a, /, b, *args)
            self.assertRaises(TypeError, fn)
            self.assertEqual(fn(1, 2), (1, 2, ()))
            self.assertEqual(fn(1, b=2), (1, 2, ()))
            self.assertEqual(fn(1, 2, 3, 4), (1, 2, (3, 4)))
            self.assertRaises(TypeError, fn, b=4)
            errmsg = re.escape("given by name ('b') and position (2)")
            self.assertRaisesRegex(TypeError, errmsg, fn, 1, 2, 3, b=4)

    def test_poskw_varpos(self):
        # fn(a, *args)
        fn = ac_tester.poskw_varpos
        self.assertRaises(TypeError, fn)
        self.assertRaises(TypeError, fn, 1, b=2)
        self.assertEqual(fn(a=1), (1, ()))
        errmsg = re.escape("given by name ('a') and position (1)")
        self.assertRaisesRegex(TypeError, errmsg, fn, 1, a=2)
        self.assertEqual(fn(1), (1, ()))
        self.assertEqual(fn(1, 2, 3, 4), (1, (2, 3, 4)))

    def test_poskw_varpos_kwonly_opt(self):
        # fn(a, *args, b=False)
        fn = ac_tester.poskw_varpos_kwonly_opt
        self.assertRaises(TypeError, fn)
        errmsg = re.escape("given by name ('a') and position (1)")
        self.assertRaisesRegex(TypeError, errmsg, fn, 1, a=2)
        self.assertEqual(fn(1, b=2), (1, (), True))
        self.assertEqual(fn(1, 2, 3, 4), (1, (2, 3, 4), False))
        self.assertEqual(fn(1, 2, 3, 4, b=5), (1, (2, 3, 4), True))
        self.assertEqual(fn(a=1), (1, (), False))
        self.assertEqual(fn(a=1, b=2), (1, (), True))

    def test_poskw_varpos_kwonly_opt2(self):
        # fn(a, *args, b=False, c=False)
        fn = ac_tester.poskw_varpos_kwonly_opt2
        self.assertRaises(TypeError, fn)
        errmsg = re.escape("given by name ('a') and position (1)")
        self.assertRaisesRegex(TypeError, errmsg, fn, 1, a=2)
        self.assertEqual(fn(1, b=2), (1, (), 2, False))
        self.assertEqual(fn(1, b=2, c=3), (1, (), 2, 3))
        self.assertEqual(fn(1, 2, 3), (1, (2, 3), False, False))
        self.assertEqual(fn(1, 2, 3, b=4), (1, (2, 3), 4, False))
        self.assertEqual(fn(1, 2, 3, b=4, c=5), (1, (2, 3), 4, 5))
        self.assertEqual(fn(a=1), (1, (), False, False))
        self.assertEqual(fn(a=1, b=2), (1, (), 2, False))
        self.assertEqual(fn(a=1, b=2, c=3), (1, (), 2, 3))

    def test_varpos_kwonly_opt(self):
        # fn(*args, b=False)
        fn = ac_tester.varpos_kwonly_opt
        self.assertEqual(fn(), ((), False))
        self.assertEqual(fn(b=2), ((), 2))
        self.assertEqual(fn(1, b=2), ((1, ), 2))
        self.assertEqual(fn(1, 2, 3, 4), ((1, 2, 3, 4), False))
        self.assertEqual(fn(1, 2, 3, 4, b=5), ((1, 2, 3, 4), 5))

    def test_varpos_kwonly_req_opt(self):
        fn = ac_tester.varpos_kwonly_req_opt
        self.assertRaises(TypeError, fn)
        self.assertEqual(fn(a=1), ((), 1, False, False))
        self.assertEqual(fn(a=1, b=2), ((), 1, 2, False))
        self.assertEqual(fn(a=1, b=2, c=3), ((), 1, 2, 3))
        self.assertRaises(TypeError, fn, 1)
        self.assertEqual(fn(1, a=2), ((1,), 2, False, False))
        self.assertEqual(fn(1, a=2, b=3), ((1,), 2, 3, False))
        self.assertEqual(fn(1, a=2, b=3, c=4), ((1,), 2, 3, 4))

    def test_only_group(self):
        # fn([a])
        fn = ac_tester.only_group
        self.assertEqual(fn(), (False, None))
        self.assertEqual(fn(1), (True, 1))
        self.assertRaises(TypeError, fn, 1, 2)
        self.assertRaises(TypeError, fn, a=1)

    def test_group_and_opt(self):
        # fn([a, b,] c=None)
        fn = ac_tester.group_and_opt
        self.assertEqual(fn(), (False, None, None, None))
        self.assertEqual(fn(1), (False, None, None, 1))
        self.assertEqual(fn(1, 2), (True, 1, 2, None))
        self.assertEqual(fn(1, 2, 3), (True, 1, 2, 3))
        self.assertRaises(TypeError, fn, 1, 2, 3, 4)
        self.assertRaises(TypeError, fn, c=1)

    def test_group_and_two_opt(self):
        # fn([a, b, c,] d=None, e=None)
        fn = ac_tester.group_and_two_opt
        self.assertEqual(fn(), (False, None, None, None, None, None))
        self.assertEqual(fn(1), (False, None, None, None, 1, None))
        self.assertEqual(fn(1, 2), (False, None, None, None, 1, 2))
        self.assertEqual(fn(1, 2, 3), (True, 1, 2, 3, None, None))
        self.assertEqual(fn(1, 2, 3, 4), (True, 1, 2, 3, 4, None))
        self.assertEqual(fn(1, 2, 3, 4, 5), (True, 1, 2, 3, 4, 5))
        self.assertRaises(TypeError, fn, 1, 2, 3, 4, 5, 6)

    def test_two_groups_on_left(self):
        # fn([a, b,] [c,] d)
        fn = ac_tester.two_groups_on_left
        self.assertRaises(TypeError, fn)
        self.assertEqual(fn(1), (False, None, None, False, None, 1))
        self.assertEqual(fn(1, 2), (False, None, None, True, 1, 2))
        self.assertEqual(fn(1, 2, 3), (True, 1, 2, False, None, 3))
        self.assertEqual(fn(1, 2, 3, 4), (True, 1, 2, True, 3, 4))
        self.assertRaises(TypeError, fn, 1, 2, 3, 4, 5)

    def test_two_groups_on_right(self):
        # fn(a, [b,] [c, d])
        fn = ac_tester.two_groups_on_right
        self.assertRaises(TypeError, fn)
        self.assertEqual(fn(1), (1, False, None, False, None, None))
        self.assertEqual(fn(1, 2), (1, True, 2, False, None, None))
        self.assertEqual(fn(1, 2, 3), (1, False, None, True, 2, 3))
        self.assertEqual(fn(1, 2, 3, 4), (1, True, 2, True, 3, 4))
        self.assertRaises(TypeError, fn, 1, 2, 3, 4, 5)

    def test_gh_32092_oob(self):
        ac_tester.gh_32092_oob(1, 2, 3, 4, kw1=5, kw2=6)

    def test_gh_32092_kw_pass(self):
        ac_tester.gh_32092_kw_pass(1, 2, 3)

    def test_gh_99233_refcount(self):
        arg = '*A unique string is not referenced by anywhere else.*'
        arg_refcount_origin = sys.getrefcount(arg)
        ac_tester.gh_99233_refcount(arg)
        arg_refcount_after = sys.getrefcount(arg)
        self.assertEqual(arg_refcount_origin, arg_refcount_after)

    def test_gh_99240_double_free(self):
        err = re.escape(
            "gh_99240_double_free() argument 2 must be encoded string "
            "without null bytes, not str"
        )
        with self.assertRaisesRegex(TypeError, err):
            ac_tester.gh_99240_double_free('a', '\0b')

    def test_null_or_tuple_for_varargs(self):
        # fn(name, *constraints, covariant=False)
        fn = ac_tester.null_or_tuple_for_varargs
        # All of these should not crash:
        self.assertEqual(fn('a'), ('a', (), False))
        self.assertEqual(fn('a', 1, 2, 3, covariant=True), ('a', (1, 2, 3), True))
        self.assertEqual(fn(name='a'), ('a', (), False))
        self.assertEqual(fn(name='a', covariant=True), ('a', (), True))
        self.assertEqual(fn(covariant=True, name='a'), ('a', (), True))

        self.assertRaises(TypeError, fn, covariant=True)
        errmsg = re.escape("given by name ('name') and position (1)")
        self.assertRaisesRegex(TypeError, errmsg, fn, 1, name='a')
        self.assertRaisesRegex(TypeError, errmsg, fn, 1, 2, 3, name='a', covariant=True)
        self.assertRaisesRegex(TypeError, errmsg, fn, 1, 2, 3, covariant=True, name='a')

    def test_cloned_func_exception_message(self):
        incorrect_arg = -1  # f1() and f2() accept a single str
        with self.assertRaisesRegex(TypeError, "clone_f1"):
            ac_tester.clone_f1(incorrect_arg)
        with self.assertRaisesRegex(TypeError, "clone_f2"):
            ac_tester.clone_f2(incorrect_arg)

    def test_cloned_func_with_converter_exception_message(self):
        for name in "clone_with_conv_f1", "clone_with_conv_f2":
            with self.subTest(name=name):
                func = getattr(ac_tester, name)
                self.assertEqual(func(), name)

    def test_get_defining_class(self):
        obj = ac_tester.TestClass()
        meth = obj.get_defining_class
        self.assertIs(obj.get_defining_class(), ac_tester.TestClass)

        # 'defining_class' argument is a positional only argument
        with self.assertRaises(TypeError):
            obj.get_defining_class_arg(cls=ac_tester.TestClass)

        check = partial(self.assertRaisesRegex, TypeError, "no arguments")
        check(meth, 1)
        check(meth, a=1)

    def test_get_defining_class_capi(self):
        from _testcapi import pyobject_vectorcall
        obj = ac_tester.TestClass()
        meth = obj.get_defining_class
        pyobject_vectorcall(meth, None, None)
        pyobject_vectorcall(meth, (), None)
        pyobject_vectorcall(meth, (), ())
        pyobject_vectorcall(meth, None, ())
        self.assertIs(pyobject_vectorcall(meth, (), ()), ac_tester.TestClass)

        check = partial(self.assertRaisesRegex, TypeError, "no arguments")
        check(pyobject_vectorcall, meth, (1,), None)
        check(pyobject_vectorcall, meth, (1,), ("a",))

    def test_get_defining_class_arg(self):
        obj = ac_tester.TestClass()
        self.assertEqual(obj.get_defining_class_arg("arg"),
                         (ac_tester.TestClass, "arg"))
        self.assertEqual(obj.get_defining_class_arg(arg=123),
                         (ac_tester.TestClass, 123))

        # 'defining_class' argument is a positional only argument
        with self.assertRaises(TypeError):
            obj.get_defining_class_arg(cls=ac_tester.TestClass, arg="arg")

        # wrong number of arguments
        with self.assertRaises(TypeError):
            obj.get_defining_class_arg()
        with self.assertRaises(TypeError):
            obj.get_defining_class_arg("arg1", "arg2")

    def test_defclass_varpos(self):
        # fn(*args)
        cls = ac_tester.TestClass
        obj = cls()
        fn = obj.defclass_varpos
        self.assertEqual(fn(), (cls, ()))
        self.assertEqual(fn(1, 2), (cls, (1, 2)))
        fn = cls.defclass_varpos
        self.assertRaises(TypeError, fn)
        self.assertEqual(fn(obj), (cls, ()))
        self.assertEqual(fn(obj, 1, 2), (cls, (1, 2)))

    def test_defclass_posonly_varpos(self):
        # fn(a, b, /, *args)
        cls = ac_tester.TestClass
        obj = cls()
        fn = obj.defclass_posonly_varpos
        errmsg = 'takes at least 2 positional arguments'
        self.assertRaisesRegex(TypeError, errmsg, fn)
        self.assertRaisesRegex(TypeError, errmsg, fn, 1)
        self.assertEqual(fn(1, 2), (cls, 1, 2, ()))
        self.assertEqual(fn(1, 2, 3, 4), (cls, 1, 2, (3, 4)))
        fn = cls.defclass_posonly_varpos
        self.assertRaises(TypeError, fn)
        self.assertRaisesRegex(TypeError, errmsg, fn, obj)
        self.assertRaisesRegex(TypeError, errmsg, fn, obj, 1)
        self.assertEqual(fn(obj, 1, 2), (cls, 1, 2, ()))
        self.assertEqual(fn(obj, 1, 2, 3, 4), (cls, 1, 2, (3, 4)))

    def test_depr_star_new(self):
        cls = ac_tester.DeprStarNew
        cls()
        cls(a=None)
        self.check_depr_star("'a'", cls, None)

    def test_depr_star_new_cloned(self):
        fn = ac_tester.DeprStarNew().cloned
        fn()
        fn(a=None)
        self.check_depr_star("'a'", fn, None, name='_testclinic.DeprStarNew.cloned')

    def test_depr_star_init(self):
        cls = ac_tester.DeprStarInit
        cls()
        cls(a=None)
        self.check_depr_star("'a'", cls, None)

    def test_depr_star_init_cloned(self):
        fn = ac_tester.DeprStarInit().cloned
        fn()
        fn(a=None)
        self.check_depr_star("'a'", fn, None, name='_testclinic.DeprStarInit.cloned')

    def test_depr_star_init_noinline(self):
        cls = ac_tester.DeprStarInitNoInline
        self.assertRaises(TypeError, cls, "a")
        cls(a="a", b="b")
        cls(a="a", b="b", c="c")
        cls("a", b="b")
        cls("a", b="b", c="c")
        check = partial(self.check_depr_star, "'b' and 'c'", cls)
        check("a", "b")
        check("a", "b", "c")
        check("a", "b", c="c")
        self.assertRaises(TypeError, cls, "a", "b", "c", "d")

    def test_depr_kwd_new(self):
        cls = ac_tester.DeprKwdNew
        cls()
        cls(None)
        self.check_depr_kwd("'a'", cls, a=None)

    def test_depr_kwd_init(self):
        cls = ac_tester.DeprKwdInit
        cls()
        cls(None)
        self.check_depr_kwd("'a'", cls, a=None)

    def test_depr_kwd_init_noinline(self):
        cls = ac_tester.DeprKwdInitNoInline
        cls = ac_tester.depr_star_noinline
        self.assertRaises(TypeError, cls, "a")
        cls(a="a", b="b")
        cls(a="a", b="b", c="c")
        cls("a", b="b")
        cls("a", b="b", c="c")
        check = partial(self.check_depr_star, "'b' and 'c'", cls)
        check("a", "b")
        check("a", "b", "c")
        check("a", "b", c="c")
        self.assertRaises(TypeError, cls, "a", "b", "c", "d")

    def test_depr_star_pos0_len1(self):
        fn = ac_tester.depr_star_pos0_len1
        fn(a=None)
        self.check_depr_star("'a'", fn, "a")

    def test_depr_star_pos0_len2(self):
        fn = ac_tester.depr_star_pos0_len2
        fn(a=0, b=0)
        check = partial(self.check_depr_star, "'a' and 'b'", fn)
        check("a", b=0)
        check("a", "b")

    def test_depr_star_pos0_len3_with_kwd(self):
        fn = ac_tester.depr_star_pos0_len3_with_kwd
        fn(a=0, b=0, c=0, d=0)
        check = partial(self.check_depr_star, "'a', 'b' and 'c'", fn)
        check("a", b=0, c=0, d=0)
        check("a", "b", c=0, d=0)
        check("a", "b", "c", d=0)

    def test_depr_star_pos1_len1_opt(self):
        fn = ac_tester.depr_star_pos1_len1_opt
        fn(a=0, b=0)
        fn("a", b=0)
        fn(a=0)  # b is optional
        check = partial(self.check_depr_star, "'b'", fn)
        check("a", "b")

    def test_depr_star_pos1_len1(self):
        fn = ac_tester.depr_star_pos1_len1
        fn(a=0, b=0)
        fn("a", b=0)
        check = partial(self.check_depr_star, "'b'", fn)
        check("a", "b")

    def test_depr_star_pos1_len2_with_kwd(self):
        fn = ac_tester.depr_star_pos1_len2_with_kwd
        fn(a=0, b=0, c=0, d=0),
        fn("a", b=0, c=0, d=0),
        check = partial(self.check_depr_star, "'b' and 'c'", fn)
        check("a", "b", c=0, d=0),
        check("a", "b", "c", d=0),

    def test_depr_star_pos2_len1(self):
        fn = ac_tester.depr_star_pos2_len1
        fn(a=0, b=0, c=0)
        fn("a", b=0, c=0)
        fn("a", "b", c=0)
        check = partial(self.check_depr_star, "'c'", fn)
        check("a", "b", "c")

    def test_depr_star_pos2_len2(self):
        fn = ac_tester.depr_star_pos2_len2
        fn(a=0, b=0, c=0, d=0)
        fn("a", b=0, c=0, d=0)
        fn("a", "b", c=0, d=0)
        check = partial(self.check_depr_star, "'c' and 'd'", fn)
        check("a", "b", "c", d=0)
        check("a", "b", "c", "d")

    def test_depr_star_pos2_len2_with_kwd(self):
        fn = ac_tester.depr_star_pos2_len2_with_kwd
        fn(a=0, b=0, c=0, d=0, e=0)
        fn("a", b=0, c=0, d=0, e=0)
        fn("a", "b", c=0, d=0, e=0)
        check = partial(self.check_depr_star, "'c' and 'd'", fn)
        check("a", "b", "c", d=0, e=0)
        check("a", "b", "c", "d", e=0)

    def test_depr_star_noinline(self):
        fn = ac_tester.depr_star_noinline
        self.assertRaises(TypeError, fn, "a")
        fn(a="a", b="b")
        fn(a="a", b="b", c="c")
        fn("a", b="b")
        fn("a", b="b", c="c")
        check = partial(self.check_depr_star, "'b' and 'c'", fn)
        check("a", "b")
        check("a", "b", "c")
        check("a", "b", c="c")
        self.assertRaises(TypeError, fn, "a", "b", "c", "d")

    def test_depr_star_multi(self):
        fn = ac_tester.depr_star_multi
        self.assertRaises(TypeError, fn, "a")
        fn("a", b="b", c="c", d="d", e="e", f="f", g="g", h="h")
        errmsg = (
            "Passing more than 1 positional argument to depr_star_multi() is deprecated. "
            "Parameter 'b' will become a keyword-only parameter in Python 3.16. "
            "Parameters 'c' and 'd' will become keyword-only parameters in Python 3.15. "
            "Parameters 'e', 'f' and 'g' will become keyword-only parameters in Python 3.14.")
        check = partial(self.check_depr, re.escape(errmsg), fn)
        check("a", "b", c="c", d="d", e="e", f="f", g="g", h="h")
        check("a", "b", "c", d="d", e="e", f="f", g="g", h="h")
        check("a", "b", "c", "d", e="e", f="f", g="g", h="h")
        check("a", "b", "c", "d", "e", f="f", g="g", h="h")
        check("a", "b", "c", "d", "e", "f", g="g", h="h")
        check("a", "b", "c", "d", "e", "f", "g", h="h")
        self.assertRaises(TypeError, fn, "a", "b", "c", "d", "e", "f", "g", "h")

    def test_depr_kwd_required_1(self):
        fn = ac_tester.depr_kwd_required_1
        fn("a", "b")
        self.assertRaises(TypeError, fn, "a")
        self.assertRaises(TypeError, fn, "a", "b", "c")
        check = partial(self.check_depr_kwd, "'b'", fn)
        check("a", b="b")
        self.assertRaises(TypeError, fn, a="a", b="b")

    def test_depr_kwd_required_2(self):
        fn = ac_tester.depr_kwd_required_2
        fn("a", "b", "c")
        self.assertRaises(TypeError, fn, "a", "b")
        self.assertRaises(TypeError, fn, "a", "b", "c", "d")
        check = partial(self.check_depr_kwd, "'b' and 'c'", fn)
        check("a", "b", c="c")
        check("a", b="b", c="c")
        self.assertRaises(TypeError, fn, a="a", b="b", c="c")

    def test_depr_kwd_optional_1(self):
        fn = ac_tester.depr_kwd_optional_1
        fn("a")
        fn("a", "b")
        self.assertRaises(TypeError, fn)
        self.assertRaises(TypeError, fn, "a", "b", "c")
        check = partial(self.check_depr_kwd, "'b'", fn)
        check("a", b="b")
        self.assertRaises(TypeError, fn, a="a", b="b")

    def test_depr_kwd_optional_2(self):
        fn = ac_tester.depr_kwd_optional_2
        fn("a")
        fn("a", "b")
        fn("a", "b", "c")
        self.assertRaises(TypeError, fn)
        self.assertRaises(TypeError, fn, "a", "b", "c", "d")
        check = partial(self.check_depr_kwd, "'b' and 'c'", fn)
        check("a", b="b")
        check("a", c="c")
        check("a", b="b", c="c")
        check("a", c="c", b="b")
        check("a", "b", c="c")
        self.assertRaises(TypeError, fn, a="a", b="b", c="c")

    def test_depr_kwd_optional_3(self):
        fn = ac_tester.depr_kwd_optional_3
        fn()
        fn("a")
        fn("a", "b")
        fn("a", "b", "c")
        self.assertRaises(TypeError, fn, "a", "b", "c", "d")
        check = partial(self.check_depr_kwd, "'a', 'b' and 'c'", fn)
        check("a", "b", c="c")
        check("a", b="b")
        check(a="a")

    def test_depr_kwd_required_optional(self):
        fn = ac_tester.depr_kwd_required_optional
        fn("a", "b")
        fn("a", "b", "c")
        self.assertRaises(TypeError, fn)
        self.assertRaises(TypeError, fn, "a")
        self.assertRaises(TypeError, fn, "a", "b", "c", "d")
        check = partial(self.check_depr_kwd, "'b' and 'c'", fn)
        check("a", b="b")
        check("a", b="b", c="c")
        check("a", c="c", b="b")
        check("a", "b", c="c")
        self.assertRaises(TypeError, fn, "a", c="c")
        self.assertRaises(TypeError, fn, a="a", b="b", c="c")

    def test_depr_kwd_noinline(self):
        fn = ac_tester.depr_kwd_noinline
        fn("a", "b")
        fn("a", "b", "c")
        self.assertRaises(TypeError, fn, "a")
        check = partial(self.check_depr_kwd, "'b' and 'c'", fn)
        check("a", b="b")
        check("a", b="b", c="c")
        check("a", c="c", b="b")
        check("a", "b", c="c")
        self.assertRaises(TypeError, fn, "a", c="c")
        self.assertRaises(TypeError, fn, a="a", b="b", c="c")

    def test_depr_kwd_multi(self):
        fn = ac_tester.depr_kwd_multi
        fn("a", "b", "c", "d", "e", "f", "g", h="h")
        errmsg = (
            "Passing keyword arguments 'b', 'c', 'd', 'e', 'f' and 'g' to depr_kwd_multi() is deprecated. "
            "Parameter 'b' will become positional-only in Python 3.14. "
            "Parameters 'c' and 'd' will become positional-only in Python 3.15. "
            "Parameters 'e', 'f' and 'g' will become positional-only in Python 3.16.")
        check = partial(self.check_depr, re.escape(errmsg), fn)
        check("a", "b", "c", "d", "e", "f", g="g", h="h")
        check("a", "b", "c", "d", "e", f="f", g="g", h="h")
        check("a", "b", "c", "d", e="e", f="f", g="g", h="h")
        check("a", "b", "c", d="d", e="e", f="f", g="g", h="h")
        check("a", "b", c="c", d="d", e="e", f="f", g="g", h="h")
        check("a", b="b", c="c", d="d", e="e", f="f", g="g", h="h")
        self.assertRaises(TypeError, fn, a="a", b="b", c="c", d="d", e="e", f="f", g="g", h="h")

    def test_depr_multi(self):
        fn = ac_tester.depr_multi
        self.assertRaises(TypeError, fn, "a", "b", "c", "d", "e", "f", "g")
        errmsg = (
            "Passing more than 4 positional arguments to depr_multi() is deprecated. "
            "Parameter 'e' will become a keyword-only parameter in Python 3.15. "
            "Parameter 'f' will become a keyword-only parameter in Python 3.14.")
        check = partial(self.check_depr, re.escape(errmsg), fn)
        check("a", "b", "c", "d", "e", "f", g="g")
        check("a", "b", "c", "d", "e", f="f", g="g")
        fn("a", "b", "c", "d", e="e", f="f", g="g")
        fn("a", "b", "c", d="d", e="e", f="f", g="g")
        errmsg = (
            "Passing keyword arguments 'b' and 'c' to depr_multi() is deprecated. "
            "Parameter 'b' will become positional-only in Python 3.14. "
            "Parameter 'c' will become positional-only in Python 3.15.")
        check = partial(self.check_depr, re.escape(errmsg), fn)
        check("a", "b", c="c", d="d", e="e", f="f", g="g")
        check("a", b="b", c="c", d="d", e="e", f="f", g="g")
        self.assertRaises(TypeError, fn, a="a", b="b", c="c", d="d", e="e", f="f", g="g")

    def test_alias_pos(self):
        fn = ac_tester.alias_pos
        self.assertIsNone(fn())
        self.assertEqual(fn(1), 1)
        self.assertEqual(fn(a=1), 1)
        self.assertEqual(fn(b=1), 1)
        self.assertEqual(fn.__text_signature__, "($module, /, a=None)")
        errmsg = re.escape(
            "argument for alias_pos() given by name ('b') and position (1)")
        self.assertRaisesRegex(TypeError, errmsg, fn, 1, b=2)
        errmsg = re.escape(
            "argument for alias_pos() given by name ('b') and name ('a')")
        self.assertRaisesRegex(TypeError, errmsg, fn, a=1, b=2)

    def test_alias_kwonly(self):
        fn = ac_tester.alias_kwonly
        self.assertIsNone(fn())
        self.assertEqual(fn(a=1), 1)
        self.assertEqual(fn(b=1), 1)
        self.assertEqual(fn.__text_signature__, "($module, /, *, a=None)")
        self.assertRaises(TypeError, fn, 1)
        errmsg = re.escape(
            "argument for alias_kwonly() given by name ('b') and name ('a')")
        self.assertRaisesRegex(TypeError, errmsg, fn, a=1, b=2)

    def test_depr_alias(self):
        fn = ac_tester.depr_alias
        self.assertEqual(fn(1), 1)
        self.assertEqual(fn(a=1), 1)
        errmsg = ("Passing the argument 'b' to depr_alias() is deprecated. "
                  "Use 'a' instead. It will be removed in Python 3.14.")
        self.check_depr(re.escape(errmsg), fn, b=1)

    def test_depr_param(self):
        fn = ac_tester.depr_param
        self.assertEqual(fn(), (None, None, None, None))
        self.assertEqual(fn(1), (1, None, None, None))
        def errmsg(name):
            return re.escape(f"Passing the argument {name!r} to depr_param() "
                             f"is deprecated. "
                             f"It will be removed in Python 3.14.")
        self.check_depr(errmsg('b'), fn, 1, 2)
        self.check_depr(errmsg('d'), fn, 1, d=4)
        # Each deprecated parameter is reported on its own.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.assertEqual(fn(1, 2, 3), (1, 2, 3, None))
        self.assertEqual(len(caught), 2)
        for warning, name in zip(caught, 'bc'):
            self.assertIs(warning.category, DeprecationWarning)
            self.assertRegex(str(warning.message), errmsg(name))

    def test_lone_kwds(self):
        with self.assertRaises(TypeError):
            ac_tester.lone_kwds(1, 2)
        self.assertEqual(ac_tester.lone_kwds(), ({},))
        self.assertEqual(ac_tester.lone_kwds(y='y'), ({'y': 'y'},))
        kwds = {'y': 'y', 'z': 'z'}
        self.assertEqual(ac_tester.lone_kwds(y='y', z='z'), (kwds,))
        self.assertEqual(ac_tester.lone_kwds(**kwds), (kwds,))

    def test_kwds_with_pos_only(self):
        with self.assertRaises(TypeError):
            ac_tester.kwds_with_pos_only()
        with self.assertRaises(TypeError):
            ac_tester.kwds_with_pos_only(y='y')
        with self.assertRaises(TypeError):
            ac_tester.kwds_with_pos_only(1, y='y')
        self.assertEqual(ac_tester.kwds_with_pos_only(1, 2), (1, 2, {}))
        self.assertEqual(ac_tester.kwds_with_pos_only(1, 2, y='y'), (1, 2, {'y': 'y'}))
        kwds = {'y': 'y', 'z': 'z'}
        self.assertEqual(ac_tester.kwds_with_pos_only(1, 2, y='y', z='z'), (1, 2, kwds))
        self.assertEqual(ac_tester.kwds_with_pos_only(1, 2, **kwds), (1, 2, kwds))

    def test_kwds_with_optional_pos_only(self):
        with self.assertRaises(TypeError):
            ac_tester.kwds_with_optional_pos_only()
        with self.assertRaises(TypeError):
            ac_tester.kwds_with_optional_pos_only(y='y')
        self.assertEqual(ac_tester.kwds_with_optional_pos_only(1), (1, None, {}))
        self.assertEqual(ac_tester.kwds_with_optional_pos_only(1, 2), (1, 2, {}))
        self.assertEqual(ac_tester.kwds_with_optional_pos_only(1, y='y'),
                         (1, None, {'y': 'y'}))
        self.assertEqual(ac_tester.kwds_with_optional_pos_only(1, 2, y='y'),
                         (1, 2, {'y': 'y'}))

    def test_kwds_with_stararg(self):
        self.assertEqual(ac_tester.kwds_with_stararg(), ((), {}))
        self.assertEqual(ac_tester.kwds_with_stararg(1, 2), ((1, 2), {}))
        self.assertEqual(ac_tester.kwds_with_stararg(y='y'), ((), {'y': 'y'}))
        args = (1, 2)
        kwds = {'y': 'y', 'z': 'z'}
        self.assertEqual(ac_tester.kwds_with_stararg(1, 2, y='y', z='z'), (args, kwds))
        self.assertEqual(ac_tester.kwds_with_stararg(*args, **kwds), (args, kwds))

    def test_kwds_with_pos_only_and_stararg(self):
        with self.assertRaises(TypeError):
            ac_tester.kwds_with_pos_only_and_stararg()
        with self.assertRaises(TypeError):
            ac_tester.kwds_with_pos_only_and_stararg(y='y')
        self.assertEqual(ac_tester.kwds_with_pos_only_and_stararg(1, 2), (1, 2, (), {}))
        self.assertEqual(ac_tester.kwds_with_pos_only_and_stararg(1, 2, y='y'), (1, 2, (), {'y': 'y'}))
        args = ('lobster', 'thermidor')
        kwds = {'y': 'y', 'z': 'z'}
        self.assertEqual(ac_tester.kwds_with_pos_only_and_stararg(1, 2, 'lobster', 'thermidor', y='y', z='z'), (1, 2, args, kwds))
        self.assertEqual(ac_tester.kwds_with_pos_only_and_stararg(1, 2, *args, **kwds), (1, 2, args, kwds))


class PyspecTestBase(TestCase):
    """Clinic on foo.c, with pyspec/foo.py next to it."""
    maxDiff = None

    def setUp(self):
        save_restore_converters(self)
        self.tmp_dir = self.enterContext(os_helper.temp_dir())
        os.mkdir(os.path.join(self.tmp_dir, 'pyspec'))
        self.filename = os.path.join(self.tmp_dir, 'foo.c')
        self.spec_path = os.path.join(self.tmp_dir, 'pyspec', 'foo.py')
        self.output_path = os.path.join(self.tmp_dir, 'clinic',
                                        'foo_pyspec.c.h')

    def generate(self, spec, block):
        if spec is not None:
            with open(self.spec_path, 'w', encoding='utf-8') as f:
                f.write(dedent(spec))
        clinic = _make_clinic(filename=self.filename)
        return clinic.parse(dedent(block))

    def expect_failure(self, spec, block, errmsg):
        with self.assertRaisesRegex(ClinicError, re.escape(errmsg)):
            self.generate(spec, block)

    def expect_located_failure(self, spec, block, errmsg, lineno):
        """An error *errmsg* at line *lineno* of the spec."""
        with self.assertRaises(ClinicError) as cm:
            self.generate(spec, block)
        exc = cm.exception
        self.assertEqual((exc.filename, exc.lineno, exc.message),
                         (self.spec_path, lineno, errmsg))
        return exc


class PyspecTest(PyspecTestBase):
    """Spec functions with a body: their C is generated."""

    BLOCK = """
        /*[clinic input]
        output preset block
        class bytes "PyObject *" "&PyBytes_Type"
        bytes.__new__ as foo_new
        [clinic start generated code]*/
    """

    SPEC = """
        class bytes:
            def __new__(cls, a: object, b: str = NULL, /,
                        c: str = NULL):
                return a
    """

    def vectorcall(self, generated):
        start = generated.index("foo_vectorcall(PyObject")
        return generated[start:generated.index("\n}", start)]

    def test_no_spec(self):
        block = """
            /*[clinic input]
            output preset block
            class bytes "PyObject *" "&PyBytes_Type"
            @classmethod
            bytes.__new__ as foo_new
                a: object
                b: str = NULL
                /
                c: str = NULL
            [clinic start generated code]*/
        """
        generated = self.generate(None, block)
        self.assertNotIn("foo_vectorcall", generated)
        self.assertIn("static PyObject *\nfoo_new_impl(PyTypeObject *type, "
                      "PyObject *a, const char *b, const char *c)\n"
                      "/*[clinic end generated code:", generated)
        self.assertFalse(os.path.exists(self.output_path))

    def test_stub_method(self):
        spec = self.SPEC.replace("return a", "...")
        generated = self.generate(spec, self.BLOCK)
        self.assertNotIn("foo_vectorcall", generated)
        self.assertIn("static PyObject *\nfoo_new_impl(PyTypeObject *type, "
                      "PyObject *a, const char *b, const char *c)\n"
                      "/*[clinic end generated code:", generated)
        self.assertFalse(os.path.exists(self.output_path))

    def test_generated(self):
        generated = self.generate(self.SPEC, self.BLOCK)
        # The spec provides the impl: it is declared, not started in the
        # block.
        self.assertIn("static PyObject *\nfoo_new_impl(PyTypeObject *type, "
                      "PyObject *a, const char *b, const char *c);",
                      generated)
        self.assertNotIn("const char *c)\n/*[clinic end generated code:",
                         generated)
        # One declaration per allowed call count, typed by the converters.
        self.assertNotIn("foo_new_nargs0", generated)
        for prototype in (
            "static PyObject *\nfoo_new_nargs1(PyObject *a);",
            "static PyObject *\nfoo_new_nargs2(PyObject *a, const char *b);",
            "static PyObject *\n"
            "foo_new_nargs3(PyObject *a, const char *b, const char *c);",
        ):
            self.assertIn(prototype, generated)
        # A vectorcall without @vectorcall; each call count leaves the
        # inline parsing with what it converted.
        vectorcall = self.vectorcall(generated)
        self.assertIn("    if (nargs < 2) {\n"
                      "        return_value = foo_new_nargs1(a);\n"
                      "        goto exit;\n"
                      "    }\n", vectorcall)
        self.assertIn("    if (nargs < 3) {\n"
                      "        return_value = foo_new_nargs2(a, b);\n"
                      "        goto exit;\n"
                      "    }\n", vectorcall)
        self.assertIn("return_value = foo_new_nargs3(a, b, c);", vectorcall)
        self.assertNotIn("foo_new_impl(", vectorcall)
        self.assertNotIn("skip_optional", vectorcall)
        # Keyword calls still go through the helper and the impl.
        self.assertIn("return foo_new_helper(", vectorcall)

    def test_generated_file(self):
        self.generate(self.SPEC, self.BLOCK)
        with open(self.output_path, encoding='utf-8') as f:
            output = f.read()
        self.assertStartsWith(output, "/*[pyspec]\nGenerated by Argument "
                              f"Clinic from {os.path.basename(self.tmp_dir)}"
                              "/pyspec/foo.py.\n")
        self.assertIn("static PyObject *\nfoo_new_impl(PyTypeObject *cls, "
                      "PyObject *a, const char *b, const char *c)\n{\n",
                      output)
        for nargs in (1, 2, 3):
            self.assertIn(f"static PyObject *\nfoo_new_nargs{nargs}(",
                          output)
        self.assertNotIn("foo_new_nargs0", output)

    def test_top_level_function(self):
        spec = dedent(self.SPEC) + dedent("""
            def PyFoo_Get(x: object):
                return x

            def PyFoo_Stub(x: object) -> Unknown[int]:
                ...

            def PyFoo_Documented(x: object):
                "Only a docstring: a stub too."
        """)
        self.generate(spec, self.BLOCK)
        with open(self.output_path, encoding='utf-8') as f:
            output = f.read()
        self.assertIn("\nPyObject *\nPyFoo_Get(PyObject *x)\n{\n"
                      "    return Py_NewRef(x);\n}\n", output)
        self.assertNotIn("PyFoo_Stub", output)
        self.assertNotIn("PyFoo_Documented", output)

    def test_method_and_class_method(self):
        # A method or class method with a body: clinic's parsing code
        # calls NAME_impl(), generated from the spec with clinic's self
        # (or class) parameter first.
        block = """
            /*[clinic input]
            output preset block
            class bytes "PyBytesObject *" "&PyBytes_Type"
            bytes.__bytes__
            [clinic start generated code]*/

            /*[clinic input]
            bytes.fromhex
            [clinic start generated code]*/
        """
        spec = """
            class bytes:
                def __bytes__(self):
                    "Doc."
                    if type(self) is bytes:
                        return self
                    return bytes_copy(self)

                @classmethod
                def fromhex(cls, string: object, /):
                    "Doc."
                    result = _PyBytes_FromHex(string, False)
                    if cls is not bytes:
                        return cls(result)
                    return result

            @native
            def bytes_copy(b: object):
                return exact(bytes, bytes(b))

            @native
            def _PyBytes_FromHex(string: object, use_bytearray: int):
                calls(string, "__buffer__")
                return exact(bytes, bytes.fromhex(string))
        """
        generated = self.generate(spec, block)
        self.assertIn("static PyObject *\n"
                      "bytes___bytes___impl(PyBytesObject *self);", generated)
        self.assertIn("return bytes___bytes___impl((PyBytesObject *)self);",
                      generated)
        self.assertIn("static PyObject *\n"
                      "bytes_fromhex_impl(PyTypeObject *type, "
                      "PyObject *string);", generated)
        self.assertNotIn("foo_vectorcall", generated)
        with open(self.output_path, encoding='utf-8') as f:
            output = f.read()
        self.assertIn("static PyObject *\n"
                      "bytes___bytes___impl(PyBytesObject *self)\n{\n"
                      "    if (PyBytes_CheckExact(self)) {\n"
                      "        return Py_NewRef(self);\n"
                      "    }\n", output)
        self.assertIn("static PyObject *\n"
                      "bytes_fromhex_impl(PyTypeObject *cls, "
                      "PyObject *string)\n{\n", output)
        self.assertIn("PyObject_CallOneArg((PyObject *)cls, result);",
                      output)
        # The C functions are called by name, with C arguments.
        self.assertIn("return bytes_copy((PyObject *)self);", output)
        self.assertIn("result = _PyBytes_FromHex(string, 0);\n"
                      "    if (result == NULL) {", output)

    def test_body_in_ifdef(self):
        # The generated impl is under the condition of its block, as the
        # code clinic generates for the block is.
        block = """
            /*[clinic input]
            output preset block
            class bytes "PyBytesObject *" "&PyBytes_Type"
            [clinic start generated code]*/
            #if defined(CONDITION)
            /*[clinic input]
            bytes.meth
            [clinic start generated code]*/
            #endif
        """
        spec = """
            class bytes:
                def meth(self, a: object, /):
                    "Doc."
                    return a
        """
        self.generate(spec, block)
        with open(self.output_path, encoding='utf-8') as f:
            output = f.read()
        self.assertIn("#if defined(CONDITION)\n"
                      "static PyObject *bytes_meth_impl(PyBytesObject *self, "
                      "PyObject *a);\n"
                      "#endif /* defined(CONDITION) */\n", output)
        self.assertIn("#if defined(CONDITION)\n"
                      "static PyObject *\n"
                      "bytes_meth_impl(PyBytesObject *self, PyObject *a)\n"
                      "{\n"
                      "    return Py_NewRef(a);\n"
                      "}\n"
                      "#endif /* defined(CONDITION) */\n", output)

    def test_native(self):
        # A @native function: C by hand, never generated.  Its
        # annotations are C types; the error check of a call comes from
        # what its Python reference can do.
        spec = dedent("""
            class bytes:
                def __new__(cls, a: object, /):
                    if a is NULL:
                        raise PyErr_BadInternalCall()
                    n = size_of(a)
                    if at_most(n, 3):
                        return pair(a, "__name__")
                    return a

            @native
            def PyErr_BadInternalCall() -> None:
                raise SystemError("bad argument")

            @native
            def size_of(x: object) -> Py_ssize_t:
                calls(x, "__len__")
                return len(x)

            @native
            def at_most(n: Py_ssize_t, m: 'long') -> int:
                return n <= m

            @native
            def pair(x: object, name: object):
                if x is NULL:
                    return NULL
                return unknown((x, name))
        """)
        self.generate(spec, self.BLOCK)
        with open(self.output_path, encoding='utf-8') as f:
            output = f.read()
        for name in ('size_of', 'at_most', 'pair', 'PyErr_BadInternalCall'):
            self.assertNotIn(f'\n{name}(', output)
        self.assertIn("n = size_of(a);\n"
                      "    if (n == -1 && PyErr_Occurred()) {", output)
        # Cannot fail: no check.
        self.assertIn("if (at_most(n, 3)) {", output)
        # pair() returns NULL (absent) only for NULL, and a is not NULL
        # here: the result is a new reference or NULL with an exception.
        self.assertIn("return pair(a, &_Py_ID(__name__));", output)
        # The facts of the call table come from the references too.
        self.assertIn("/* bytes(x): result type not known exactly; may run "
                      "Python code */", output)
        self.check_error_native()

    def check_error_native(self):
        spec = dedent(self.SPEC) + dedent("""
            @native
            def f(x: object):
                ...
        """)
        self.expect_failure(spec, self.BLOCK, "f: the body of a "
                            "@native function is its Python "
                            "reference")

    def test_missing_block(self):
        # Every clinic function of a spec class declared in the C file has
        # a one-line block above its impl, where clinic writes the head.
        block = self.BLOCK.replace("bytes.__new__ as foo_new",
                                   "bytes.__bytes__")
        spec = """
            class bytes:
                def __new__(cls, a: object):
                    return a

                def __bytes__(self):
                    ...
        """
        with self.assertRaises(ClinicError) as cm:
            self.generate(spec, block)
        self.assertEqual(cm.exception.message,
                         f"bytes.__new__ has no clinic block in "
                         f"{self.filename}; put this block above its impl:\n"
                         "/*[clinic input]\nbytes.__new__\n"
                         "[clinic start generated code]*/")
        self.assertEqual(cm.exception.filename, self.spec_path)
        self.assertEqual(cm.exception.lineno, 3)
        # Classes the C file does not declare are not generated.
        self.generate(spec.replace("class bytes", "class bytearray")
                      .replace("return a", "..."), block)

    def test_nothing_written_on_error(self):
        # An error in the last stage (the emitter) leaves every generated
        # file as it was: clinic writes all or nothing.
        block = """
            /*[clinic input]
            class bytes "PyObject *" "&PyBytes_Type"
            bytes.__new__ as foo_new
            [clinic start generated code]*/
        """
        spec = self.SPEC.replace("return a", "return len(a) == 0")
        with self.assertRaises(ClinicError) as cm:
            self.generate(spec, block)
        # Constructs outside the lowered subset point at the list of
        # what is lowered.
        self.assertStartsWith(cm.exception.message,
                              "bytes.__new__(): return of len(a) == 0 is "
                              "expressible, but not lowered to C yet; see "
                              '"The lowered subset" in '
                              "Objects/pyspec/README.rst")
        self.assertEqual((cm.exception.filename, cm.exception.lineno),
                         (self.spec_path, 5))
        self.assertFalse(os.path.exists(os.path.join(self.tmp_dir, 'clinic',
                                                     'foo.c.h')))
        self.assertFalse(os.path.exists(self.output_path))
        # Once fixed, both are written.
        self.generate(self.SPEC, block)
        self.assertTrue(os.path.exists(os.path.join(self.tmp_dir, 'clinic',
                                                    'foo.c.h')))
        self.assertTrue(os.path.exists(self.output_path))

    def test_not_new(self):
        block = self.BLOCK.replace("bytes.__new__ as foo_new",
                                   "bytes.__init__ as foo_init")
        spec = """
            class bytes:
                def __init__(self, a: object, /):
                    return a
        """
        self.expect_failure(spec, block, "bytes.__init__(): __init__ (an "
                            "int-returning initproc) is expressible, but "
                            "not lowered to C yet")

    def test_no_type_object(self):
        block = self.BLOCK.replace('"&PyBytes_Type"', '""')
        self.expect_failure(self.SPEC, block,
                            "requires the type object of 'bytes'")

    def test_wrong_type(self):
        block = (self.BLOCK.replace("class bytes", "class str")
                 .replace("bytes.__new__", "str.__new__"))
        spec = self.SPEC.replace("class bytes", "class str")
        self.expect_failure(spec, block, "str is &PyUnicode_Type, 'str' is "
                            "&PyBytes_Type")

    def test_unknown_type(self):
        block = (self.BLOCK.replace("class bytes", "class spam")
                 .replace("bytes.__new__", "spam.__new__"))
        spec = self.SPEC.replace("class bytes", "class spam")
        self.expect_failure(spec, block, "unknown type 'spam'")

    def test_keyword_only(self):
        spec = self.SPEC.replace("/,", "*,")
        self.expect_failure(spec, self.BLOCK, "keyword-only parameter "
                            "'c' is expressible, but not lowered")

    def test_bad_annotation(self):
        spec = self.SPEC.replace("a: object", "a: int")
        self.expect_failure(spec, self.BLOCK, "parameter 'a' with "
                            "converter int (lowered: ['object', 'str']) is "
                            "expressible, but not lowered")

    def test_bad_default(self):
        spec = self.SPEC.replace("c: str = NULL", "c: object = None")
        self.expect_failure(spec, self.BLOCK, "default None of parameter "
                            "'c' (lowered: NULL) is expressible, but not "
                            "lowered")


class PyspecStubTest(PyspecTestBase):
    """A one-line clinic block takes the rest of its input from the spec."""

    CLASS = """
        /*[clinic input]
        output preset block
        class bytes "PyBytesObject *" "&PyBytes_Type"
        [clinic start generated code]*/
    """

    def block(self, text):
        return (dedent(self.CLASS) + "/*[clinic input]\n" + dedent(text)
                + "[clinic start generated code]*/\n")

    @staticmethod
    def output(generated):
        """The generated code, without the clinic input."""
        generated = re.sub(r"/\*\[clinic input\]\n.*?"
                           r"\[clinic start generated code\]\*/", "",
                           generated, flags=re.DOTALL)
        return re.sub(r" input=\w+\]", "]", generated)

    def check(self, spec, stub, block):
        """*stub* with *spec* generates what the full *block* does."""
        os_helper.unlink(self.spec_path)
        expected = self.output(self.generate(None, self.block(block)))
        actual = self.output(self.generate(spec, self.block(stub)))
        self.assertEqual(actual, expected)
        return actual

    def test_parameters_and_docstring(self):
        spec = """
            class bytes:
                @critical_section
                def meth(self, a: object, /, b: int(c_param='bb') = 0, *,
                         c: str(accept={str, NoneType}) = None):
                    '''Summary line.

                      a
                        Doc of a,
                        on two lines.
                      c
                        Doc of c.

                    Rest of the docstring.
                      indented.
                    '''
                    ...
        """
        output = self.check(spec, """
            bytes.meth as bytes_m
        """, """
            @critical_section
            bytes.meth as bytes_m
                a: object
                    Doc of a,
                    on two lines.
                /
                b as bb: int = 0
                *
                c: str(accept={str, NoneType}) = None
                    Doc of c.

            Summary line.

            Rest of the docstring.
              indented.
        """)
        self.assertIn('"meth($self, a, /, b=0, *, c=None)\\n"', output)
        self.assertIn('"  a\\n"\n"    Doc of a,\\n"', output)
        self.assertIn('bytes_m_impl(PyBytesObject *self, PyObject *a, '
                      'int bb, const char *c)', output)

    def test_parameter_docs_only(self):
        self.check("""
            class bytes:
                def meth(self, a: object):
                    '''Summary line.

                      a
                        Doc of a.
                    '''
                    ...
        """, "bytes.meth\n", """
            bytes.meth
                a: object
                    Doc of a.

            Summary line.
        """)

    def test_no_parameters(self):
        self.check("""
            class bytes:
                def meth(self):
                    '''Summary line.'''
        """, "bytes.meth\n", """
            bytes.meth

            Summary line.
        """)

    def test_class_and_static_methods(self):
        # Each spec has only the method under test: each spec method needs
        # a block.
        self.check("""
            class bytes:
                @classmethod
                def cmeth(cls, a: object, /):
                    ...
        """, "bytes.cmeth\n", """
            @classmethod
            bytes.cmeth
                a: object
                /
        """)
        self.check("""
            class bytes:
                @staticmethod
                def smeth(a: object, b: object, /):
                    ...
        """, "bytes.smeth\n", """
            @staticmethod
            bytes.smeth
                a: object
                b: object
                /
        """)

    def test_new(self):
        self.check("""
            class bytes:
                def __new__(cls, a: object(c_param='x') = NULL):
                    ...
        """, "bytes.__new__ as bytes_new\n", """
            @classmethod
            bytes.__new__ as bytes_new
                a as x: object = NULL
        """)

    def test_explicit_self(self):
        self.check("""
            class bytes:
                def meth(self: self(type="PyObject *"), a: object, /):
                    ...
        """, "bytes.meth\n", """
            bytes.meth
                self: self(type="PyObject *")
                a: object
                /
        """)

    def test_return_converter(self):
        self.check("""
            class bytes:
                def meth(self, /) -> Py_ssize_t:
                    ...
        """, "bytes.meth\n", """
            bytes.meth -> Py_ssize_t
        """)

    def test_same_signature_as_clone(self):
        # Python has no clones: a method with the signature of another is
        # a full def, and clinic generates what it does for a clone.
        spec = """
            class bytes:
                def meth(self, a: object = None, /):
                    '''Summary.

                      a
                        Doc of a.
                    '''
                    ...

                def other(self, a: object = None, /):
                    '''Other summary.

                      a
                        Doc of a.

                    More.
                    '''
                    ...
        """
        output = self.check(spec, """
            bytes.meth
            [clinic start generated code]*/
            /*[clinic input]
            bytes.other as bytes_o
        """, """
            bytes.meth
                a: object = None
                    Doc of a.
                /

            Summary.
            [clinic start generated code]*/
            /*[clinic input]
            bytes.other as bytes_o = bytes.meth

            Other summary.

            More.
        """)
        self.assertIn('"other($self, a=None, /)\\n"\n"--\\n"\n"\\n"\n'
                      '"Other summary.\\n"\n"\\n"\n"  a\\n"', output)

    def test_class_not_in_spec(self):
        # The block is a complete clinic function without parameters.
        spec = """
            class bytearray:
                def meth(self, a: object):
                    ...
        """
        self.check(spec, "bytes.meth\n", "bytes.meth\n")

    def test_missing_method(self):
        spec = """
            class bytes:
                def meth(self, a: object):
                    ...
        """
        self.expect_failure(spec, self.block("bytes.nope\n"),
                            f"'bytes.nope' has no parameters or docstring, "
                            f"and class bytes in {self.spec_path} has no "
                            "method 'nope' to take them from")

    def test_declared_twice(self):
        spec = """
            class bytes:
                def meth(self, a: object):
                    ...
        """
        self.expect_failure(spec, self.block("bytes.meth\n    a: object\n"),
                            f"'bytes.meth' is declared both here and in "
                            f"{self.spec_path}; a function whose signature "
                            "depends on #if keeps its clinic input here, "
                            "and is only 'def meth(self): ...' in the spec")

    # Conditional compilation: as with plain clinic, the condition of a
    # function is where its block is in the C file.

    IFDEF = """
        /*[clinic input]
        output everything block
        output methoddef_ifndef buffer
        [clinic start generated code]*/
        #ifdef CONDITION
        /*[clinic input]
        {}
        [clinic start generated code]*/
        #endif
        /*[clinic input]
        dump buffer
        [clinic start generated code]*/
    """

    def test_stub_in_ifdef(self):
        spec = """
            class bytes:
                def meth(self, a: object, /):
                    "Doc."
                    ...
        """
        full = "bytes.meth\n    a: object\n    /\n\nDoc."
        os_helper.unlink(self.spec_path)
        expected = self.output(self.generate(
            None, dedent(self.CLASS) + dedent(self.IFDEF).format(full)))
        actual = self.output(self.generate(
            spec, dedent(self.CLASS) + dedent(self.IFDEF).format("bytes.meth")))
        self.assertEqual(actual, expected)
        self.assertIn("#if defined(CONDITION)\n", actual)
        self.assertIn("#endif /* defined(CONDITION) */", actual)
        # The METHODDEF fallback: a method table lists it unconditionally.
        self.assertIn("#ifndef BYTES_METH_METHODDEF\n"
                      "    #define BYTES_METH_METHODDEF\n"
                      "#endif /* !defined(BYTES_METH_METHODDEF) */", actual)

    def test_mixed_file(self):
        # A signature that depends on #if keeps its full blocks, and is
        # only ``def other(self): ...`` in the spec (its place in the
        # class), or not in the spec; the other methods are one-line
        # blocks.
        spec = """
            class bytes:
                def meth(self, a: object, /):
                    ...

                def other(self):
                    ...
        """
        generated = self.generate(spec, dedent(self.CLASS) + dedent("""
            /*[clinic input]
            bytes.meth
            [clinic start generated code]*/
            #ifdef CONDITION
            /*[clinic input]
            bytes.other
                a: object
                /
            [clinic start generated code]*/
            #else
            /*[clinic input]
            bytes.other

            Doc.
            [clinic start generated code]*/
            #endif
        """))
        self.assertIn("bytes_meth_impl(PyBytesObject *self, PyObject *a)",
                      generated)
        self.assertIn("bytes_other_impl(PyBytesObject *self, PyObject *a)",
                      generated)
        self.assertIn("bytes_other_impl(PyBytesObject *self)", generated)

    def test_python_decorator_in_block(self):
        spec = """
            class bytes:
                @classmethod
                def meth(cls, a: object):
                    ...
        """
        self.expect_failure(spec, self.block("@classmethod\nbytes.meth\n"),
                            "'bytes.meth': @classmethod of a spec method "
                            f"is written in {self.spec_path}")

    def test_clinic_decorator_in_block(self):
        spec = """
            class bytes:
                def meth(self, a: object):
                    ...
        """
        self.expect_failure(spec, self.block("@critical_section\n"
                                             "bytes.meth\n"),
                            "'bytes.meth': @critical_section of a spec "
                            f"method is written in {self.spec_path}")

    # Any clinic decorator is written on the spec method as a Python
    # decorator with the same name and arguments.

    def test_clinic_decorators(self):
        long_summary = "Summary " + "x" * 80
        spec = f"""
            class bytes:
                @permit_long_summary
                @critical_section
                @text_signature('($self, a[, b], /)')
                def meth(self, a: object, b: object = NULL, /):
                    '''{long_summary}'''
                    ...
        """
        output = self.check(spec, "bytes.meth\n", f"""
            @permit_long_summary
            @critical_section
            @text_signature "($self, a[, b], /)"
            bytes.meth
                a: object
                b: object = NULL
                /

            {long_summary}
        """)
        self.assertIn('"meth($self, a[, b], /)\\n"', output)
        self.assertIn('Py_BEGIN_CRITICAL_SECTION(self);', output)
        spec = """
            class bytes:
                @vectorcall
                def __init__(self, a: object, /):
                    ...
        """
        output = self.check(spec, "bytes.__init__\n", """
            @vectorcall
            bytes.__init__
                a: object
                /
        """)
        self.assertIn('bytes_vectorcall(PyObject *type', output)

    def test_clinic_decorator_arguments(self):
        # Arguments are words of the clinic line, quoted as needed.
        spec = """
            class bytes:
                @critical_section('self', 'a')
                @disable('fastcall')
                def meth(self, a: object, /):
                    ...
        """
        self.check(spec, "bytes.meth\n", """
            @critical_section self a
            @disable fastcall
            bytes.meth
                a: object
                /
        """)

    def test_no_clones(self):
        for clone in ("other = meth", "other = permit_long_summary(meth)"):
            spec = f"""
                class bytes:
                    def meth(self, a: object = None, /):
                        '''Summary.'''
                        ...

                    {clone}
            """
            with self.subTest(clone=clone):
                self.expect_failure(spec, self.block("bytes.meth\n"),
                                    "Python has no clones: write other as "
                                    "a full def")

    def test_unneeded_permit_long_summary(self):
        # The warning points at the decorator in the spec.
        spec = """
            class bytes:
                @permit_long_summary
                def meth(self, /):
                    '''Summary.'''
                    ...

                @permit_long_summary
                def other(self, /):
                    '''Other.'''
                    ...
        """
        with support.captured_stdout() as stdout:
            self.generate(spec, self.block(
                "bytes.meth\n"
                "[clinic start generated code]*/\n"
                "/*[clinic input]\n"
                "bytes.other\n"))
        self.assertIn(f"{self.spec_path}:3: warning: Remove the "
                      "@permit_long_summary decorator from 'bytes.meth'!",
                      stdout.getvalue())
        self.assertIn(f"{self.spec_path}:8: warning: Remove the "
                      "@permit_long_summary decorator from 'bytes.other'!",
                      stdout.getvalue())

    def test_unknown_clinic_decorator(self):
        spec = """
            class bytes:
                @nosuchdecorator
                def meth(self, a: object):
                    ...
        """
        # Errors in the input taken from the spec are reported at the line
        # of the spec it comes from.
        self.expect_located_failure(spec, self.block("bytes.meth\n"),
                                    "'bytes.meth': unknown clinic decorator "
                                    "@nosuchdecorator", 3)

    def test_clinic_decorator_non_constant_argument(self):
        spec = """
            class bytes:
                @text_signature(SIGNATURE)
                def meth(self, a: object):
                    ...
        """
        self.expect_failure(spec, self.block("bytes.meth\n"),
                            "the arguments of a clinic decorator must be "
                            "string or integer constants")

    def test_runtime_clinic_decorators(self):
        # runtime.py has an identity decorator for each clinic decorator,
        # so that the spec runs as Python.
        clinic_decorators = {name.removeprefix('at_')
                             for name in dir(DSLParser)
                             if name.startswith('at_')}
        clinic_decorators -= {'classmethod', 'staticmethod'}
        runtime = {name for name, value in vars(pyspec_runtime).items()
                   if value is pyspec_runtime._clinic_decorator
                   and not name.startswith('_')}
        self.assertEqual(runtime, clinic_decorators)
        def f(): pass
        self.assertIs(pyspec_runtime.permit_long_summary(f), f)
        self.assertIs(pyspec_runtime.text_signature("($self)")(f), f)
        self.assertIs(pyspec_runtime.critical_section("a", "b")(f), f)

    def test_c_basename(self):
        # One rule: clinic's default C basename (T for T.__new__,
        # T___init__ for T.__init__), or the one @c_name gives.
        spec = """
            class bytes:
                def __new__(cls, a: object = NULL):
                    ...
        """
        self.check(spec, "bytes.__new__\n", """
            @classmethod
            bytes.__new__
                a: object = NULL
        """)
        self.check("""
            class bytes:
                @c_name("bytes_new")
                def __new__(cls, a: object = NULL):
                    ...
        """, "bytes.__new__\n", """
            @classmethod
            bytes.__new__ as bytes_new
                a: object = NULL
        """)
        self.check("""
            class bytes:
                def __init__(self, a: object = NULL):
                    ...
        """, "bytes.__init__\n", """
            bytes.__init__
                a: object = NULL
        """)
        self.check(spec, "bytes.__new__ as spam\n", """
            @classmethod
            bytes.__new__ as spam
                a: object = NULL
        """)

    def test_parameter_docs_out_of_order(self):
        spec = """
            class bytes:
                def meth(self, a: object, b: object):
                    '''Summary.

                      b
                        Doc of b.
                      a
                        Doc of a.
                    '''
                    ...
        """
        self.expect_failure(spec, self.block("bytes.meth\n"),
                            "expected an empty line after the parameter "
                            "section, got '  a'")

    def test_missing_converter(self):
        spec = """
            class bytes:
                def meth(self, a):
                    ...
        """
        self.expect_failure(spec, self.block("bytes.meth\n"),
                            "parameter 'a' needs a converter as its "
                            "annotation")

    def test_clinic_error_names_spec(self):
        spec = """
            class bytes:
                def meth(self,
                         a: nosuchconverter):
                    '''Doc.'''
                    ...
        """
        exc = self.expect_located_failure(
            spec, self.block("bytes.meth\n"),
            "'nosuchconverter' is not a valid converter", 4)
        self.assertEqual(exc.report(),
                         f"{self.spec_path}:4: error: 'nosuchconverter' is "
                         "not a valid converter\n")
        # A check of the whole function is reported at its def.
        spec = """
            class bytes:
                def __new__(cls, a: object, /):
                    return a
        """
        block = self.block("bytes.__new__\n").replace('"&PyBytes_Type"',
                                                       '""')
        self.expect_located_failure(
            spec, block, f"bytes.__new__() in {self.spec_path}: requires "
            "the type object of 'bytes', which was declared without one", 3)
        # A construct outside the lowered subset, at its line.
        spec = """
            class bytes:
                @critical_section
                def meth(self, a: object, /):
                    return a
        """
        exc = self.expect_located_failure(
            spec, self.block("bytes.meth\n"), "bytes.meth(): "
            "@critical_section is expressible, but not lowered to C yet; "
            'see "The lowered subset" in Objects/pyspec/README.rst; a '
            "function implemented natively (in C) keeps this as its Python "
            "reference with @native", 3)
        self.assertEqual(exc.kind, SpecErrorKind.NOT_LOWERED)
        # So is a syntax error.
        self.expect_located_failure("class bytes:\n  def f(self):\n"
                                    "    return (\n",
                                    self.block("bytes.meth\n"),
                                    "'(' was never closed", 3)


class PyspecTypeTest(PyspecTestBase):
    """Clinic generates the docstring, method table and slot tables of the
    classes of the spec of a C file (libclinic/pyspec/typeobj.py)."""

    CLASS = """
        /*[clinic input]
        class bytes "PyBytesObject *" "&PyBytes_Type"
        class myiter "myiterobject *" "&MyIter_Type"
        [clinic start generated code]*/
    """

    # The blocks of the clinic functions of SPEC.
    BLOCKS = CLASS + """
        /*[clinic input]
        bytes.__new__
        [clinic start generated code]*/
        /*[clinic input]
        bytes.meth
        [clinic start generated code]*/
    """

    SPEC = """
        class bytes:
            '''Doc of
              bytes.'''

            def __new__(cls, a: object, /):
                return a

            def meth(self, a: object, /):
                '''Meth.'''
                ...

            @c_name(METH_NOARGS="bytes_getnewargs")
            def __getnewargs__(self, /):
                ...

            @c_name(METH_O="bytes_other")
            def other(self, x, /):
                '''Other(x)'''
                ...

            def __repr__(self, /): ...
            def __lt__(self, value, /): ...
            def __le__(self, value, /): ...
            def __eq__(self, value, /): ...
            def __ne__(self, value, /): ...
            def __gt__(self, value, /): ...
            def __ge__(self, value, /): ...

            @c_name(mp_length="bytes_length", sq_length="bytes_length")
            def __len__(self, /): ...

            @c_name(sq_repeat="bytes_rep")
            def __mul__(self, value, /): ...
            def __rmul__(self, value, /): ...

            @c_name("bytes_mod")
            def __mod__(self, value, /): ...
            def __rmod__(self, value, /): ...

        @c_name("myit")
        class myiter:
            @c_name("PyObject_SelfIter")
            def __iter__(self, /): ...

            def __next__(self, /): ...

            @c_name(METH_NOARGS="myit_len")
            def __length_hint__(self, /):
                '''Hint.'''
                ...
    """

    def types_header(self, spec, text=None):
        self.generate(spec, text or self.CLASS)
        with open(self.output_path, encoding='utf-8') as f:
            return f.read()

    def test_type_objects(self):
        header = self.types_header(self.SPEC, self.BLOCKS)
        self.assertIn('PyDoc_STRVAR(bytes_doc,\n'
                      '"Doc of\\n"\n"  bytes.");', header)
        self.assertIn('PyDoc_STRVAR(bytes_other__doc__,\n"Other(x)");',
                      header)
        self.assertIn(dedent("""\
            static PyMethodDef bytes_methods[] = {
                BYTES_METH_METHODDEF
                {"__getnewargs__", bytes_getnewargs, METH_NOARGS, NULL},
                {"other", bytes_other, METH_O, bytes_other__doc__},
                {NULL, NULL}  /* sentinel */
            };
            """), header)
        self.assertIn(dedent("""\
            static PyNumberMethods bytes_as_number = {
                .nb_remainder = bytes_mod,
            };

            static PySequenceMethods bytes_as_sequence = {
                .sq_length = bytes_length,
                .sq_repeat = bytes_rep,
            };

            static PyMappingMethods bytes_as_mapping = {
                .mp_length = bytes_length,
            };
            """), header)
        # @c_name on a class: the prefix of its tables.
        self.assertIn(dedent("""\
            static PyMethodDef myit_methods[] = {
                {"__length_hint__", myit_len, METH_NOARGS, myit___length_hint____doc__},
                {NULL, NULL}  /* sentinel */
            };"""), header)
        # The PyTypeObject is written in C; it names its own slots
        # (tp_repr, tp_iter...), tp_new and tp_init.
        self.assertNotIn('PyTypeObject PyBytes_Type', header)
        self.assertNotIn('MyIter_Type', header)
        self.assertNotIn('bytes_repr', header)

    def test_header_declares_no_type(self):
        # The spec of a header (stringlib/transmogrify.h) declares methods
        # that specs of C files share: no tables.
        self.filename = os.path.join(self.tmp_dir, 'foo.h')
        self.generate("""
            class bytes:
                def meth(self, a: object, /):
                    '''Meth.'''
                    ...
        """, self.CLASS + """
        /*[clinic input]
        bytes.meth
        [clinic start generated code]*/
        """)
        self.assertFalse(os.path.exists(self.output_path))

    def check_error(self, spec, errmsg):
        with self.assertRaisesRegex(ClinicError, re.escape(errmsg)):
            self.types_header(spec)

    def test_methods_only_class(self):
        # A class that declares no slot declares its methods only: their
        # table stays in C, so a first migration is signatures only.
        self.generate("""
            class bytes:
                def meth(self, a: object, /):
                    '''Meth.'''
                    ...
        """, self.CLASS + """
        /*[clinic input]
        bytes.meth
        [clinic start generated code]*/
        """)
        self.assertFalse(os.path.exists(self.output_path))

    def test_method_table_with_ifdef(self):
        # The table lists every method unconditionally: clinic defines an
        # empty *_METHODDEF for a method not compiled in.  A signature
        # that depends on #if keeps its full blocks and is only placed in
        # the class by ``def other(self): ...``.
        spec = """
            class bytes:
                def __repr__(self, /): ...
                def meth(self, a: object, /):
                    ...

                def other(self):
                    ...
        """
        header = self.types_header(spec, dedent(self.CLASS) + dedent("""
            #ifdef CONDITION
            /*[clinic input]
            bytes.meth
            [clinic start generated code]*/
            /*[clinic input]
            bytes.other
                a: object
                /
            [clinic start generated code]*/
            #else
            /*[clinic input]
            bytes.other

            Doc.
            [clinic start generated code]*/
            #endif
        """))
        self.assertIn(dedent("""\
            static PyMethodDef bytes_methods[] = {
                BYTES_METH_METHODDEF
                BYTES_OTHER_METHODDEF
                {NULL, NULL}  /* sentinel */
            };
            """), header)

    def test_partial_group(self):
        self.check_error("""
            class bytes:
                def __lt__(self, value, /): ...
                def __gt__(self, value, /): ...
        """, "tp_richcompare also implements __le__, __eq__, __ne__, "
             "__ge__: declare them too")
        self.check_error("""
            class bytes:
                def __mod__(self, value, /): ...
        """, "nb_remainder also implements __rmod__: declare it too")

    def test_several_slots(self):
        self.check_error("""
            class bytes:
                def __len__(self, /): ...
        """, "several slots can implement __len__ (mp_length, sq_length); "
             "name them")
        self.check_error("""
            class bytes:
                @c_name(nb_add="bytes_add")
                def __len__(self, /): ...
        """, "nb_add is not a slot of __len__")

    def test_slot_signature(self):
        self.check_error("""
            class bytes:
                def __repr__(self): ...
        """, "bytes.__repr__($self): the signature of tp_repr is "
             "__repr__($self, /)")
        self.check_error("""
            class bytes:
                def __contains__(self, value, /): ...
        """, "the signature of sq_contains is __contains__($self, key, /)")
        self.check_error("""
            class bytes:
                def __repr__(self, /):
                    '''Doc.'''
        """, "a slot has no docstring")
        self.check_error("""
            class bytes:
                def __repr__(self, /):
                    return 'x'
        """, "bytes.__repr__ is a slot implemented in C")

    def test_pycfunction(self):
        self.check_error("""
            class bytes:
                def __repr__(self, /): ...
                @c_name(METH_O="f")
                def meth(self, /): ...
        """, "bytes.meth: a METH_O function takes (self, arg, /)")
        self.check_error("""
            class bytes:
                def __repr__(self, /): ...
                @c_name(METH_BOGUS="f")
                def meth(self, /): ...
        """, "@c_name with a keyword names a slot")

    def test_decorators_of_c_methods(self):
        # A slot or a hand-written PyCFunction takes only @c_name (and a
        # PyCFunction @classmethod): nothing is silently ignored.
        self.check_error("""
            class bytes:
                @cname("bytes_r")
                def __repr__(self, /): ...
        """, "bytes.__repr__: a slot takes only @c_name and "
             "@coexist and @native and @text_signature, not "
             "@cname('bytes_r')")
        self.check_error("""
            class bytes:
                def __repr__(self, /): ...
                @permit_long_summary
                @c_name(METH_NOARGS="f")
                def meth(self, /): ...
        """, "bytes.meth: a PyCFunction takes only @c_name and "
             "@classmethod and @coexist and @native and @staticmethod and "
             "@text_signature, not @permit_long_summary")
        # @classmethod is METH_CLASS.
        header = self.types_header("""
            class bytes:
                def __repr__(self, /): ...
                @classmethod
                @c_name(METH_O="Py_GenericAlias")
                def __class_getitem__(cls, item, /):
                    '''See PEP 585'''
                    ...
        """)
        self.assertIn('    {"__class_getitem__", Py_GenericAlias, '
                      'METH_O | METH_CLASS, bytes___class_getitem____doc__},',
                      header)

    def test_accessors(self):
        # tp_getset is not generated: accessors are not in the tables (see
        # PyspecLanguageTest for their clinic input).  Their blocks say
        # which accessor they are.
        with self.assertRaisesRegex(ClinicError, re.escape(
                "'bytes.nbytes' is an accessor in ")):
            self.types_header("""
                class bytes:
                    def __repr__(self, /): ...
                    @getter
                    def nbytes(self): ...
            """, self.CLASS + """
        /*[clinic input]
        bytes.nbytes
        [clinic start generated code]*/
        """)
        self.check_error("""
            class bytes:
                def __repr__(self, /): ...
                @getter
                def nbytes(self): ...
                @getter
                def nbytes(self): ...
        """, "bytes.nbytes is defined twice")

    def test_class_body(self):
        # A spec class holds a docstring, defs, shared methods and pass:
        # anything else is an error, not ignored.
        for stmt in ("x = 1", "if True: pass", "center: int",
                     "center = tm.B.center"):
            with self.subTest(stmt=stmt):
                self.check_error(f"""
                    class bytes:
                        {stmt}
                """, "unsupported statement in spec class bytes: "
                     if not stmt.startswith("center =") else
                     "tm is not a spec imported with 'from <package> "
                     "import tm'")
        self.check_error("""
            import transmogrify as tm
        """, "import a spec as 'from stringlib.pyspec import "
             "transmogrify'")
        self.check_error("""
            class bytes:
                def meth(self, /):
                    pass
        """, "bytes.meth: use ... as the body of a function implemented "
             "in C, not pass")
        self.check_error("""
            class bytes:
                def meth(self, /): ...
                def meth(self, /): ...
        """, "bytes.meth is defined twice")

    def test_class_decorators(self):
        # The PyTypeObject is written in C: a class takes only the prefix
        # of its tables.
        for decorator in ('@static_type(tp_new="PyType_GenericNew")',
                          '@final', '@c_name(tp_repr="x")'):
            with self.subTest(decorator=decorator):
                self.check_error(f"""
                    {decorator}
                    class bytes:
                        pass
                """, 'class bytes: a spec class takes only @c_name("prefix")')

    def test_slot_block_rejected(self):
        with self.assertRaisesRegex(ClinicError,
                                    "'bytes.__repr__' is not a clinic "
                                    "function: it is a slot"):
            self.generate(self.SPEC, dedent(self.CLASS) + "/*[clinic input]\n"
                          "bytes.__repr__\n"
                          "[clinic start generated code]*/\n")

    def test_c_name_is_clinic_as(self):
        spec = """
            class bytes:
                @c_name("bytes_m")
                def meth(self, a: object, /):
                    ...
        """
        generated = self.generate(spec, dedent(self.CLASS)
                                  + "/*[clinic input]\nbytes.meth\n"
                                  "[clinic start generated code]*/\n")
        self.assertIn('bytes_m_impl(PyBytesObject *self, PyObject *a)\n'
                      '/*[clinic end generated code:', generated)
        with open(os.path.join(self.tmp_dir, 'clinic', 'foo.c.h'),
                  encoding='utf-8') as f:
            self.assertIn('#define BYTES_M_METHODDEF', f.read())
        with self.assertRaisesRegex(ClinicError, "the C name is written in"):
            self.generate(spec, dedent(self.CLASS) + "/*[clinic input]\n"
                          "bytes.meth as bytes_x\n"
                          "[clinic start generated code]*/\n")

    def test_shared_methods(self):
        os.mkdir(os.path.join(self.tmp_dir, 'shared'))
        with open(os.path.join(self.tmp_dir, 'shared', 'm.py'), 'w',
                  encoding='utf-8') as f:
            f.write(dedent('''
                class B:
                    @c_name("stringlib_center")
                    def center(self, width: Py_ssize_t, /):
                        """Center."""
                        ...

                    @c_name(METH_NOARGS="stringlib_lower")
                    def lower(self, /):
                        """B.lower() -> copy of B"""
                        ...
            '''))
        # Imports are relative to the directory of the C file.
        header = self.types_header("""
            from shared import m

            class bytes:
                def __repr__(self, /): ...
                center = m.B.center
                lower = m.B.lower
        """)
        self.assertIn('    STRINGLIB_CENTER_METHODDEF\n'
                      '    {"lower", stringlib_lower, METH_NOARGS, '
                      'bytes_lower__doc__},\n', header)
        self.assertIn('"B.lower() -> copy of B"', header)
        # A typo names the method that is missing.
        self.check_error("""
            from shared import m

            class bytes:
                def __repr__(self, /): ...
                center = m.B.centre
        """, "m.B has no method 'centre'")
        self.check_error("""
            from shared import m

            class bytes:
                def __repr__(self, /): ...
                centre = m.B.center
        """, "a shared method keeps its name: write "
             "center = m.B.center")
        self.check_error("""
            from shared import nosuchmodule
        """, "nosuchmodule.py not found")

    def test_shared_declarations(self):
        # A shared method with decorators: critical_section() and c_name().
        os.mkdir(os.path.join(self.tmp_dir, 'shared'))
        with open(os.path.join(self.tmp_dir, 'shared', 'm.py'), 'w',
                  encoding='utf-8') as f:
            f.write(dedent('''
                class B:
                    @c_name("stringlib_center")
                    def center(self, width: Py_ssize_t, /):
                        """Center."""
                        ...

                    @c_name(METH_NOARGS="stringlib_lower")
                    def lower(self, /):
                        """B.lower() -> copy of B"""
                        ...

                    def strip(self, chars: object = None, /):
                        """Strip."""
                        ...
            '''))
        # The flags of a clinic function come from its METHODDEF.
        os.mkdir(os.path.join(self.tmp_dir, 'clinic'))
        with open(os.path.join(self.tmp_dir, 'clinic', 'm.h.h'), 'w',
                  encoding='utf-8') as f:
            f.write('#define STRINGLIB_CENTER_METHODDEF    \\\n'
                    '    {"center", _PyCFunction_CAST(stringlib_center), '
                    'METH_FASTCALL, stringlib_center__doc__},\n')
        spec = """
            from shared import m

            class bytes:
                def __repr__(self, /): ...
                def __reduce__(self):
                    '''Reduce.'''
                    ...

                center = critical_section(m.B.center)
                lower = critical_section(m.B.lower)
                strip = critical_section(m.B.strip)

            class myiter:
                def __repr__(self, /): ...
                lower = c_name(METH_NOARGS="myiter_lower")(m.B.lower)
                __reduce__ = c_name(METH_NOARGS="myiter_reduce")(
                    bytes.__reduce__)
        """
        # With a block, strip is a clinic function of bytes with the
        # parameters and docstring of m.B.strip, and @critical_section.
        blocks = self.CLASS + """
        /*[clinic input]
        bytes.__reduce__
        [clinic start generated code]*/
        /*[clinic input]
        bytes.strip
        [clinic start generated code]*/
        """
        generated = self.generate(spec, blocks)
        self.assertIn('bytes_strip_impl(PyBytesObject *self, PyObject *chars)'
                      '\n/*[clinic end generated code:', generated)
        with open(os.path.join(self.tmp_dir, 'clinic', 'foo.c.h'),
                  encoding='utf-8') as f:
            clinic_h = f.read()
        self.assertIn('"strip($self, chars=None, /)\\n"', clinic_h)
        self.assertIn('Py_BEGIN_CRITICAL_SECTION(self);\n'
                      '    return_value = bytes_strip_impl', clinic_h)
        with open(self.output_path, encoding='utf-8') as f:
            header = f.read()
        self.assertIn(dedent("""\
            static PyObject *
            bytes_center(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
            {
                PyObject *ret;
                Py_BEGIN_CRITICAL_SECTION(self);
                ret = stringlib_center(self, args, nargs);
                Py_END_CRITICAL_SECTION();
                return ret;
            }
            """), header)
        self.assertIn('ret = stringlib_lower(self, NULL);', header)
        self.assertIn(
            '    BYTES___REDUCE___METHODDEF\n'
            '    {"center", _PyCFunction_CAST(bytes_center), METH_FASTCALL, '
            'stringlib_center__doc__},\n'
            '    {"lower", bytes_lower, METH_NOARGS, bytes_lower__doc__},\n'
            '    BYTES_STRIP_METHODDEF\n', header)
        self.assertIn(
            '    {"lower", myiter_lower, METH_NOARGS, myiter_lower__doc__},\n'
            '    {"__reduce__", myiter_reduce, METH_NOARGS, '
            'bytes___reduce____doc__},\n', header)
        # Errors.
        self.check_error("""
            from shared import m

            class bytes:
                def __repr__(self, /): ...
                strip = text_signature("()")(m.B.strip)
        """, "a shared method takes only critical_section and c_name")
        self.check_error("""
            from shared import m

            class bytes:
                def __repr__(self, /): ...
                lower = c_name(METH_O="f")(m.B.lower)
        """, "bytes.lower: write c_name(METH_NOARGS=\"f\")(...)")
        self.check_error("""
            from shared import m

            class bytes:
                def __repr__(self, /): ...
                lower = critical_section(c_name(METH_NOARGS="f")(m.B.lower))
        """, "critical_section() generates the C function")


def spec_files():
    """(spec, the C file it describes or None) of every spec of the tree,
    as the tools and test_pyspec_facts find them
    (libclinic/pyspec/specfiles.py)."""
    return pyspec_specfiles.spec_files(test_tools.basepath)


def load_cases(spec_path):
    """The module <stem>_cases.py next to the spec *spec_path*, or None."""
    return pyspec_specfiles.load_cases(spec_path)


def compiled_out(c_file, types):
    """The spec methods ("T.meth") of *c_file* not compiled in this build:
    their clinic block is under #if (clinic's cpp.Monitor condition) and
    the type types[T] does not define it (an inherited attribute of the
    same name, e.g. object.__sizeof__, does not count)."""
    clinic = Clinic(CLanguage(c_file), filename=c_file, limited_capi=False,
                    writer=libclinic.FileWriter(dry_run=True))
    with open(c_file, encoding='utf-8') as f:
        clinic.parse(f.read())
    return {f'{cls.name}.{func.name}'
            for _, cls in clinic._clinic_classes(clinic, '')
            for func in cls.functions
            if func.condition and cls.name in types
            and func.name not in vars(types[cls.name])}


@unittest.skipUnless(spec_files(), 'needs the source tree')
class PyspecFilesTest(TestCase):
    """Every spec file (Objects/pyspec/*.py, Objects/stringlib/pyspec/*.py,
    Modules/pyspec/*.py):

    * what clinic generates from it is up to date;
    * run as Python, its functions behave like the interpreter's on the
      CASES of <stem>_cases.py, next to the spec;
    * the classes of the spec of a C file are the interpreter's TYPES:
      their PyTypeObject is written in C, and the slots it fills are the
      dunders of the class.

    A method whose block is under an #if false in this build is skipped.
    A new spec adds data (a <stem>_cases.py), not a test class.
    """
    maxDiff = None

    REBUILD = ("the spec and the interpreter differ: if the spec changed, "
               "run \"make clinic\", rebuild Python (make) and rerun")

    def setUp(self):
        # Clinic on a C file registers the converters it defines.
        save_restore_converters(self)

    def test_compiled_out(self):
        # A method under an #if false in this build is skipped; one that
        # is compiled in, or not under #if, is checked.
        c_file = os.path.join(self.enterContext(os_helper.temp_dir()),
                              'foo.c')
        with open(c_file, 'w', encoding='utf-8') as f:
            f.write(dedent("""
                /*[clinic input]
                class int "PyObject *" "&PyLong_Type"
                [clinic start generated code]*/
                #ifdef NEVER
                /*[clinic input]
                int.nope
                [clinic start generated code]*/
                /*[clinic input]
                int.bit_length
                [clinic start generated code]*/
                #endif
                /*[clinic input]
                int.other
                [clinic start generated code]*/
            """))
        self.assertEqual(compiled_out(c_file, {'int': int}), {'int.nope'})

    def test_up_to_date(self):
        for spec_path, c_file in spec_files():
            if c_file is None:
                continue
            with self.subTest(spec=spec_path):
                writer = libclinic.FileWriter(dry_run=True)
                parse_file(c_file, limited_capi=False, writer=writer)
                self.assertEqual([change.filename
                                  for change in writer.changes], [],
                                 'run "make clinic"')

    @staticmethod
    def outcome(func, args, kwargs):
        """What calling func does: its exception, or its result, which is
        (the index of) one of the arguments or not."""
        try:
            result = func(*args, **kwargs)
        except Exception as exc:
            return ('raises', type(exc), str(exc))
        same = [i for i, arg in enumerate(args) if arg is result]
        return ('returns', type(result), result, same)

    def interpreter_function(self, cases, name):
        """What the interpreter runs for spec function *name*."""
        cls, _, meth = name.rpartition('.')
        if cls:
            # The descriptor: called with self (or cls) first.
            return vars(cases.TYPES[cls])[meth]
        module, _, func = cases.C_FUNCTIONS[name].rpartition('.')
        try:
            return getattr(importlib.import_module(module), func)
        except ImportError:
            return None

    def test_cases(self):
        for spec_path, c_file in spec_files():
            cases = load_cases(spec_path)
            if not getattr(cases, 'CASES', None):
                continue
            spec = pyspec_runtime.load(spec_path)
            skip = compiled_out(c_file, cases.TYPES) if c_file else set()
            for name, calls in cases.CASES.items():
                if name in skip:
                    continue
                interpreter = self.interpreter_function(cases, name)
                if interpreter is None:
                    continue        # e.g. no _testlimitedcapi
                for make_call in calls:
                    args, kwargs = make_call()
                    with self.subTest(func=name, args=args, kwargs=kwargs):
                        expected = self.outcome(interpreter, args, kwargs)
                        args, kwargs = make_call()
                        actual = self.outcome(spec[name], args, kwargs)
                        self.assertEqual(actual, expected, self.REBUILD)

    def test_types(self):
        for spec_path, c_file in spec_files():
            if c_file is None or not c_file.endswith('.c'):
                continue
            spec = pyspec_frontend.Spec.load(spec_path)
            cases = load_cases(spec_path)
            for cls_name in spec.classes:
                with self.subTest(spec=spec_path, cls=cls_name):
                    self.assertIsNotNone(
                        cases, f"add TYPES to the _cases.py of {spec_path}")
                    skip = compiled_out(c_file, cases.TYPES)
                    self.check_type(spec, cls_name, cases.TYPES[cls_name],
                                    skip)

    def check_type(self, spec, cls_name, tp, skip=()):
        """The type generated from class *cls_name* is *tp*, but for the
        methods *skip* (not compiled in)."""
        methods, slots, docs = [], set(), {}
        for meth in spec.entries(cls_name):
            name = f'{cls_name}.{meth}'
            if name in skip:
                continue
            kind = spec.method_kind(name)
            if kind == pyspec_frontend.SLOT or meth == '__init__':
                slots.add(meth)     # tp_init: a wrapper too
                continue
            if meth == '__new__':
                continue
            methods.append(meth)
            if kind == pyspec_frontend.SHARED:
                other, other_name = spec.shared_source(name)
                if other.method_kind(other_name) == pyspec_frontend.PYCFUNCTION:
                    docs[meth] = other.docstring(other_name)
            elif kind == pyspec_frontend.PYCFUNCTION:
                docs[meth] = spec.docstring(name)
        wrappers = {name for name, value in vars(tp).items()
                    if isinstance(value, types.WrapperDescriptorType)}
        # __hash__ is None: PyType_Ready() makes a type that defines
        # comparisons but no tp_hash unhashable.
        # Getsets and members stay in the C tables of the type.
        others = [name for name, value in vars(tp).items()
                  if name not in wrappers and name not in ('__doc__',
                                                           '__module__',
                                                           '__new__')
                  and not (name == '__hash__' and value is None)
                  and not isinstance(value, (types.GetSetDescriptorType,
                                             types.MemberDescriptorType))]
        # The method table, hence __dict__, is in the order of the spec.
        self.assertEqual(others, methods, self.REBUILD)
        if not slots:
            # The spec declares the methods only (e.g. mmap): the slots
            # and tp_doc stay in C.
            return
        # The slots of the spec are the wrappers of the type: the slots
        # its C PyTypeObject and the generated tables fill.
        self.assertEqual(wrappers, slots,
                         "the slots of the type (its PyTypeObject, in C) "
                         "and the dunders of the spec class differ; "
                         + self.REBUILD)
        # Hand-written PyCFunctions: the docstring as is.
        for meth, doc in docs.items():
            self.assertEqual(getattr(tp, meth).__doc__, doc, self.REBUILD)
        # tp_doc is the class docstring, as is.
        node = spec.classes[cls_name]
        doc = ast.get_docstring(node, clean=False)
        if doc is not None:
            doc = '\n'.join(spec._clean_docstring(node.body[0], doc))
        self.assertEqual(tp.__doc__, doc, self.REBUILD)

    def test_types_mismatch(self):
        # The C of a type and the dunders of its spec class disagree: a
        # dunder of the type missing from the class, or one too many.
        checked = 0
        for spec_path, c_file in spec_files():
            if c_file is None or not c_file.endswith('.c'):
                continue
            with open(spec_path, encoding='utf-8') as f:
                source = f.read()
            lines = source.splitlines(keepends=True)
            spec = pyspec_frontend.Spec(source, spec_path)
            for cls_name, node in spec.classes.items():
                if not spec.declares_slots(cls_name):
                    continue
                tp = load_cases(spec_path).TYPES[cls_name]
                stubs = [f for f in node.body
                         if isinstance(f, ast.FunctionDef)
                         and f.lineno == f.end_lineno and not f.decorator_list
                         and spec.method_kind(f'{cls_name}.{f.name}')
                         == pyspec_frontend.SLOT]
                if not stubs:
                    continue
                line = stubs[0].lineno - 1
                extra = next(s.name for s in pyspec_slots.slotdefs()
                             if s.name not in vars(tp)
                             and pyspec_slots.is_slot(s.name))
                indent = ' ' * stubs[0].col_offset
                changes = {
                    f'missing {stubs[0].name}':
                        lines[:line] + lines[line + 1:],
                    f'extra {extra}':
                        lines[:line] + [f'{indent}def {extra}(self, /): '
                                        '...\n'] + lines[line:],
                }
                for change, text in changes.items():
                    with self.subTest(cls=cls_name, change=change):
                        changed = pyspec_frontend.Spec(''.join(text),
                                                       spec_path)
                        with self.assertRaisesRegex(
                                AssertionError, 'and the dunders of the spec'):
                            self.check_type(changed, cls_name, tp)
                checked += 1
        self.assertGreater(checked, 0)


class PyspecSlotdefsTest(TestCase):
    """slotdefs[] of Objects/typeobject.c, as Argument Clinic reads it
    (libclinic/pyspec/slots.py)."""

    def test_wrappers(self):
        # Every wrapper of the static builtin types is described by the
        # slotdefs entry clinic parsed: same text signature and doc.
        expected = {}
        for slotdef in pyspec_slots.slotdefs():
            expected.setdefault(slotdef.name, set()).add(
                (slotdef.signature, slotdef.doc.partition('\n--\n\n')[2]))
        import builtins
        tps = [tp for tp in vars(builtins).values() if isinstance(tp, type)]
        tps += [type(iter(b'')), types.FunctionType, types.MethodType,
                types.GeneratorType, types.CoroutineType, property,
                types.MappingProxyType, types.SimpleNamespace]
        seen = 0
        for tp in tps:
            for name, value in vars(tp).items():
                if not isinstance(value, types.WrapperDescriptorType) \
                        or name in ('__new__', '__init__'):
                    continue
                with self.subTest(type=tp, name=name):
                    self.assertIn((value.__text_signature__, value.__doc__),
                                  expected[name])
                    seen += 1
        self.assertGreater(seen, 100)


@unittest.skipUnless(spec_files(), 'needs the source tree')
class PyspecFactsTest(TestCase):
    """The facts Argument Clinic derives from the specs by partial
    evaluation (libclinic/pyspec/facts.py, for the tier-2 call tables of
    call_table.py), and the conditions under which they hold: the FACTS
    of each <stem>_cases.py, checked by the generic assertions below (the
    format is described in Objects/pyspec/bytesobject_cases.py)."""

    maxDiff = None

    @staticmethod
    def env(cases, env):
        """The facts of partial_eval for the markers of a FACTS env."""
        pe = pyspec_partial_eval
        out = {}
        for name, value in env.items():
            if value is getattr(cases, 'NULL', None):
                out[name] = pe.NULL
            elif value is getattr(cases, 'ANY', None):
                out[name] = pe.NOTNULL
            elif isinstance(value, tuple) and value[:1] == ('is',):
                out[name] = pe.Value(value[1])
            else:
                out[name] = value
        return out

    def check_code(self, code, expected):
        for text in expected.get('contains', ()):
            self.assertIn(text, code)
        for text in expected.get('lacks', ()):
            self.assertNotIn(text, code)
        for text, count in expected.get('count', {}).items():
            self.assertEqual(code.count(text), count, text)

    def check_body(self, body, expected):
        """A specialization's body: its code, its only loop (whether it
        iterates by index, and the exact type it iterates), and the calls
        in the loop (else in the body)."""
        self.check_code(ast.unparse(ast.Module(body, [])), expected)
        where = body
        if 'loop' in expected:
            loop, = [node for stmt in body for node in ast.walk(stmt)
                     if isinstance(node, ast.For)]
            sequence, iterable = expected['loop']
            self.assertIs(loop.pyspec_sequence, sequence)
            self.assertIs(loop.pyspec_iterable, iterable)
            where = [loop]
        calls = {ast.unparse(node.func) for stmt in where
                 for node in ast.walk(stmt) if isinstance(node, ast.Call)}
        for name in expected.get('calls', ()):
            self.assertIn(name, calls)
        for name in expected.get('no_calls', ()):
            self.assertNotIn(name, calls)

    def check_fact(self, spec, cases, fact):
        pe = pyspec_partial_eval
        analyzer = pyspec_facts.analyzer(spec)
        env = self.env(cases, fact['env'])
        residual = None
        if 'expr' in fact:
            effects = pyspec_facts.Facts()
            call = ast.parse(fact['expr'], mode='eval').body
            result_type = analyzer.call(call, env, effects)
            found = types.SimpleNamespace(
                result_type=result_type, runs_python=effects.runs_python)
        elif fact.get('reference'):
            found = analyzer.reference_facts(fact['function'], env)
        else:
            options = {}
            if 'inline' in fact:
                options['inline'] = fact['inline']
            if 'arities' in fact:
                options['arities'] = [(self.env(cases, e), name, given)
                                      for e, name, given in fact['arities']]
            residual = pe.specialize(spec, fact['function'], env, **options)
            found = None
            if 'args' in fact:
                found = analyzer.facts(residual, env, fact['args'])
        for key in ('alias', 'result_type', 'runs_python', 'always_raises'):
            if key in fact:
                self.assertEqual(getattr(found, key), fact[key], key)
        if residual is None:
            return
        code = ast.unparse(ast.Module(residual, []))
        if 'residual' in fact:
            self.assertEqual(code, fact['residual'])
        if 'first' in fact:
            self.assertEqual(ast.unparse(residual[0]), fact['first'])
        if 'last' in fact:
            self.assertEqual(ast.unparse(residual[-1]), fact['last'])
        self.check_code(code, fact)
        if 'called' in fact:
            special = pe.specialization_of(spec, residual[-1].value,
                                           facts=True)
            self.check_body(special.body, fact['called'])
        for name, expected in fact.get('specializations', {}).items():
            special = pe.specialization(spec, name)
            if 'params' in expected:
                self.assertEqual(special.params, expected['params'])
            if 'lock' in expected:
                self.assertEqual(special.lock, expected['lock'])
            self.check_body(special.body, expected)

    def test_facts(self):
        checked = 0
        for spec_path, _ in spec_files():
            cases = load_cases(spec_path)
            spec = pyspec_frontend.Spec.load(spec_path)
            for fact in getattr(cases, 'FACTS', ()):
                what = fact.get('function') or fact['expr']
                with self.subTest(spec=spec_path, what=what,
                                  env=fact['env']):
                    self.check_fact(spec, cases, fact)
                    checked += 1
        self.assertGreater(checked, 0)

    def test_class_method_entries(self):
        # Sub.m shares the ml_meth of T.m, and the method table is keyed
        # by it: the generic entry of a class method, which
        # _PySpec_FindMethod() returns for a subclass, holds for any
        # class; the entries for an argument type are for exactly T.
        checked = 0
        for spec_path, c_file in spec_files():
            if c_file is None or not c_file.endswith('.c'):
                continue
            spec = pyspec_frontend.Spec.load(spec_path)
            output = pyspec_frontend.output_path(c_file)
            if not os.path.exists(output):
                continue
            with open(output, encoding='utf-8') as f:
                text = f.read()
            for name in spec.implemented_functions():
                node = spec.functions[name]
                if not any(pyspec_frontend.decorator_name(d) == 'classmethod'
                           for d in node.decorator_list):
                    continue
                cls_name = name.rpartition('.')[0]
                entries = re.findall(
                    rf'/\* ({re.escape(name)}\(\w+\)[^:]*): [^*]* \*/'
                    r'\s*\{([^}]*)\}', text)
                for comment, body in entries:
                    with self.subTest(comment=comment):
                        if '.arg_type = NULL' in body:
                            self.assertEqual(comment, f'{name}(x)')
                        else:
                            self.assertTrue(comment.endswith(
                                f', on exactly {cls_name}'))
                        checked += 1
        self.assertGreater(checked, 0)

    def test_builtin_type_facts(self):
        # The facts about builtin types (libclinic/pyspec/builtin_types.py,
        # and the spec classes that describe a whole builtin type) agree
        # with the builtins of the Python being built.
        import builtins
        bt = pyspec_builtin_types
        for spec_path, _ in spec_files():
            spec = pyspec_frontend.Spec.load(spec_path)
            facts = bt.TypeFacts(spec)
            tps = [*bt.TABLE]
            tps += [tp for name in spec.classes
                    if (tp := getattr(builtins, name, None)) is not None
                    and facts.spec_class(tp) is not None]
            for tp in tps:
                for name in bt.SPECIALS:
                    with self.subTest(spec=spec_path, tp=tp, name=name):
                        self.assertEqual(facts.defines(tp, name),
                                         name in tp.__dict__)
                        self.assertEqual(facts.has(tp, name),
                                         hasattr(tp, name))
                with self.subTest(spec=spec_path, tp=tp):
                    self.assertEqual(facts.mro(tp), list(tp.__mro__))
            # Types it knows nothing about: nothing is decided.
            class Unknown:
                pass
            self.assertIsNone(facts.has(Unknown, '__len__'))
            self.assertIsNone(facts.has(object, '__add__'))
        # The row of a type with a spec class repeats nothing the spec
        # derives: it lists only the special methods the spec writes as
        # ... (C only).
        for tp, spec in bt.spec_classes().items():
            row = bt.TABLE.get(tp)
            for name in (row.slots if row else ()):
                with self.subTest(tp=tp, name=name):
                    other, full = spec.declaration(f'{tp.__name__}.{name}')
                    self.assertTrue(
                        pyspec_frontend.is_stub(other.functions[full]),
                        f'{full} has a body or Python reference in the '
                        'spec: delete it from its row of builtin_types.py')

    def test_independent_of_host(self):
        # The generated code does not depend on the builtins of the Python
        # running Argument Clinic (PYTHON_FOR_REGEN may be as old as 3.10,
        # where no builtin type has __buffer__, and bytes had no
        # __bytes__).
        from unittest import mock
        real_hasattr = hasattr

        def old_hasattr(obj, name):
            if name in pyspec_builtin_types.SPECIALS \
                    and isinstance(obj, type):
                return False
            return real_hasattr(obj, name)

        for spec_path, c_file in spec_files():
            spec = pyspec_frontend.Spec.load(spec_path)
            if c_file is None or not spec.implemented_functions():
                continue
            with self.subTest(spec=spec_path):
                writer = libclinic.FileWriter(dry_run=True)
                with mock.patch('builtins.hasattr', old_hasattr):
                    parse_file(c_file, limited_capi=False, writer=writer)
                self.assertEqual(
                    [change.filename for change in writer.changes], [])

    def test_registry_up_to_date(self):
        # The registry in pycore_pyspec.h lists the call table of every
        # class of call_table.table_classes() of the core specs.
        root = test_tools.basepath
        header = os.path.join(root, pyspec_call_table.REGISTRY_HEADER)
        with open(header, encoding='utf-8') as f:
            text = f.read()
        expected = pyspec_call_table.registry_text(
            pyspec_call_table.registry(root))
        self.assertIn(pyspec_call_table.REGISTRY_START + '\n' + expected
                      + pyspec_call_table.REGISTRY_END, text,
                      'run "make clinic"')

    def test_unknown_is_worst(self):
        # A C function whose body is ... may do anything: a call of it may
        # run Python code, raise anything and return NULL.
        spec = pyspec_frontend.Spec(dedent("""
            def f(x: object):
                return g(x)

            def g(x: object):
                ...
        """))
        facts = pyspec_facts.analyzer(spec).function_facts('f')
        self.assertTrue(facts.runs_python)
        self.assertIn(pyspec_facts.ANY, facts.raises)
        self.assertIsNone(facts.result_type)


class PyspecLanguageTest(PyspecTestBase):
    """The spec language (libclinic/pyspec/frontend.py): every signature
    clinic can state, and any Python in a body; what is lowered to C and
    analysed for facts is the lowered subset (libclinic/pyspec/subset.py).
    """

    CLASS = PyspecStubTest.CLASS
    block = PyspecStubTest.block
    output = staticmethod(PyspecStubTest.output)
    check = PyspecStubTest.check

    def blocks(self, *texts):
        return dedent(self.CLASS) + "".join(
            "/*[clinic input]\n" + dedent(text)
            + "[clinic start generated code]*/\n" for text in texts)

    # -- signatures: the output of plain clinic, byte for byte -------------

    def test_new_with_constant_default(self):
        # tuple.__new__(iterable=()), list.__init__: any constant default.
        self.check("""
            class bytes:
                def __new__(cls, iterable: object(c_default="NULL") = (),
                            /):
                    '''Built-in immutable sequence.'''
                    ...
        """, "bytes.__new__ as bytes_new\n", """
            @classmethod
            bytes.__new__ as bytes_new
                iterable: object(c_default="NULL") = ()
                /

            Built-in immutable sequence.
        """)
        self.check("""
            class bytes:
                def __init__(self, iterable: object(c_default="NULL") = (),
                             /):
                    '''Built-in mutable sequence.'''
                    ...
        """, "bytes.__init__\n", """
            bytes.__init__
                iterable: object(c_default="NULL") = ()
                /

            Built-in mutable sequence.
        """)

    def test_keyword_parameter(self):
        # int(x, base=10): a keyword parameter with its C name.
        self.check("""
            class bytes:
                def __new__(cls, x: object(c_default="NULL") = 0, /,
                            base: object(c_default="NULL",
                                         c_param='obase') = 10):
                    ...
        """, "bytes.__new__ as long_new\n", """
            @classmethod
            bytes.__new__ as long_new
                x: object(c_default="NULL") = 0
                /
                base as obase: object(c_default="NULL") = 10
        """)

    def test_varargs_keyword_only_and_kwargs(self):
        output = self.check("""
            class bytes:
                @staticmethod
                def meth(a: object, /, *args: tuple,
                         flag: bool = False) -> Py_ssize_t:
                    '''Summary.'''
                    ...
        """, "bytes.meth\n", """
            @staticmethod
            bytes.meth -> Py_ssize_t
                a: object
                /
                *args: tuple
                flag: bool = False

            Summary.
        """)
        self.assertIn("bytes_meth_impl(PyObject *a, PyObject *args, "
                      "int flag)", output)
        # str.format: *args and **kwargs.
        output = self.check("""
            class bytes:
                def format(self, /, *args: tuple, **kwargs: dict):
                    '''Summary.'''
                    ...
        """, "bytes.format\n", """
            bytes.format
                *args: tuple
                **kwargs: dict

            Summary.
        """)
        self.assertIn("bytes_format_impl(PyBytesObject *self, "
                      "PyObject *args, PyObject *kwargs)", output)

    def test_self_and_defining_class_converters(self):
        self.check("""
            class bytes:
                @coexist
                @text_signature("($self, cls)")
                def meth(self: self(type="PyObject *"),
                         cls: defining_class, /):
                    '''Summary.'''
                    ...
        """, "bytes.meth\n", """
            @coexist
            @text_signature "($self, cls)"
            bytes.meth
                self: self(type="PyObject *")
                cls: defining_class
                /

            Summary.
        """)

    def test_accessors(self):
        # A getter and a setter: their blocks name them with @getter and
        # @setter, the rest comes from the spec.
        spec = """
            class bytes:
                @critical_section
                @getter
                def nbytes(self) -> Py_ssize_t:
                    '''The size in bytes.'''
                    ...

                @setter
                @deleter
                def nbytes(self, value: object = NULL):
                    ...
        """
        stubs = ("@getter\nbytes.nbytes\n", "@setter\nbytes.nbytes\n")
        full = ("@critical_section\n@getter\nbytes.nbytes -> Py_ssize_t\n\n"
                "The size in bytes.\n",
                "@setter\n@deleter\nbytes.nbytes\n"
                "    value: object = NULL\n")
        os_helper.unlink(self.spec_path)
        expected = self.output(self.generate(None, self.blocks(*full)))
        actual = self.output(self.generate(spec, self.blocks(*stubs)))
        self.assertEqual(actual, expected)
        self.assertIn("bytes_nbytes_get_impl(PyBytesObject *self)", actual)
        self.assertIn("bytes_nbytes_set_impl(PyBytesObject *self, "
                      "PyObject *value)", actual)
        # Each accessor needs its block, with its decorator.
        with self.assertRaises(ClinicError) as cm:
            self.generate(spec, self.blocks(stubs[0]))
        self.assertIn("put this block above its impl:\n/*[clinic input]\n"
                      "@setter\nbytes.nbytes\n", cm.exception.message)
        self.expect_failure(spec, self.blocks("bytes.nbytes\n"),
                            "'bytes.nbytes' is an accessor in")
        self.expect_failure("""
            class bytes:
                @getter
                def nbytes(self):
                    return 1
        """, self.blocks(stubs[0]), "bytes.nbytes(): an accessor with a "
                                    "body is expressible, but not lowered")

    def test_native_method(self):
        # A clinic method whose C is written by hand, with a Python
        # reference in any Python and any signature: plain clinic output.
        self.check("""
            class bytes:
                @native
                def meth(self, *args: tuple, sep: object = None):
                    '''Summary.'''
                    out = []
                    while args:
                        out.append(args[0])
                        args = args[1:]
                    return sep.join(out)
        """, "bytes.meth\n", """
            bytes.meth
                *args: tuple
                sep: object = None

            Summary.
        """)
        self.assertFalse(os.path.exists(self.output_path))

    # -- method tables -------------------------------------------------------

    def types_header(self, spec):
        self.generate(spec, PyspecTypeTest.CLASS)
        with open(self.output_path, encoding='utf-8') as f:
            return f.read()

    def test_pycfunction_conventions(self):
        header = self.types_header("""
            class bytes:
                def __repr__(self, /): ...

                @c_name(METH_VARARGS="do_string_format")
                def format(self, /, *args, **kwargs):
                    '''S.format(*args, **kwargs) -> str'''
                    ...

                @c_name(METH_FASTCALL="bytes_fast")
                def fast(self, /, *args): ...

                @staticmethod
                @c_name(METH_O="bytes_static")
                def static(x, /): ...

                @c_name(mp_subscript="list_subscript", sq_item="list_item",
                        METH_O="list_subscript")
                @coexist
                @text_signature("($self, index, /)")
                def __getitem__(self, key, /):
                    '''Return self[index].'''
                    ...
        """)
        self.assertIn(dedent("""\
            PyDoc_STRVAR(bytes___getitem____doc__,
            "__getitem__($self, index, /)\\n"
            "--\\n"
            "\\n"
            "Return self[index].");
            """), header)
        self.assertIn(dedent("""\
            static PyMethodDef bytes_methods[] = {
                {"format", _PyCFunction_CAST(do_string_format), METH_VARARGS | METH_KEYWORDS, bytes_format__doc__},
                {"fast", _PyCFunction_CAST(bytes_fast), METH_FASTCALL, NULL},
                {"static", bytes_static, METH_O | METH_STATIC, NULL},
                {"__getitem__", list_subscript, METH_O | METH_COEXIST, bytes___getitem____doc__},
                {NULL, NULL}  /* sentinel */
            };
            """), header)
        self.assertIn("    .mp_subscript = list_subscript,\n", header)
        self.assertIn("    .sq_item = list_item,\n", header)

    def test_pycfunction_signature(self):
        for convention, params, wanted in (
                ('METH_NOARGS', '(self, x, /)', '(self, /)'),
                ('METH_O', '(self, /)', '(self, arg, /)'),
                ('METH_VARARGS', '(self, x, /)', '(self, /, *args'),
                ('METH_FASTCALL', '(self, /, *, x)', '(self, /, *args'),
                ('METH_O', '(self, x)', '(self, arg, /)')):
            with self.subTest(convention=convention, params=params):
                spec = f"""
                    class bytes:
                        def __repr__(self, /): ...
                        @c_name({convention}="f")
                        def meth{params}: ...
                """
                self.expect_failure(spec, PyspecTypeTest.CLASS,
                                    f"bytes.meth: a {convention} function "
                                    f"takes {wanted}")

    # -- bodies: the lowered subset --------------------------------------------

    BODIES = [
        # (the def, what the error says is not lowered, its line)
        ("def __new__(cls, a: object, /):\n"
         "    while a is not NULL:\n        return a\n    return a",
         "while loop 'while a is not NULL:\\n    return a'", 2),
        ("def __new__(cls, *args: tuple):\n    return args",
         "*args", 1),
        ("def __new__(cls, a: object, /, **kw: dict):\n    return a",
         "**kw", 1),
        ("def __new__(cls, a: object = 0, /):\n    return a",
         "default 0 of parameter 'a' (lowered: NULL)", 1),
        ("def __new__(cls, a: object, /):\n"
         "    for x in a:\n        pass\n    else:\n        pass\n"
         "    return a",
         'this form of for loop (lowered: "for item in it:", no else)', 2),
        ("def __new__(cls, a: object, /):\n    b = a.copy()\n    return b",
         "call a.copy() (lowered: of C functions, spec functions, iter(), "
         "len(), and of local objects with at most one argument)", 2),
        ("def __new__(cls, a: object, /):\n    b = [x for x in a]\n"
         "    return b",
         "assignment of [x for x in a] (lowered: of a call)", 2),
        ("def __new__(cls, a: object, /):\n"
         "    raise TypeError('x') from None",
         "raise statement \"raise TypeError('x') from None\"", 2),
        ("def __new__(cls, a: object, /):\n    try:\n        b = iter(a)\n"
         "    except (TypeError, ValueError):\n        return a\n"
         "    return b",
         "except clause (TypeError, ValueError) (lowered: except E, E a "
         "builtin exception)", 4),
        ("def __new__(cls, a: object, /):\n    return",
         "return of nothing", 2),
        ("def __new__(cls, a: object, /):\n    a += 1\n    return a",
         "augmented assignment 'a += 1'", 2),
        ("def __new__(cls, a: object, /):\n    if a == 'x':\n"
         "        return a\n    return a",
         "value 'x' (lowered: names, NULL, types, exceptions, bool and int "
         "constants)", 2),
        ("def __new__(cls, a: object, /):\n    return exact(bytes, a)",
         "exact() outside the Python reference of a @native "
         "function", 2),
        ("@staticmethod\ndef meth(a: object, /):\n    return a",
         "@staticmethod", 1),
    ]

    def test_not_lowered(self):
        block = PyspecTest.BLOCK
        for body, what, line in self.BODIES:
            name = 'meth' if 'def meth' in body else '__new__'
            with self.subTest(body=body):
                spec = "class bytes:\n" + "".join(
                    f"    {line}\n" for line in body.splitlines())
                if name == 'meth':
                    spec = spec.replace("class bytes:",
                                        "class bytes:\n    def __new__"
                                        "(cls, /): ...", 1)
                    line += 1
                    block = self.blocks("bytes.__new__ as foo_new\n",
                                        "bytes.meth\n")
                exc = self.expect_located_failure(
                    spec, block,
                    f"bytes.{name}(): {what} is expressible, but not "
                    'lowered to C yet; see "The lowered subset" in '
                    "Objects/pyspec/README.rst; a function implemented "
                    "natively (in C) keeps this as its Python reference "
                    "with @native", line + 1)
                self.assertEqual(exc.kind, SpecErrorKind.NOT_LOWERED)

    def test_all_not_lowered(self):
        # subset.lowered() lists every construct, in order.
        spec = pyspec_frontend.Spec(dedent("""
            def f(a: object, *, b: int = 1):
                while a:
                    pass
                return a + b
        """))
        self.assertEqual(
            [(node.lineno, what)
             for node, what in pyspec_subset.lowered(spec, 'f')],
            [(2, "keyword-only parameter 'b'"),
             (3, "while loop 'while a:\\n    pass'"),
             (5, "return of a + b")])

    def test_specs_in_subset(self):
        # Every body of the specs of the tree is in the lowered subset,
        # every Python reference in the analysed one.
        for path, _ in spec_files():
            spec = pyspec_frontend.Spec.load(path)
            for name, node in spec.functions.items():
                with self.subTest(spec=path, function=name):
                    if pyspec_frontend.is_native(node):
                        self.assertEqual(
                            pyspec_subset.analysed(spec, name), [])
                    elif spec.implemented(name):
                        self.assertEqual(
                            pyspec_subset.lowered(spec, name), [])

    # -- facts: the worst case outside the subset -------------------------------

    REFERENCES = """
        @native
        def model(x: object):
            n = 0
            while n < 3:
                n += 1
            return exact(bytes, bytes(n))

        @native
        def effect_in_loop(x: object):
            while x:
                calls(x, "__len__")
            return exact(bytes, x)

        @native
        def nested_effect(x: object):
            return exact(bytes, unknown(x))
    """

    def test_worst_case_facts(self):
        spec = pyspec_frontend.Spec(dedent(self.REFERENCES) + dedent("""
            def lowered_outside(x: object):
                while x:
                    pass
                return x
        """))
        analyzer = pyspec_facts.analyzer(spec)
        # A loop without effects is a model of the value.
        model = analyzer.reference_facts('model', {})
        self.assertEqual((model.result_type, model.runs_python,
                          model.raises), (bytes, False, {'MemoryError'}))
        # Effects where facts.py does not follow them: the worst facts.
        for name in ('effect_in_loop', 'nested_effect'):
            with self.subTest(name):
                self.assertNotEqual(pyspec_subset.analysed(spec, name), [])
                facts = analyzer.reference_facts(name, {})
                self.assertEqual((facts.result_type, facts.runs_python,
                                  facts.raises, facts.returns_null),
                                 (None, True, {pyspec_facts.ANY}, True))
        self.assertEqual([what for _, what in
                          pyspec_subset.analysed(spec, 'nested_effect')],
                         ["unknown(x) in an argument of exact()"])
        # A body outside the lowered subset: the worst facts too.
        facts = analyzer.function_facts('lowered_outside')
        self.assertEqual((facts.result_type, facts.runs_python),
                         (None, True))

    def test_worst_case_facts_of_a_call(self):
        # A spec body calling such a reference checks for any error and
        # says it may run Python code.
        spec = dedent("""
            class bytes:
                def __new__(cls, a: object, /):
                    b = effect_in_loop(a)
                    if b is NULL:
                        return a
                    return b
        """) + dedent(self.REFERENCES)
        self.generate(spec, PyspecTest.BLOCK)
        with open(self.output_path, encoding='utf-8') as f:
            output = f.read()
        self.assertIn("/* bytes(x): result type not known exactly; may run "
                      "Python code */", output)

    # -- errors -------------------------------------------------------------

    def test_error_in_the_spec_it_is_written_in(self):
        # An @inline function of another spec is reported there.
        other = os.path.join(self.tmp_dir, 'pyspec', 'other.py')
        with open(other, 'w', encoding='utf-8') as f:
            f.write(dedent("""\
                @inline
                def helper(x: object):
                    if type(x) is bytes:
                        return x.upper()
                    return x
            """))
        spec = """
            from pyspec.other import helper

            class bytes:
                def __new__(cls, a: object, /):
                    if type(a) is bytes:
                        return helper(a)
                    return a
        """
        with self.assertRaises(SpecError) as cm:
            self.generate(spec, PyspecTest.BLOCK)
        exc = cm.exception
        self.assertEqual((exc.filename, exc.lineno), (other, 4))
        self.assertStartsWith(exc.message, "helper(): call x.upper() ")
        self.assertEqual(exc.kind, SpecErrorKind.NOT_LOWERED)

    def test_error_kinds(self):
        # A spec that is not valid, one the C file does not match, and a
        # use of the subset the emitter cannot lower.
        for spec, block, kind in (
                ("class bytes:\n    x = 1\n", PyspecTest.BLOCK,
                 SpecErrorKind.INVALID),
                (PyspecTest.SPEC,
                 PyspecTest.BLOCK.replace('"&PyBytes_Type"', '""'),
                 SpecErrorKind.BINDING),
                ("class bytes:\n    def __new__(cls, a: object, /):\n"
                 "        b = iter(a)\n        b = iter(a)\n        return b\n",
                 PyspecTest.BLOCK, SpecErrorKind.LOWERING)):
            with self.subTest(kind=kind):
                with self.assertRaises(SpecError) as cm:
                    self.generate(spec, block)
                self.assertEqual(cm.exception.kind, kind)
                self.assertEqual(cm.exception.filename, self.spec_path)

    # -- clinic integration ----------------------------------------------------

    def test_bindings(self):
        with open(self.spec_path, 'w', encoding='utf-8') as f:
            f.write(dedent(PyspecTest.SPEC))
        clinic = _make_clinic(filename=self.filename)
        clinic.parse(dedent(PyspecTest.BLOCK))
        self.assertEqual(clinic.pyspec_bindings.functions, {
            'bytes.__new__': pyspec_frontend.SpecBinding(
                'foo_new', 'PyTypeObject *', '')})
        self.assertEqual(clinic.pyspec_bindings.type_objects,
                         {'bytes': '&PyBytes_Type'})

    def test_lazy_imports(self):
        # A file without a spec does not load the generators of specs.
        from test.support.script_helper import assert_python_ok
        code = ("import sys, libclinic.app, libclinic.cli; "
                "print(sorted(m for m in sys.modules "
                "if m.startswith('libclinic.pyspec.')))")
        with test_tools.imports_under_tool('clinic'):
            path = os.pathsep.join(sys.path)
        _, out, _ = assert_python_ok('-c', code, PYTHONPATH=path)
        modules = ast.literal_eval(out.decode())
        self.assertIn('libclinic.pyspec.frontend', modules)
        self.assertNotIn('libclinic.pyspec.emit', modules)
        self.assertNotIn('libclinic.pyspec.typeobj', modules)


class VectorcallFunctionalTest(unittest.TestCase):
    """Runtime tests for @vectorcall exemplar types."""

    def test_vc_new(self):
        self.assertIsInstance(ac_tester.VcNew(), ac_tester.VcNew)
        self.assertIsInstance(ac_tester.VcNew(1), ac_tester.VcNew)
        self.assertIsInstance(ac_tester.VcNew(a=1), ac_tester.VcNew)

    def test_vc_new_rejects_extra_args(self):
        with self.assertRaises(TypeError):
            ac_tester.VcNew(1, 2)

    def test_vc_init(self):
        self.assertIsInstance(ac_tester.VcInit(1), ac_tester.VcInit)
        self.assertIsInstance(ac_tester.VcInit(1, 2), ac_tester.VcInit)
        self.assertIsInstance(ac_tester.VcInit(1, b=2), ac_tester.VcInit)

    def test_vc_init_missing_required(self):
        with self.assertRaises(TypeError):
            ac_tester.VcInit()

    def test_vc_init_rejects_a_as_keyword(self):
        # 'a' is positional-only
        with self.assertRaises(TypeError):
            ac_tester.VcInit(a=1)

    def test_vc_new_base(self):
        self.assertIsInstance(ac_tester.VcNewBase(1), ac_tester.VcNewBase)
        self.assertIsInstance(ac_tester.VcNewBase(1, 2), ac_tester.VcNewBase)
        self.assertIsInstance(ac_tester.VcNewBase(1, b=2), ac_tester.VcNewBase)

    def test_vc_new_base_missing_required(self):
        with self.assertRaises(TypeError):
            ac_tester.VcNewBase()

    def test_vc_new_base_subclass(self):
        # tp_vectorcall is not inherited, so the subclass is constructed
        # through tp_new.  The generated vectorcall asserts on that, so a
        # debug build aborts here if that ever stops holding.
        Sub = type('Sub', (ac_tester.VcNewBase,), {})
        obj = Sub(1)
        self.assertIsInstance(obj, Sub)
        self.assertIsInstance(obj, ac_tester.VcNewBase)

    def test_vc_kwonly(self):
        # keyword-only 'b': vectorcall has no kwnames==NULL fast path,
        # so every call goes through the helper.
        self.assertIsInstance(ac_tester.VcKwOnly(1), ac_tester.VcKwOnly)
        self.assertIsInstance(ac_tester.VcKwOnly(1, b=2), ac_tester.VcKwOnly)
        self.assertIsInstance(ac_tester.VcKwOnly(a=1, b=2), ac_tester.VcKwOnly)

    def test_vc_kwonly_b_as_positional(self):
        with self.assertRaises(TypeError):
            ac_tester.VcKwOnly(1, 2)

    def test_vc_kwonly_missing_required(self):
        with self.assertRaises(TypeError):
            ac_tester.VcKwOnly()

    def test_parse_errors_match_slot(self):
        # tp_vectorcall and tp_new/tp_init slot should match in argument parsing
        # error messages. Explicit calls to __new__ and __init__, as well as
        # subtype calls, will not hit the vectorcall slot. Test errors match.
        def error(func, args, kwargs):
            try:
                func(*args, **kwargs)
            except TypeError as exc:
                return str(exc)
            return None

        def through_new(cls):
            return cls, partial(cls.__new__, cls)

        def through_init(cls):
            # Not subclassable, and tp_new is PyType_GenericNew, so reach
            # tp_init through the __init__ slot wrapper on an instance.
            return cls, partial(cls.__init__, cls(1))

        entry_points = [
            through_new(enumerate),   # the only non-test @vectorcall function
            through_new(ac_tester.VcNew),
            through_new(ac_tester.VcNewBase),
            through_new(ac_tester.VcKwOnly),
            through_init(ac_tester.VcInit),
        ]
        invalid_calls = [
            ((), {}),           # too few positional arguments
            ((1, 2, 3), {}),    # too many positional arguments
            ((), {'zz': 1}),    # unknown keyword argument
        ]

        for direct, slot in entry_points:
            for args, kwargs in invalid_calls:
                with self.subTest(cls=direct, args=args, kwargs=kwargs):
                    self.assertEqual(error(direct, args, kwargs),
                                     error(slot, args, kwargs))


class LimitedCAPIOutputTests(unittest.TestCase):

    def setUp(self):
        self.clinic = _make_clinic(limited_capi=True)

    @staticmethod
    def wrap_clinic_input(block):
        return dedent(f"""
            /*[clinic input]
            output everything buffer
            {block}
            [clinic start generated code]*/
            /*[clinic input]
            dump buffer
            [clinic start generated code]*/
        """)

    def test_limited_capi_float(self):
        block = self.wrap_clinic_input("""
            func
                f: float
                /
        """)
        generated = self.clinic.parse(block)
        self.assertNotIn("PyFloat_AS_DOUBLE", generated)
        self.assertIn("float f;", generated)
        self.assertIn("f = (float) PyFloat_AsDouble", generated)

    def test_limited_capi_double(self):
        block = self.wrap_clinic_input("""
            func
                f: double
                /
        """)
        generated = self.clinic.parse(block)
        self.assertNotIn("PyFloat_AS_DOUBLE", generated)
        self.assertIn("double f;", generated)
        self.assertIn("f = PyFloat_AsDouble", generated)

    def test_limited_capi_alias(self):
        block = self.wrap_clinic_input("""
            func
                a: object = None
                *
                b as a: object = None
        """)
        err = ("Parameter 'b' cannot be an alias: "
               "the arguments are not parsed one by one.")
        _expect_failure(self, self.clinic.parse, block, err)

    def test_limited_capi_deprecated(self):
        block = self.wrap_clinic_input("""
            func
                [until 3.14] a: object = None
        """)
        err = ("Parameter 'a' cannot be deprecated: "
               "the arguments are not parsed one by one.")
        _expect_failure(self, self.clinic.parse, block, err)


try:
    import _testclinic_limited
except ImportError:
    _testclinic_limited = None

@unittest.skipIf(_testclinic_limited is None, "_testclinic_limited is missing")
class LimitedCAPIFunctionalTest(unittest.TestCase):
    locals().update((name, getattr(_testclinic_limited, name))
                    for name in dir(_testclinic_limited) if name.startswith('test_'))

    def test_my_int_func(self):
        with self.assertRaises(TypeError):
            _testclinic_limited.my_int_func()
        self.assertEqual(_testclinic_limited.my_int_func(3), 3)
        with self.assertRaises(TypeError):
            _testclinic_limited.my_int_func(1.0)
        with self.assertRaises(TypeError):
            _testclinic_limited.my_int_func("xyz")

    def test_my_int_sum(self):
        with self.assertRaises(TypeError):
            _testclinic_limited.my_int_sum()
        with self.assertRaises(TypeError):
            _testclinic_limited.my_int_sum(1)
        self.assertEqual(_testclinic_limited.my_int_sum(1, 2), 3)
        with self.assertRaises(TypeError):
            _testclinic_limited.my_int_sum(1.0, 2)
        with self.assertRaises(TypeError):
            _testclinic_limited.my_int_sum(1, "str")

    def test_my_double_sum(self):
        for func in (
            _testclinic_limited.my_float_sum,
            _testclinic_limited.my_double_sum,
        ):
            with self.subTest(func=func.__name__):
                self.assertEqual(func(1.0, 2.5), 3.5)
                with self.assertRaises(TypeError):
                    func()
                with self.assertRaises(TypeError):
                    func(1)
                with self.assertRaises(TypeError):
                    func(1., "2")

    def test_get_file_descriptor(self):
        # test 'file descriptor' converter: call PyObject_AsFileDescriptor()
        get_fd = _testclinic_limited.get_file_descriptor

        class MyInt(int):
            pass

        class MyFile:
            def __init__(self, fd):
                self._fd = fd
            def fileno(self):
                return self._fd

        for fd in (0, 1, 2, 5, 123_456):
            self.assertEqual(get_fd(fd), fd)

            myint = MyInt(fd)
            self.assertEqual(get_fd(myint), fd)

            myfile = MyFile(fd)
            self.assertEqual(get_fd(myfile), fd)

        with self.assertRaises(OverflowError):
            get_fd(2**256)
        with self.assertWarnsRegex(RuntimeWarning,
                                   "bool is used as a file descriptor"):
            get_fd(True)
        with self.assertRaises(TypeError):
            get_fd(1.0)
        with self.assertRaises(TypeError):
            get_fd("abc")
        with self.assertRaises(TypeError):
            get_fd(None)


class PermutationTests(unittest.TestCase):
    """Test permutation support functions."""

    def test_permute_left_option_groups(self):
        expected = (
            (),
            (3,),
            (2, 3),
            (1, 2, 3),
        )
        data = list(zip([1, 2, 3]))  # Generate a list of 1-tuples.
        actual = tuple(permute_left_option_groups(data))
        self.assertEqual(actual, expected)

    def test_permute_right_option_groups(self):
        expected = (
            (),
            (1,),
            (1, 2),
            (1, 2, 3),
        )
        data = list(zip([1, 2, 3]))  # Generate a list of 1-tuples.
        actual = tuple(permute_right_option_groups(data))
        self.assertEqual(actual, expected)

    def test_permute_optional_groups(self):
        empty = {
            "left": (), "required": (), "right": (),
            "expected": ((),),
        }
        noleft1 = {
            "left": (), "required": ("b",), "right": (("c",),),
            "expected": (
                ("b",),
                ("b", "c"),
            ),
        }
        noleft2 = {
            "left": (), "required": ("b", "c",), "right": (("d",),),
            "expected": (
                ("b", "c"),
                ("b", "c", "d"),
            ),
        }
        noleft3 = {
            "left": (), "required": ("b", "c",), "right": (("d", "e"),),
            "expected": (
                ("b", "c"),
                ("b", "c", "d"),
                ("b", "c", "d", "e"),
            ),
        }
        noright1 = {
            "left": (("a",),), "required": ("b",), "right": (),
            "expected": (
                ("b",),
                ("a", "b"),
            ),
        }
        noright2 = {
            "left": (("a",),), "required": ("b", "c"), "right": (),
            "expected": (
                ("b", "c"),
                ("a", "b", "c"),
            ),
        }
        noright3 = {
            "left": (("a", "b"),), "required": ("c",), "right": (),
            "expected": (
                ("c",),
                ("b", "c"),
                ("a", "b", "c"),
            ),
        }
        leftandright1 = {
            "left": (("a",),), "required": ("b",), "right": (("c",),),
            "expected": (
                ("b",),
                ("a", "b"),  # Prefer left.
                ("a", "b", "c"),
            ),
        }
        leftandright2 = {
            "left": (("a", "b"),), "required": ("c", "d"), "right": (("e", "f"),),
            "expected": (
                ("c", "d"),
                ("b", "c", "d"),       # Prefer left.
                ("a", "b", "c", "d"),  # Prefer left.
                ("a", "b", "c", "d", "e"),
                ("a", "b", "c", "d", "e", "f"),
            ),
        }
        independentleft = {
            "left": (("a",), ("b",)), "required": ("c",), "right": (),
            "expected": (
                ("c",),
                ("b", "c"),
                ("a", "b", "c"),
            ),
        }
        independentright = {
            "left": (), "required": ("a",), "right": (("b",), ("c",)),
            "expected": (
                ("a",),
                ("a", "b"),
                ("a", "b", "c"),
            ),
        }
        dataset = (
            empty,
            noleft1, noleft2, noleft3,
            noright1, noright2, noright3,
            leftandright1, leftandright2,
            independentleft, independentright,
        )
        for params in dataset:
            with self.subTest(**params):
                left, required, right, expected = params.values()
                permutations = permute_optional_groups(left, required, right)
                actual = tuple(permutations)
                self.assertEqual(actual, expected)


class FormatHelperTests(unittest.TestCase):

    def test_strip_leading_and_trailing_blank_lines(self):
        dataset = (
            # Input lines, expected output.
            ("a\nb",            "a\nb"),
            ("a\nb\n",          "a\nb"),
            ("a\nb ",           "a\nb"),
            ("\na\nb\n\n",      "a\nb"),
            ("\n\na\nb\n\n",    "a\nb"),
            ("\n\na\n\nb\n\n",  "a\n\nb"),
            # Note, leading whitespace is preserved:
            (" a\nb",               " a\nb"),
            (" a\nb ",              " a\nb"),
            (" \n \n a\nb \n \n ",  " a\nb"),
        )
        for lines, expected in dataset:
            with self.subTest(lines=lines, expected=expected):
                out = libclinic.normalize_snippet(lines)
                self.assertEqual(out, expected)

    def test_normalize_snippet(self):
        snippet = """
            one
            two
            three
        """

        # Expected outputs:
        zero_indent = (
            "one\n"
            "two\n"
            "three"
        )
        four_indent = (
            "    one\n"
            "    two\n"
            "    three"
        )
        eight_indent = (
            "        one\n"
            "        two\n"
            "        three"
        )
        expected_outputs = {0: zero_indent, 4: four_indent, 8: eight_indent}
        for indent, expected in expected_outputs.items():
            with self.subTest(indent=indent):
                actual = libclinic.normalize_snippet(snippet, indent=indent)
                self.assertEqual(actual, expected)

    def test_escaped_docstring(self):
        dataset = (
            # input,    expected
            (r"abc",    r'"abc"'),
            (r"\abc",   r'"\\abc"'),
            (r"\a\bc",  r'"\\a\\bc"'),
            (r"\a\\bc", r'"\\a\\\\bc"'),
            (r'"abc"',  r'"\"abc\""'),
            (r"'a'",    r'"\'a\'"'),
        )
        for line, expected in dataset:
            with self.subTest(line=line, expected=expected):
                out = libclinic.docstring_for_c_string(line)
                self.assertEqual(out, expected)

    def test_format_escape(self):
        line = "{}, {a}"
        expected = "{{}}, {{a}}"
        out = libclinic.format_escape(line)
        self.assertEqual(out, expected)

    def test_c_bytes_repr(self):
        c_bytes_repr = libclinic.c_bytes_repr
        self.assertEqual(c_bytes_repr(b''), '""')
        self.assertEqual(c_bytes_repr(b'abc'), '"abc"')
        self.assertEqual(c_bytes_repr(b'\a\b\f\n\r\t\v'), r'"\a\b\f\n\r\t\v"')
        self.assertEqual(c_bytes_repr(b' \0\x7f'), r'" \000\177"')
        self.assertEqual(c_bytes_repr(b'"'), r'"\""')
        self.assertEqual(c_bytes_repr(b"'"), r'''"'"''')
        self.assertEqual(c_bytes_repr(b'\\'), r'"\\"')
        self.assertEqual(c_bytes_repr(b'??/'), r'"?\?/"')
        self.assertEqual(c_bytes_repr(b'???/'), r'"?\?\?/"')
        self.assertEqual(c_bytes_repr(b'/*****/ /*/ */*'), r'"/\*****\/ /\*\/ *\/\*"')
        self.assertEqual(c_bytes_repr(b'\xa0'), r'"\240"')
        self.assertEqual(c_bytes_repr(b'\xff'), r'"\377"')

    def test_c_str_repr(self):
        c_str_repr = libclinic.c_str_repr
        self.assertEqual(c_str_repr(''), '""')
        self.assertEqual(c_str_repr('abc'), '"abc"')
        self.assertEqual(c_str_repr('\a\b\f\n\r\t\v'), r'"\a\b\f\n\r\t\v"')
        self.assertEqual(c_str_repr(' \0\x7f'), r'" \000\177"')
        self.assertEqual(c_str_repr('"'), r'"\""')
        self.assertEqual(c_str_repr("'"), r'''"'"''')
        self.assertEqual(c_str_repr('\\'), r'"\\"')
        self.assertEqual(c_str_repr('??/'), r'"?\?/"')
        self.assertEqual(c_str_repr('???/'), r'"?\?\?/"')
        self.assertEqual(c_str_repr('/*****/ /*/ */*'), r'"/\*****\/ /\*\/ *\/\*"')
        self.assertEqual(c_str_repr('\xa0'), r'"\u00a0"')
        self.assertEqual(c_str_repr('\xff'), r'"\u00ff"')
        self.assertEqual(c_str_repr('\u20ac'), r'"\u20ac"')
        self.assertEqual(c_str_repr('\U0001f40d'), r'"\U0001f40d"')

    def test_c_unichar_repr(self):
        c_unichar_repr = libclinic.c_unichar_repr
        self.assertEqual(c_unichar_repr('a'), "'a'")
        self.assertEqual(c_unichar_repr('\n'), r"'\n'")
        self.assertEqual(c_unichar_repr('\b'), r"'\b'")
        self.assertEqual(c_unichar_repr('\0'), '0')
        self.assertEqual(c_unichar_repr('\1'), '0x01')
        self.assertEqual(c_unichar_repr('\x7f'), '0x7f')
        self.assertEqual(c_unichar_repr(' '), "' '")
        self.assertEqual(c_unichar_repr('"'), """'"'""")
        self.assertEqual(c_unichar_repr("'"), r"'\''")
        self.assertEqual(c_unichar_repr('\\'), r"'\\'")
        self.assertEqual(c_unichar_repr('?'), "'?'")
        self.assertEqual(c_unichar_repr('\xa0'), '0xa0')
        self.assertEqual(c_unichar_repr('\xff'), '0xff')
        self.assertEqual(c_unichar_repr('\u20ac'), '0x20ac')
        self.assertEqual(c_unichar_repr('\U0001f40d'), '0x1f40d')

    def test_indent_all_lines(self):
        # Blank lines are expected to be unchanged.
        self.assertEqual(libclinic.indent_all_lines("", prefix="bar"), "")

        lines = (
            "one\n"
            "two"  # The missing newline is deliberate.
        )
        expected = (
            "barone\n"
            "bartwo"
        )
        out = libclinic.indent_all_lines(lines, prefix="bar")
        self.assertEqual(out, expected)

        # If last line is empty, expect it to be unchanged.
        lines = (
            "\n"
            "one\n"
            "two\n"
            ""
        )
        expected = (
            "bar\n"
            "barone\n"
            "bartwo\n"
            ""
        )
        out = libclinic.indent_all_lines(lines, prefix="bar")
        self.assertEqual(out, expected)

    def test_suffix_all_lines(self):
        # Blank lines are expected to be unchanged.
        self.assertEqual(libclinic.suffix_all_lines("", suffix="foo"), "")

        lines = (
            "one\n"
            "two"  # The missing newline is deliberate.
        )
        expected = (
            "onefoo\n"
            "twofoo"
        )
        out = libclinic.suffix_all_lines(lines, suffix="foo")
        self.assertEqual(out, expected)

        # If last line is empty, expect it to be unchanged.
        lines = (
            "\n"
            "one\n"
            "two\n"
            ""
        )
        expected = (
            "foo\n"
            "onefoo\n"
            "twofoo\n"
            ""
        )
        out = libclinic.suffix_all_lines(lines, suffix="foo")
        self.assertEqual(out, expected)


class ClinicReprTests(unittest.TestCase):
    def test_Block_repr(self):
        block = Block("foo")
        expected_repr = "<clinic.Block 'text' input='foo' output=None>"
        self.assertEqual(repr(block), expected_repr)

        block2 = Block("bar", "baz", [], "eggs", "spam")
        expected_repr_2 = "<clinic.Block 'baz' input='bar' output='eggs'>"
        self.assertEqual(repr(block2), expected_repr_2)

        block3 = Block(
            input="longboi_" * 100,
            dsl_name="wow_so_long",
            signatures=[],
            output="very_long_" * 100,
            indent=""
        )
        expected_repr_3 = (
            "<clinic.Block 'wow_so_long' input='longboi_longboi_longboi_l...' output='very_long_very_long_very_...'>"
        )
        self.assertEqual(repr(block3), expected_repr_3)

    def test_Destination_repr(self):
        c = _make_clinic()

        destination = Destination(
            "foo", type="file", clinic=c, args=("eggs",)
        )
        self.assertEqual(
            repr(destination), "<clinic.Destination 'foo' type='file' file='eggs'>"
        )

        destination2 = Destination("bar", type="buffer", clinic=c)
        self.assertEqual(repr(destination2), "<clinic.Destination 'bar' type='buffer'>")

    def test_Module_repr(self):
        module = Module("foo", _make_clinic())
        self.assertRegex(repr(module), r"<clinic.Module 'foo' at \d+>")

    def test_Class_repr(self):
        cls = Class("foo", _make_clinic(), None, 'some_typedef', 'some_type_object')
        self.assertRegex(repr(cls), r"<clinic.Class 'foo' at \d+>")

    def test_FunctionKind_repr(self):
        self.assertEqual(
            repr(FunctionKind.CLASS_METHOD), "<clinic.FunctionKind.CLASS_METHOD>"
        )

    def test_Function_and_Parameter_reprs(self):
        function = Function(
            name='foo',
            module=_make_clinic(),
            cls=None,
            c_basename=None,
            full_name='foofoo',
            return_converter=int_return_converter(),
            kind=FunctionKind.METHOD_INIT,
            coexist=False
        )
        self.assertEqual(repr(function), "<clinic.Function 'foo'>")

        converter = self_converter('bar', 'bar', function)
        parameter = Parameter(
            "bar",
            kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
            function=function,
            converter=converter
        )
        self.assertEqual(repr(parameter), "<clinic.Parameter 'bar'>")

    def test_Monitor_repr(self):
        monitor = libclinic.cpp.Monitor("test.c")
        self.assertRegex(repr(monitor), r"<clinic.Monitor \d+ line=0 condition=''>")

        monitor.line_number = 42
        monitor.stack.append(("token1", "condition1"))
        self.assertRegex(
            repr(monitor), r"<clinic.Monitor \d+ line=42 condition='condition1'>"
        )

        monitor.stack.append(("token2", "condition2"))
        self.assertRegex(
            repr(monitor),
            r"<clinic.Monitor \d+ line=42 condition='condition1 && condition2'>"
        )


if __name__ == "__main__":
    unittest.main()
