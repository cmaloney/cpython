from __future__ import annotations
import os

from collections.abc import Callable, Sequence
from typing import Any, TYPE_CHECKING


import libclinic
from libclinic import fail, warn
from libclinic.function import Class
from libclinic.block_parser import Block, BlockParser
from libclinic.codegen import BlockPrinter, Destination, CodeGen
from libclinic.parser import Parser, PythonParser
from libclinic.dsl_parser import DSLParser
from libclinic.pyspec import emit, frontend, typeobj
if TYPE_CHECKING:
    from libclinic.clanguage import CLanguage
    from libclinic.function import (
        Module, Function, Property, ClassDict, ModuleDict)
    from libclinic.codegen import DestinationDict


# maps strings to callables.
# the callable should return an object
# that implements the clinic parser
# interface (__init__ and parse).
#
# example parsers:
#   "clinic", handles the Clinic DSL
#   "python", handles running Python code
#
parsers: dict[str, Callable[[Clinic], Parser]] = {
    'clinic': DSLParser,
    'python': PythonParser,
}


class Clinic:

    presets_text = """
preset block
everything block
methoddef_ifndef buffer 1
docstring_prototype suppress
parser_prototype suppress
cpp_if suppress
cpp_endif suppress

preset original
everything block
methoddef_ifndef buffer 1
docstring_prototype suppress
parser_prototype suppress
cpp_if suppress
cpp_endif suppress

preset file
everything file
methoddef_ifndef file 1
docstring_prototype suppress
parser_prototype suppress
impl_definition block

preset buffer
everything buffer
methoddef_ifndef buffer 1
impl_definition block
docstring_prototype suppress
impl_prototype suppress
parser_prototype suppress

preset partial-buffer
everything buffer
methoddef_ifndef buffer 1
docstring_prototype block
impl_prototype suppress
methoddef_define block
parser_prototype block
impl_definition block

"""

    def __init__(
        self,
        language: CLanguage,
        printer: BlockPrinter | None = None,
        *,
        filename: str,
        limited_capi: bool,
        verify: bool = True,
        writer: libclinic.FileWriter | None = None,
    ) -> None:
        # maps strings to Parser objects.
        # (instantiated from the "parsers" global.)
        self.parsers: dict[str, Parser] = {}
        self.language: CLanguage = language
        if printer:
            fail("Custom printers are broken right now")
        self.printer = printer or BlockPrinter(language)
        self.writer = writer or libclinic.FileWriter()
        self.verify = verify
        self.limited_capi = limited_capi
        self.filename = filename
        self.modules: ModuleDict = {}
        self.classes: ClassDict = {}
        self.functions: list[Function] = []
        # The attributes implemented by accessors, in the order of definition.
        self.properties: list[Property] = []
        self.codegen = CodeGen(self.limited_capi)
        # The spec of the file (see libclinic.pyspec), read on first use.
        self._pyspec: frontend.Spec | None = None
        self._pyspec_read = False
        # C basenames of the clinic functions implemented by spec methods.
        self.pyspec_c_basenames: dict[str, str] = {}
        # C type of the self (or class) parameter of the other spec methods.
        self.pyspec_self_ctypes: dict[str, str] = {}

        self.line_prefix = self.line_suffix = ''

        self.destinations: DestinationDict = {}
        self.add_destination("block", "buffer")
        self.add_destination("suppress", "suppress")
        self.add_destination("buffer", "buffer")
        if filename:
            self.add_destination("file", "file", "{dirname}/clinic/{basename}.h")

        d = self.get_destination_buffer
        self.destination_buffers = {
            'cpp_if': d('file'),
            'docstring_prototype': d('suppress'),
            'docstring_definition': d('file'),
            'methoddef_define': d('file'),
            'impl_prototype': d('file'),
            'parser_prototype': d('suppress'),
            'parser_helper': d('file'),
            'parser_definition': d('file'),
            'vectorcall_definition': d('file'),
            'cpp_endif': d('file'),
            'methoddef_ifndef': d('file', 1),
            'impl_definition': d('block'),
        }

        DestBufferType = dict[str, list[str]]
        DestBufferList = list[DestBufferType]

        self.destination_buffers_stack: DestBufferList = []

        self.presets: dict[str, dict[Any, Any]] = {}
        preset = None
        for line in self.presets_text.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            name, value, *options = line.split()
            if name == 'preset':
                self.presets[value] = preset = {}
                continue

            if len(options):
                index = int(options[0])
            else:
                index = 0
            buffer = self.get_destination_buffer(value, index)

            if name == 'everything':
                for name in self.destination_buffers:
                    preset[name] = buffer
                continue

            assert name in self.destination_buffers
            preset[name] = buffer

    def add_destination(
        self,
        name: str,
        type: str,
        *args: str
    ) -> None:
        if name in self.destinations:
            fail(f"Destination already exists: {name!r}")
        self.destinations[name] = Destination(name, type, self, args)

    def get_destination(self, name: str) -> Destination:
        d = self.destinations.get(name)
        if not d:
            fail(f"Destination does not exist: {name!r}")
        return d

    def get_destination_buffer(
        self,
        name: str,
        item: int = 0
    ) -> list[str]:
        d = self.get_destination(name)
        return d.buffers[item]

    def parse(self, input: str) -> str:
        printer = self.printer
        self.block_parser = BlockParser(input, self.language, verify=self.verify)
        for block in self.block_parser:
            dsl_name = block.dsl_name
            if dsl_name:
                if dsl_name not in self.parsers:
                    assert dsl_name in parsers, f"No parser to handle {dsl_name!r} block."
                    self.parsers[dsl_name] = parsers[dsl_name](self)
                parser = self.parsers[dsl_name]
                parser.parse(block)
            printer.print_block(block)

        self.check_spec_blocks()

        # The entry of an attribute is composed of all its accessors, so it
        # is rendered when the whole file is parsed.
        self.language.render_properties(self)

        # (filename, text) of the files generated besides the C file.
        outputs: list[tuple[str, str]] = []
        # these are destinations not buffers
        for name, destination in self.destinations.items():
            if destination.type == 'suppress':
                continue
            output = destination.dump()

            if output:
                block = Block("", dsl_name="clinic", output=output)

                if destination.type == 'buffer':
                    block.input = "dump " + name + "\n"
                    warn("Destination buffer " + repr(name) + " not empty at end of file, emptying.")
                    printer.write("\n")
                    printer.print_block(block)
                    continue

                if destination.type == 'file':
                    try:
                        dirname = os.path.dirname(destination.filename)
                        try:
                            self.writer.makedirs(dirname)
                        except FileExistsError:
                            if not os.path.isdir(dirname):
                                fail(f"Can't write to destination "
                                     f"{destination.filename!r}; "
                                     f"can't make directory {dirname!r}!")
                        if self.verify:
                            with open(destination.filename) as f:
                                parser_2 = BlockParser(f.read(), language=self.language)
                                blocks = list(parser_2)
                                if (len(blocks) != 1) or (blocks[0].input != 'preserve\n'):
                                    fail(f"Modified destination file "
                                         f"{destination.filename!r}; not overwriting!")
                    except FileNotFoundError:
                        pass

                    block.input = 'preserve\n'
                    includes = self.codegen.get_includes()

                    printer_2 = BlockPrinter(self.language)
                    printer_2.print_block(block, header_includes=includes)
                    outputs.append((destination.filename,
                                    printer_2.f.getvalue()))
                    continue

        outputs += self.pyspec_outputs()
        # Nothing is written unless every output could be generated (the
        # caller writes the C file itself last).
        for filename, text in outputs:
            self.writer.write(filename, text)
        return printer.f.getvalue()

    @property
    def pyspec(self) -> frontend.Spec | None:
        """The spec of the file: pyspec/<stem>.py next to it, if any."""
        if not self._pyspec_read:
            self._pyspec_read = True
            if self.filename:
                path = frontend.spec_path(self.filename)
                try:
                    self._pyspec = frontend.Spec.load(path)
                except SyntaxError as exc:
                    raise frontend.SpecError(exc.msg, filename=path,
                                             lineno=exc.lineno) from None
        return self._pyspec

    def check_spec_blocks(self) -> None:
        """Every clinic function of a spec class declared in the file
        (``class T`` directive) has a one-line block, ``T.meth``, above its
        impl: clinic writes the impl head there."""
        spec = self.pyspec
        if spec is None:
            return
        for path, cls in self._clinic_classes(self, ''):
            if cls.name not in spec.classes:
                continue
            declared = {f.name for f in cls.functions}
            for meth in spec.methods(cls.name):
                if meth not in declared:
                    raise spec.error(
                        spec.functions[f'{cls.name}.{meth}'],
                        f"{path}.{meth} has no clinic block in "
                        f"{self.filename}; put this block above its "
                        f"impl:\n/*[clinic input]\n{path}.{meth}\n"
                        "[clinic start generated code]*/")

    def _clinic_classes(self, parent: Any, prefix: str
                        ) -> list[tuple[str, Class]]:
        """(dotted name, class) of the clinic classes under *parent*."""
        found = []
        for name, cls in parent.classes.items():
            found.append((prefix + name, cls))
            found += self._clinic_classes(cls, f'{prefix}{name}.')
        for name, module in getattr(parent, 'modules', {}).items():
            found += self._clinic_classes(module, f'{prefix}{name}.')
        return found

    def pyspec_outputs(self) -> list[tuple[str, str]]:
        """(filename, text) of the C generated from the spec, if any:
        clinic/<stem>_pyspec.c.h holds the implemented spec functions, then
        the static types.  The C file includes it once, at its end."""
        spec = self.pyspec
        if spec is None:
            return []
        # Name the spec the same way whatever the current directory.
        dirname, basename = os.path.split(os.path.abspath(self.filename))
        stem = os.path.splitext(basename)[0]
        spec_name = f"{os.path.basename(dirname)}/pyspec/{stem}.py"
        parts = []
        if spec.implemented_functions():
            try:
                parts.append(emit.generate(spec, spec_name,
                                           self.pyspec_c_basenames,
                                           self.pyspec_self_ctypes))
            except emit.SpecError as exc:
                raise frontend.SpecError(exc.message, filename=spec.filename,
                                         lineno=exc.lineno) from None
        types = self.type_objects(spec)
        if types is not None:
            if not parts:
                parts.append(typeobj.header(spec_name))
            parts.append(types)
        if not parts:
            return []
        output = frontend.output_path(self.filename)
        try:
            self.writer.makedirs(os.path.dirname(output))
        except FileExistsError:
            pass
        return [(output, "\n\n".join(parts) + "\n")]

    def type_objects(self, spec: frontend.Spec) -> str | None:
        """The static types of the spec (see pyspec/typeobj.py)."""
        clinic_classes = self._clinic_classes(self, '')
        classes = {path: (cls.typedef, cls.type_object)
                   for path, cls in clinic_classes}
        functions = {
            f'{path}.{f.name}': (
                f.c_basename,
                f.c_basename_vectorcall if f.vectorcall else None)
            for path, cls in clinic_classes for f in cls.functions}
        return typeobj.generate(spec, classes, functions)

    def _module_and_class(
        self, fields: Sequence[str]
    ) -> tuple[Module | Clinic, Class | None]:
        """
        fields should be an iterable of field names.
        returns a tuple of (module, class).
        the module object could actually be self (a clinic object).
        this function is only ever used to find the parent of where
        a new class/module should go.
        """
        parent: Clinic | Module | Class = self
        module: Clinic | Module = self
        cls: Class | None = None

        for idx, field in enumerate(fields):
            fullname = ".".join(fields[:idx + 1])
            if not isinstance(parent, Class):
                if fullname in parent.modules:
                    parent = module = parent.modules[fullname]
                    continue
            if field in parent.classes:
                parent = cls = parent.classes[field]
            else:
                fail(f"Parent class or module {fullname!r} does not exist.")

        return module, cls

    def __repr__(self) -> str:
        return "<clinic.Clinic object>"
