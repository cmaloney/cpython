"""An object-oriented interface to .netrc files."""

# Module and documentation by Eric S. Raymond, 21 Dec 1998

import os
import stat
import sys

__all__ = ["netrc", "NetrcParseError"]


class NetrcParseError(Exception):
    """Exception raised on syntax errors in the .netrc file."""
    def __init__(self, msg, filename=None, lineno=None):
        self.filename = filename
        self.lineno = lineno
        self.msg = msg
        Exception.__init__(self, msg)

    def __str__(self):
        return "%s (%s, line %s)" % (self.msg, self.filename, self.lineno)


def _process_escapes(token):
    """Single-pass escape removal to avoid copies.

    Most netrc keywords don't contain escapes. (ex. machine, user, login, ...)
    """
    if "\\" not in token:
        return token

    unescaped = ""
    for char in token:
        if char == "\\":
            continue
        unescaped += char
    return unescaped


class _netrcparse:
    def __init__(self, file, fp):
        # NOTE: Relies on universal newlines to count lineno post-parse as well
        # as normalize line endings across platforms.
        self.instream = fp
        assert fp.newlines is None, "Doesn't allow arbitrary readline."
        self.file = file
        self.whitespace = "\n\t\r "
        self.all_text = self.instream.read()
        self.remaining = self.all_text
        self.next_token_end = 0
        self.next_token = None
        self.bytes_consumed = 0

    def get_lineno(self):
        return self.all_text[:self.bytes_consumed].count("\n")

    def _make_error(self, msg):
        return NetrcParseError(msg, self.file, self.get_lineno())

    def _consume(self):
        self.bytes_consumed += self.next_token_end
        self.remaining = self.remaining[self.next_token_end:]
        # assert self.bytes_consumed + len(self.remaining) == len(self.all_text), \
        #    "Shouldn't be loosing data ever."
        self.next_token_end = 0
        self.next_token = None


    def _lex_quotes(self):
        """Read until quote that is not preceeded by an escape."""
        self.next_token_end += 1
        while True:
            next_newline = self.remaining[self.next_token_end:].find('"')
            match next_newline:
                case -1:
                    # TODO/FIXME: This wasn't handled in old code...
                    raise self._make_error("TODO: Unexpected quote end %r" % self.remaining)
                case _ as offset:
                    # If the newline was escaped, ignore it
                    if self.remaining[self.next_token_end+offset-1] == '\\':
                        continue
                    # Found end of string, return the string contents.
                    unquoted = self.remaining[1:self.next_token_end-1]
                    return _process_escapes(unquoted)

    def _find_next_token(self):
        """Move to the start of the next token, but don't consume."""

        while True:
            assert self.next_token_end == 0, \
                "Shouldn't be in a token / last token should be consumed."

            # End of file/buffer
            if not self.remaining:
                return ""

            match self.remaining[0]:
                # Comments
                case '#':
                    match self.remaining.find("\n"):
                        case -1:
                            # Comment into EOF, no further tokens.
                            self.next_token_end += len(self.remaining)
                        case _ as next_newline:
                            self.next_token_end += next_newline
                    self._consume()

                # Whitespace
                case c if c in self.whitespace:
                    # Find first non-whitespace.
                    # FIXME/TODO: Can we do a faster find method?
                    while self.next_token_end < len(self.remaining) \
                        and self.remaining[self.next_token_end] in c:
                        self.next_token_end += 1
                    self._consume()

                # Tokens, either quoted or literals
                case '"':
                    return self._lex_quotes()
                case _:
                    # Read until whitespace which doesn't have an escape.
                    self.next_token_end += 1
                    while self.remaining[self.next_token_end] not in self.whitespace:
                        # Skip all escaped characters
                        if self.remaining[self.next_token_end] == '\\':
                            # FIXME/TODO: This will error at EOF currently.
                            self.next_token_end += 1

                        self.next_token_end += 1

                    return _process_escapes(self.remaining[:self.next_token_end])


    def _peek_token(self):
        """Move to the start of the next token, but don't consume."""
        # Already have a peeked token
        if self.next_token is not None:
            return self.next_token

        self.next_token = self._find_next_token()
        assert self.next_token is not None, \
            "Should have gotten a token or exception."
        assert not self.remaining or self.next_token_end != 0, \
            "Should either have no data remaining, or "

        # DEBUG: print(f"TOKEN {self.next_token}, {self.remaining[:20] = }")
        return self.next_token


    def _consume_token(self):
        """Consume and return the next token."""
        token = self._peek_token()
        self._consume()
        return token

    def _parse_macro(self):
        """Macros: have a name, end with double newline."""
        macro_name = self._consume_token()
        # TODO, FIXME: Assert that the next byte after macro_name is a newline
        #              and consume it.
        while True:
            # Start of this loop, last byte was always a newline.
            next_newline = self.remaining[self.next_token_end:].find('\n')
            match next_newline:
                case -1:
                    # End of file before next newline.
                    raise self._make_error(
                        "Macro definition missing null line terminator.")
                case 0:
                    # Two newlines in a row indicates end of macro.
                    self.next_token_end += 1
                    return (macro_name, self._consume_token())
                case _ as next_newline:
                    # Text in the macro
                    self.next_token_end += next_newline

    def _parse_machine(self, default):
        # Default doesn't get any machine name, so just use default as the
        # machine name.
        if default:
            machine = "default"
        else:
            machine = self._consume_token()

        login = account = password = ''

        while True:
            # DEBUG: print(f"_parse_machine state {machine, (login, account, password)}")
            match self._peek_token():
                case 'login' | 'user':
                    self._consume()
                    login = self._consume_token()
                case 'account':
                    self._consume()
                    account = self._consume_token()
                case 'password':
                    self._consume()
                    password = self._consume_token()
                case '' | 'machine' | 'default' | 'macdef':
                    return machine, (login, account, password)
                case _ as unhandled:
                    raise self._make_error("bad follower token %r" % unhandled)

    def entries(self):
        while True:
            match self._consume_token():
                case "default":
                    self._consume()
                    yield "machine", self._parse_machine(True)
                case "machine":
                    self._consume()
                    yield "machine", self._parse_machine(False)
                case "macdef":
                    self._consume()
                    yield "macdef", self._parse_macro()
                case "":
                    return
                case _ as unhandled:
                    raise self._make_error("bad toplevel token %r" % unhandled)


class netrc:
    def __init__(self, file=None):
        default_netrc = file is None
        if file is None:
            file = os.path.join(os.path.expanduser("~"), ".netrc")
        self.hosts = {}
        self.macros = {}
        try:
            with open(file, encoding="utf-8") as fp:
                self._parse(file, fp, default_netrc)
        except UnicodeDecodeError:
            with open(file, encoding="locale") as fp:
                self._parse(file, fp, default_netrc)

    def _parse(self, file, fp, default_netrc):
        parser = _netrcparse(file, fp)
        for kind, entry in parser.entries():
            match kind:
                case "machine":
                    self.hosts[entry[0]] = entry[1]
                case "macdef":
                    self.macros[entry[0]] = entry[1]
                case _ as unhandled:
                    raise NetrcParseError(
                        "bad parser return %r" % unhandled, file, self.lineno)

        # FIXME/TODO: Assert hit end of file.

        # FIXME/TODO: Should this be a set of usernames? Shuld it be
        # called/checked for every machine entry?
        one_entry = next(iter(self.hosts.keys()))
        self._security_check(fp, default_netrc, self.hosts[one_entry][0])

    def _security_check(self, fp, default_netrc, login):
        if os.name == 'posix' and default_netrc and login != "anonymous":
            prop = os.fstat(fp.fileno())
            if prop.st_uid != os.getuid():
                import pwd
                try:
                    fowner = pwd.getpwuid(prop.st_uid)[0]
                except KeyError:
                    fowner = 'uid %s' % prop.st_uid
                try:
                    user = pwd.getpwuid(os.getuid())[0]
                except KeyError:
                    user = 'uid %s' % os.getuid()
                raise NetrcParseError(
                    (f"~/.netrc file owner ({fowner}, {user}) does not match"
                     " current user"))
            if (prop.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
                raise NetrcParseError(
                    "~/.netrc access too permissive: access"
                    " permissions must restrict access to only"
                    " the owner")

    def authenticators(self, host):
        """Return a (user, account, password) tuple for given host."""
        if host in self.hosts:
            return self.hosts[host]
        elif 'default' in self.hosts:
            return self.hosts['default']
        else:
            return None

    def __repr__(self):
        """Dump the class data in the format of a .netrc file."""
        rep = ""
        for host in self.hosts.keys():
            attrs = self.hosts[host]
            rep += f"machine {host}\n\tlogin {attrs[0]}\n"
            if attrs[1]:
                rep += f"\taccount {attrs[1]}\n"
            rep += f"\tpassword {attrs[2]}\n"
        for macro in self.macros.keys():
            rep += f"macdef {macro}\n"
            for line in self.macros[macro]:
                rep += line
            rep += "\n"
        return rep

if __name__ == '__main__':
    if len(sys.argv) == 2:
        print(netrc(sys.argv[1]))
    else:
        print(netrc())
