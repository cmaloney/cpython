"""An object-oriented interface to .netrc files."""

# Module and documentation by Eric S. Raymond, 21 Dec 1998

import os
import resource
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
    """Single-pass escape removal to avoid copies."""
    unescaped = ""
    for char in token:
        if char == "\\":
            continue
        unescaped += char
    return unescaped


_whitespace = "\n\t\r "


class _rune_iter:
    """Cache current byte, advance() to get next. "" as EOF."""
    def __init__(self, corpus) -> None:
        self.corpus = corpus
        self.position = 0
        self._corpus_len = len(self.corpus)  # cached to reduce cost

        # Prime first rune.
        self.advance(0)

    def at_end(self):
        return self.position == self._corpus_len

    def _tombstone(self):
        self.current = ""
        self.position = self._corpus_len

    def advance(self, /, count=1):
        self.position += count
        if self.position >= self._corpus_len:
            self._tombstone()
        else:
            self.current = self.corpus[self.position]

    def advance_through(self, substr):
        """Find the next given string, if hit EOF consume everything.

        Returns true if substr was found."""
        found = self.corpus.find(substr, self.position)
        if found == -1:
            self._tombstone()
            return False

        self.position = found
        self.current = self.corpus[self.position]
        return True


class _token_iter:
    """Cache current token, next() to get next, "" as EOF."""
    def __init__(self, file, corpus) -> None:
        self.file = file
        self.runes = _rune_iter(corpus)

        self.consumed = 0
        self.current = ""
        self._find_next_token(allow_comments=True)

    def _compute_lineno(self):
        return self.runes.corpus[:self.consumed].count("\n")

    def _materialize(self, offset=0, *, has_escape=False):
        self.current = \
            self.runes.corpus[self.consumed+offset:self.runes.position]

        if has_escape:
            self.current = _process_escapes(self.current)

        return self.current

    def _find_next_token(self, *, allow_comments: bool):
        """Move to the start of the next token, but don't consume."""
        while self.runes.current:
            self.consumed = self.runes.position

            match self.runes.current:
                case '#' if allow_comments:  # Comment, advance and no token.
                    self.runes.advance_through("\n")
                case '"':  # Quoted token
                    self.runes.advance()  # Skip start quote
                    has_escape = False
                    while self.runes.current:
                        match self.runes.current:
                            case '\\':  # Skip escape and escaped rune.
                                self.runes.advance(2)
                                has_escape = True
                            case '"':  # End quote
                                # Don't include start quote in token.
                                self._materialize(1, has_escape=has_escape)
                                self.runes.advance()  # move past end quote
                                return
                            case _:
                                self.runes.advance()
                    # EOF before end quote.
                    # FIXME(cmaloney): Needs a test case.
                    raise self.make_error(
                        "Quoted string missing end quote %r" % \
                            self._materialize())
                case c if c in _whitespace:  # Whitespace, advance and no token.
                    while self.runes.current in _whitespace \
                            and self.runes.current:  # EOF "" is in _whitespace
                        self.runes.advance()
                case _:  # Unquoted token, read until unescaped whitespace.
                    has_escape = False
                    while self.runes.current not in _whitespace:
                        match self.runes.current:
                            case '\\':
                                self.runes.advance(2)
                                has_escape = True
                            case _:
                                self.runes.advance()

                    self._materialize(has_escape=has_escape)
                    return
        # EOF
        self.current = ""

    def advance_default(self):
        """Handle the special-case 'default' which has no value after."""
        self._find_next_token(allow_comments=True)

    def advance_macro(self):
        """Macros aren't standard tokens.

        Macros are everything until the next "\n\n"
        """
        self.consumed = self.runes.position
        if not self.runes.advance_through('\n\n'):
            # End of file before next newline.
            raise self.make_error(
                "Macro definition missing null line terminator.")
        self.runes.advance()  # First "\n" of end "\n\n" is part of macro
        body = self._materialize(1)
        self.runes.advance()  # Discard second "\n"
        self._find_next_token(allow_comments=True)
        return body

    def advance_value(self):
        """Just read a key (login, password, etc.) and now reading its value.

        Value is a required token which can start with any character. Even if
        it looks like a comment, it is not a comment.
        """
        # Consume the keyword, next token is the value. The value may be an
        # unquoted literal that starts with '#' so don't allow comments.
        self._find_next_token(allow_comments=False)
        value = self.current
        self._find_next_token(allow_comments=True)
        return value

    def make_error(self, msg):
        raise NetrcParseError(msg, self.file, self._compute_lineno())

class _netrcparser:
    def __init__(self, filename, contents):
        self.tokens = _token_iter(filename, contents)

    def _parse_macro(self):
        """Macros: have a name, end with double newline.

        They are "lexed" as one block until the newline which is different than
        how the tokenizer normally works."""
        # TODO(fixme): Name here can contain a `#`, needs tests
        self.tokens._find_next_token(allow_comments=False)
        name = self.tokens.current
        body = self.tokens.advance_macro()
        return (name, body.splitlines(keepends=True))

    def _parse_machine(self):
        login = account = password = ''
        while True:
            match self.tokens.current:
                case 'login' | 'user':
                    login = self.tokens.advance_value()
                case 'account':
                    account = self.tokens.advance_value()
                case 'password':
                    password = self.tokens.advance_value()
                case '' | 'machine' | 'default' | 'macdef':
                    return (login, account, password)
                case _ as unhandled:
                    raise self.tokens.make_error("bad follower token %r" % unhandled)

    def populate(self, netrc):
        while top_entry := self.tokens.current:
            match top_entry:
                case "default":
                    self.tokens.advance_default()
                    netrc.hosts["default"] = self._parse_machine()
                case "machine":
                    machine = self.tokens.advance_value()
                    netrc.hosts[machine] = self._parse_machine()
                case "macdef":
                    name, value = self._parse_macro()
                    netrc.macros[name] = value
                case "":
                    break
                case _ as unhandled:
                    raise self.tokens.make_error("bad toplevel token %r" % unhandled)

        if not self.tokens.runes.at_end():
            raise self.tokens.make_error("netrc parser error, didn't reach end")

def _security_check(fp):
    """Validate netrc file is only readable by current user."""
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


def _populate_netrc(netrc, filename, fp, default_netrc):
    # NOTE: Relies on universal newlines to count lineno and normalize line
    # endings across platforms.
    if fp.newlines not in (None, '\n'):
        raise parser.tokens.make_error("doesn't support alternate file newlines.")

    parser = _netrcparser(filename, fp.read())
    parser.populate(netrc)

    if os.name == 'posix' and default_netrc:
        for machine in netrc.hosts.values():
            # All non-anonymous logins which have a password should trigger
            # check. Check only needs to happen once per file.
            if machine[0] != 'anonymous' and machine[2] != '':
                _security_check(fp)
                break  # Just checks file permissions, only need to run once.

class netrc:
    def __init__(self, file=None):
        default_netrc = file is None
        if file is None:
            file = os.path.join(os.path.expanduser("~"), ".netrc")
        self.hosts = {}
        self.macros = {}
        try:
            with open(file, encoding="utf-8") as fp:
                _populate_netrc(self, file, fp, default_netrc)
        except UnicodeDecodeError:
            with open(file, encoding="locale") as fp:
                _populate_netrc(self, file, fp, default_netrc)

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
        # FIXME/TODO: Removed print (it's half the runtime...)
        netrc(sys.argv[1])
        # DEBUG:
        # print(f"{resource.getrusage(resource.RUSAGE_SELF).ru_maxrss =}")
    else:
        print(netrc())
