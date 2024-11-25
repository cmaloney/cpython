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
    assert "\\" in token

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
        self._corpus_len = len(self.corpus)
        self.at_end = False

        # Prime first rune.
        self.advance(0)

    def _tombstone(self):
        self.current = ""
        self.at_end = True
        self.position = self._corpus_len


    def advance(self, count=1):
        self.position += count
        if self.position >= self._corpus_len:
            self._tombstone()
        else:
            self.current = self.corpus[self.position]

    def advance_through(self, substr):
        """Find the next given string, if hit EOF consume everything.

        Returns true if substr was found."""
        pos = self.corpus.find(substr, self.position)
        if pos == -1 or pos >= self._corpus_len:
            self._tombstone()
            return False

        self.position = pos
        self.current = self.corpus[self.position]
        return True


class _token_iter:
    """Cache current token, next() to get next, "" as EOF."""
    def __init__(self, corpus) -> None:
        self.runes = _rune_iter(corpus)
        self.consumed = 0
        self.advance()

    def advance(self, skip_comments=True):
        """Consume the last token, find the next"""
        self.consumed = self.runes.position


        raise NotImplementedError()

    def materialize(self, start_offset=0):
        return self.runes.corpus[self.consumed+start_offset,self.runes.position]


class _netrcparse:
    def __init__(self, file, fp):
        # NOTE: Relies on universal newlines to count lineno post-parse as well
        # as normalize line endings across platforms.
        assert fp.newlines is None, "Doesn't allow arbitrary readline."
        self.file = file
        self.all_text = fp.read()
        self.bytes_consumed = 0
        self.next_token = None
        self.total_bytes = len(self.all_text)
        self.runes = _rune_iter(self.all_text)

    def _compute_lineno(self):
        return self.all_text[:self.bytes_consumed].count("\n")

    def _make_error(self, msg):
        return NetrcParseError(msg, self.file, self._compute_lineno())

    def _materialize_token(self, start_offset=0, end_offset=0):
        return self.all_text[self.bytes_consumed+start_offset:self.runes.position+end_offset]

    def _consume(self):
        self.bytes_consumed = self.runes.position
        self.next_token = None

    def _find_next_token(self, skip_comments: bool):
        """Move to the start of the next token, but don't consume."""

        while True:
            match self.runes.current:
                case "":  # EOF
                    return ""
                case '#' if skip_comments:  # Comments
                    self.runes.advance_through("\n")
                    self._consume()
                case c if c in _whitespace:  # Whitespace between tokens
                    # Eat until no longer whitespace
                    # FIXME/TODO: Can we do a faster find method?
                    while True:
                        match self.runes.current:
                            case '':  # EOF
                                self._consume()
                                break
                            case _ as rune if rune in _whitespace:
                                self.runes.advance()
                            case _:
                                # non-whitespace
                                self._consume()
                                break
                case '"':  # Tokens, either quoted or literals
                    # Skip start quote
                    self.runes.advance()
                    has_escape = False
                    while True:
                        match self.runes.current:
                            case '\\':
                                # Escape and skip next
                                # FIXME: Validate EOF behavior
                                self.runes.advance(2)
                                has_escape = True
                            case '"':
                                unquoted = self._materialize_token(1)
                                self.runes.advance()
                                return _process_escapes(unquoted) if has_escape else unquoted
                            case '':
                                # EOF
                                # FIXME(cmaloney): Needs a test case.
                                raise self._make_error("Quotation didn't end %r" % self._materialize_token(0))
                            case _ as c:
                                self.runes.advance()
                case _:
                    # Read until whitespace which doesn't have an escape.
                    # FIXME: Change to match statement
                    has_escape = False
                    while self.runes.current not in _whitespace:
                        # EOF
                        if self.runes.current == '':
                            break

                        # Skip all escaped characters
                        if self.runes.current == '\\':
                            # FIXME/TODO: This will error at EOF currently.
                            self.runes.advance(2)
                            has_escape = True
                            continue

                        self.runes.advance()

                    token = self._materialize_token()
                    return _process_escapes(token) if has_escape else token

    # FIXME: I hate skip_comments, it's sooo ugly...
    def _peek_token(self, skip_comments: bool):
        """Move to the start of the next token, but don't consume."""
        # Already have a peeked token
        if self.next_token is not None:
            return self.next_token

        self.next_token = self._find_next_token(skip_comments=skip_comments)
        assert self.next_token is not None, \
            "Should have gotten a token or exception."
        assert self.runes.at_end or self.runes.position != self.bytes_consumed, \
            "Should either have no data remaining, or be in a token"

        return self.next_token


    def _consume_token(self, skip_comments: bool = False):
        """Consume and return the next token."""
        token = self._peek_token(skip_comments=skip_comments)
        self._consume()
        return token

    def _parse_macro(self):
        """Macros: have a name, end with double newline."""
        # TODO(fixme): Name here can contain a `#`, needs tests
        name = self._consume_token()
        # TODO, FIXME: Assert that the next byte after name is a newline.
        while True:
            if not self.runes.advance_through('\n\n'):
                # End of file before next newline.
                raise self._make_error(
                    "Macro definition missing null line terminator.")
            self.runes.advance()  # First newline is part of macro
            body = self._materialize_token(1)
            self.runes.advance()  # Discard second newline
            self._consume()
            print(f"{body!r}")
            return (name, body.splitlines(keepends=True))

    def _parse_machine(self):
        login = account = password = ''
        while True:
            match self._peek_token(skip_comments=True):
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
                    return (login, account, password)
                case _ as unhandled:
                    raise self._make_error("bad follower token %r" % unhandled)

    def populate(self, netrc):
        while True:
            match self._consume_token(skip_comments=True):
                case "default":
                    self._consume()
                    netrc.hosts["default"] = self._parse_machine()
                case "machine":
                    machine = self._consume_token()
                    netrc.hosts[machine] = self._parse_machine()
                case "macdef":
                    name, value = self._parse_macro()
                    netrc.macros[name] = value
                case "":
                    break
                case _ as unhandled:
                    raise self._make_error("bad toplevel token %r" % unhandled)

        if not self.runes.at_end:
            raise self._make_error("netrc parser error, didn't reach end")



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
        parser.populate(self)

        if os.name == 'posix' and default_netrc:
            for machine in self.hosts.values():
                # All non-anonymous logins which have a password should trigger
                # check. Check only needs to happen once per file.
                if machine[0] != 'anonymous' and machine[2] != '':
                    self._security_check(fp)
                    break

    def _security_check(self, fp):
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
        # FIXME/TODO: Removed print
        netrc(sys.argv[1])
    else:
        print(netrc())
