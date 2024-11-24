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
        self.bytes_consumed = self.next_token_end = 0
        self.next_token = None
        self.total_byes = len(self.all_text)

    def _compute_lineno(self):
        return self.all_text[:self.bytes_consumed].count("\n")

    def _make_error(self, msg):
        return NetrcParseError(msg, self.file, self._compute_lineno())

    def _at_end(self):
        return self.next_token_end >= self.total_byes

    def _next_byte(self):
        # ow, this apparently hurts a lot...
        return self.all_text[self.next_token_end]

    def _next_find(self, substr, offset=0):
        new_method = self.all_text.find(substr, self.next_token_end)
        if new_method != -1:
            new_method = new_method - self.bytes_consumed
        return new_method

    def _materilize_token(self, start_offset, end_offset):
        return self.all_text[self.bytes_consumed+start_offset:self.next_token_end+end_offset]

    def _consume(self):
        self.bytes_consumed = self.next_token_end
        self.next_token = None

    def _lex_quotes(self):
        """Read until quote that is not preceeded by an escape."""
        # Eat first quote
        self.next_token_end += 1
        has_escape = False
        while True:
            match self._next_byte():
                case '\\':
                    # Escape and skip next
                    # FIXME: Validate EOF behavior
                    self.next_token_end += 2
                    has_escape = True
                case '"':
                    unquoted = self._materilize_token(1, 0)
                    self.next_token_end += 1
                    return _process_escapes(unquoted) if has_escape else unquoted
                case _:
                    self.next_token_end += 1

            if self._at_end():
                raise self._make_error("Quotation didn't end %r" % self._materilize_token(0, 0))

    def _find_next_token(self, comment_as_token: bool):
        """Move to the start of the next token, but don't consume."""

        while True:
            assert self.next_token_end == self.bytes_consumed, \
                "Shouldn't be in a token / last token should be consumed."

            # End of file/buffer
            if self._at_end():
                return ""

            match self._next_byte():
                # Comments
                case '#' if comment_as_token is False:
                    match self._next_find("\n"):
                        case -1:
                            # Comment into EOF, no further tokens.
                            self.next_token_end = self.total_byes
                        case _ as next_newline:
                            self.next_token_end += next_newline
                    self._consume()

                # Whitespace
                case c if c in self.whitespace:
                    # Find first non-whitespace.
                    # FIXME/TODO: Can we do a faster find method?
                    while not self._at_end() \
                        and self._next_byte() in self.whitespace:
                        self.next_token_end += 1
                    self._consume()

                # Tokens, either quoted or literals
                case '"':
                    return self._lex_quotes()
                case _:
                    # Read until whitespace which doesn't have an escape.
                    self.next_token_end += 1
                    has_escape = False
                    while not self._at_end() \
                        and self._next_byte() not in self.whitespace:
                        # Skip all escaped characters
                        if self._next_byte() == '\\':
                            # FIXME/TODO: This will error at EOF currently.
                            self.next_token_end += 1
                            has_escape = True

                        self.next_token_end += 1

                    token = self._materilize_token(0, 0)
                    return _process_escapes(token) if has_escape else token

    # FIXME: I hate comment_as_token, it's sooo ugly...
    def _peek_token(self, comment_as_token: bool):
        """Move to the start of the next token, but don't consume."""
        # Already have a peeked token
        if self.next_token is not None:
            return self.next_token

        self.next_token = self._find_next_token(comment_as_token=comment_as_token)
        assert self.next_token is not None, \
            "Should have gotten a token or exception."
        assert self._at_end() or self.next_token_end != self.bytes_consumed, \
            "Should either have no data remaining, or be in a token"

        return self.next_token


    def _consume_token(self, comment_as_token: bool = False):
        """Consume and return the next token."""
        token = self._peek_token(comment_as_token=comment_as_token)
        self._consume()
        return token

    def _parse_macro(self):
        """Macros: have a name, end with double newline."""
        name = self._consume_token()
        # TODO, FIXME: Assert that the next byte after name is a newline
        #              and consume it.
        self.next_token_end += 1
        # Started with the double newline...
        while True:
            # Start of this loop, last byte was always a newline.
            next_newline = self._next_find('\n\n')
            match next_newline:
                case -1:
                    # End of file before next newline.
                    raise self._make_error(
                        "Macro definition missing null line terminator.")
                case _ as next_newline:
                    # Text in the macro
                    self.next_token_end += next_newline
                    body = self._materilize_token(1,0)
                    self._consume()
                    return (name, body.splitlines(keepends=True))

    def _parse_machine(self):
        login = account = password = ''
        while True:
            match self._peek_token(comment_as_token=False):
                case 'login' | 'user':
                    self._consume()
                    login = self._consume_token(comment_as_token=True)
                case 'account':
                    self._consume()
                    account = self._consume_token(comment_as_token=True)
                case 'password':
                    self._consume()
                    password = self._consume_token(comment_as_token=True)
                case '' | 'machine' | 'default' | 'macdef':
                    return (login, account, password)
                case _ as unhandled:
                    raise self._make_error("bad follower token %r" % unhandled)


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
        while True:
            match parser._consume_token():
                case "default":
                    parser._consume()
                    machine = "default"
                    self.hosts[machine] = parser._parse_machine()
                case "machine":
                    machine = parser._consume_token(comment_as_token=True)
                    self.hosts[machine] = parser._parse_machine()
                case "macdef":
                    name, value = parser._parse_macro()
                    self.macros[name] = value
                case "":
                    break
                case _ as unhandled:
                    raise parser._make_error("bad toplevel token %r" % unhandled)

        # FIXME/TODO: Assert hit end of file.

        # FIXME/TODO: Should this be a set of usernames? Shuld it be
        # called/checked for every machine entry?
        # FIXME/TODO: Only check for every distinct login once....
        # FIXME/TODO: Only stat once...
        # FIXME: THIS NEEDS TO BE CALLED for every user where `password` is set.
        for machine in self.hosts.values():
            self._security_check(fp, default_netrc, machine[0])

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
        # FIXME/TODO: Removed print
        netrc(sys.argv[1])
    else:
        print(netrc())
