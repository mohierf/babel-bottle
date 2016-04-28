#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This module is an extraction for Bottle simple template
"""
from collections import namedtuple
import re
from babel._compat import unichr

# name_re = re.compile(r'[\w$_][\w\d$_]*', re.UNICODE)
# dotted_name_re = re.compile(r'[\w$_][\w\d$_.]*[\w\d$_.]', re.UNICODE)
# division_re = re.compile(r'/=?')
# regex_re = re.compile(r'/(?:[^/\\]*(?:\\.[^/\\]*)*)/[a-zA-Z]*(?s)')
# line_re = re.compile(r'(\r\n|\n|\r)')
# line_join_re = re.compile(r'\\' + line_re.pattern)
# uni_escape_re = re.compile(r'[a-fA-F0-9]{1,4}')


# _rules = [
    # (None, re.compile(r'\s+(?u)')),
    # (None, re.compile(r'<!--.*')),
    # ('linecomment', re.compile(r'//.*')),
    # ('multilinecomment', re.compile(r'/\*.*?\*/(?us)')),
    # ('multilinecomment2', re.compile(r'<!--.*--!>')),
    # ('dotted_name', dotted_name_re),
    # ('name', name_re),
    # ('number', re.compile(r'''(?x)(
        # (?:0|[1-9]\d*)
        # (\.\d+)?
        # ([eE][-+]?\d+)? |
        # (0x[a-fA-F0-9]+)
    # )''')),
    # ('jsx_tag', re.compile(r'<(?:/?)\w+>', re.I)),  # May be mangled in `get_rules`
    ### ('jsx_tag', re.compile(r'<(?:/?)\w+.+?>', re.I)),  # May be mangled in `get_rules`
    # ('operator', re.compile(r'(%s)' % '|'.join(map(re.escape, operators)))),
    # ('template_string', re.compile(r'''`(?:[^`\\]*(?:\\.[^`\\]*)*)`''', re.UNICODE)),
    # ('string', re.compile(r'''(?xs)(
        # '(?:[^'\\]*(?:\\.[^'\\]*)*)'  |
        # "(?:[^"\\]*(?:\\.[^"\\]*)*)"
    # )'''))
# ]
"""
    Duplicated from:
    babel.messages.jslexer
    ~~~~~~~~~~~~~~~~~~~~~~

    :copyright: (c) 2013 by the Babel Team.
    :license: BSD, see LICENSE for more details.

    And then adapted for Bottle templates ...
"""

from operator import itemgetter
import re
from babel._compat import unichr

operators = [
    '+', '-', '*', '%', '!=', '==', '<', '>', '<=', '>=', '=',
    '+=', '-=', '*=', '%=', '<<', '>>', '>>>', '<<=', '>>=',
    '>>>=', '&', '&=', '|', '|=', '&&', '||', '^', '^=', '(', ')',
    '[', ']', '{', '}', '!', '--', '++', '~', ',', ';', '.', ':'
]
operators.sort(key=lambda a: -len(a))

escapes = {'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}

rules = [
    (None, re.compile(r'\s+(?u)')),
    # (None, re.compile(r'<!--.*')),
    ('linecomment', re.compile(r'//.*')),
    ('multilinecomment', re.compile(r'/\*.*?\*/(?us)')),
    # Multi line HTML comment
    ('html_comment', re.compile(r'<!--.*[^->]-->')),
    ('html_multilinecomment', re.compile(r'<!--.*?-->', re.DOTALL)),
    # HTML tag
    ('html_doc', re.compile(r'<!DOCTYPE html>')),
    ('html_tag', re.compile(r'<\w+>(?i)')),
    ('html_tag_open', re.compile(r'<\w+(?i)')),
    ('html_tag_close', re.compile(r'<(?:/?)\w+>(?i)')),
    ('name', re.compile(r'(\$+\w*|[^\W\d]\w*)(?u)')),
    ('fct_name', re.compile(r'(\$+\w*|[^\W\d]\w*)(?u)')),
    ('number', re.compile(r'''(?x)(
        (?:0|[1-9]\d*)
        (\.\d+)?
        ([eE][-+]?\d+)? |
        (0x[a-fA-F0-9]+)
    )''')),
    ('operator', re.compile(r'(%s)' % '|'.join(map(re.escape, operators)))),
    ('string', re.compile(r'''(?xs)(
        '(?:[^'\\]*(?:\\.[^'\\]*)*)'  |
        "(?:[^"\\]*(?:\\.[^"\\]*)*)"
    )'''))
]

division_re = re.compile(r'/=?')
regex_re = re.compile(r'/(?:[^/\\]*(?:\\.[^/\\]*)*)/[a-zA-Z]*(?s)')
line_re = re.compile(r'(\r\n|\n|\r)')
line_join_re = re.compile(r'\\' + line_re.pattern)
uni_escape_re = re.compile(r'[a-fA-F0-9]{1,4}')


class Token(tuple):
    """Represents a token as returned by `tokenize`."""
    __slots__ = ()

    def __new__(cls, type, value, lineno):
        return tuple.__new__(cls, (type, value, lineno))

    type = property(itemgetter(0))
    value = property(itemgetter(1))
    lineno = property(itemgetter(2))


def indicates_division(token):
    """A helper function that helps the tokenizer to decide if the current
    token may be followed by a division operator.
    """
    if token.type == 'operator':
        return token.value in (')', ']', '}', '++', '--')
    return token.type in ('name', 'number', 'string', 'regexp')


def unquote_string(string):
    """Unquote a string with JavaScript rules.  The string has to start with
    string delimiters (``'`` or ``"``.)
    """
    assert string and string[0] == string[-1] and string[0] in '"\'', \
        'string provided is not properly delimited'
    string = line_join_re.sub('\\1', string[1:-1])
    result = []
    add = result.append
    pos = 0

    while 1:
        # scan for the next escape
        escape_pos = string.find('\\', pos)
        if escape_pos < 0:
            break
        add(string[pos:escape_pos])

        # check which character is escaped
        next_char = string[escape_pos + 1]
        if next_char in escapes:
            add(escapes[next_char])

        # unicode escapes.  trie to consume up to four characters of
        # hexadecimal characters and try to interpret them as unicode
        # character point.  If there is no such character point, put
        # all the consumed characters into the string.
        elif next_char in 'uU':
            escaped = uni_escape_re.match(string, escape_pos + 2)
            if escaped is not None:
                escaped_value = escaped.group()
                if len(escaped_value) == 4:
                    try:
                        add(unichr(int(escaped_value, 16)))
                    except ValueError:
                        pass
                    else:
                        pos = escape_pos + 6
                        continue
                add(next_char + escaped_value)
                pos = escaped.end()
                continue
            else:
                add(next_char)

        # bogus escape.  Just remove the backslash.
        else:
            add(next_char)
        pos = escape_pos + 2

    if pos < len(string):
        add(string[pos:])

    return u''.join(result)


def tokenize(source):
    """Tokenize a JavaScript source.  Returns a generator of tokens.
    """
    may_divide = False
    pos = 0
    lineno = 1
    end = len(source)

    while pos < end:
        # handle regular rules first
        for token_type, rule in rules:
            match = rule.match(source, pos)
            if match is not None:
                break
        # if we don't have a match we don't give up yet, but check for
        # division operators or regular expression literals, based on
        # the status of `may_divide` which is determined by the last
        # processed non-whitespace token using `indicates_division`.
        else:
            if may_divide:
                match = division_re.match(source, pos)
                token_type = 'operator'
            else:
                match = regex_re.match(source, pos)
                token_type = 'regexp'
            if match is None:
                # woops. invalid syntax. jump one char ahead and try again.
                pos += 1
                continue

        token_value = match.group()
        if token_type is not None:
            token = Token(token_type, token_value, lineno)
            may_divide = indicates_division(token)
            yield token
        lineno += len(line_re.findall(token_value))
        pos = match.end()



def extract_tpl(fileobj, keywords, comment_tags, options):
    """Extract messages from JavaScript source code.
    :param fileobj: the seekable, file-like object the messages should be
                    extracted from
    :param keywords: a list of keywords (i.e. function names) that should be
                     recognized as translation functions
    :param comment_tags: a list of translator tags to search for and include
                         in the results
    :param options: a dictionary of additional options (optional)
    """
    # from babel.messages.jslexer import tokenize, unquote_string
    funcname = message_lineno = None
    messages = []
    last_argument = None
    translator_comments = []
    concatenate_next = False
    encoding = options.get('encoding', 'utf-8')
    last_token = None
    call_stack = -1

    for token in tokenize(fileobj.read().decode(encoding)):
        if token.type == 'string':
            regex = re.compile( "\('(.*)'\)" )
            found = regex.search(token.value)
            if found and found.group(1):
                print "Found:", found.group(1) if found else 'not found'
                yield (token.lineno, '_', found.group(1), [])

        if token.type == 'operator' and token.value == '(':
            if funcname:
                message_lineno = token.lineno
                call_stack += 1

        elif call_stack == -1 and token.type == 'linecomment':
            value = token.value[2:].strip()
            if translator_comments and \
               translator_comments[-1][0] == token.lineno - 1:
                translator_comments.append((token.lineno, value))
                continue

            for comment_tag in comment_tags:
                if value.startswith(comment_tag):
                    translator_comments.append((token.lineno, value.strip()))
                    break

        elif token.type == 'multilinecomment' or token.type == 'html_comment':
            # only one multi-line comment may preceed a translation
            translator_comments = []
            value = token.value[2:-2].strip()
            for comment_tag in comment_tags:
                if value.startswith(comment_tag):
                    lines = value.splitlines()
                    if lines:
                        lines[0] = lines[0].strip()
                        lines[1:] = dedent('\n'.join(lines[1:])).splitlines()
                        for offset, line in enumerate(lines):
                            translator_comments.append((token.lineno + offset,
                                                        line))
                    break

        elif funcname and call_stack == 0:
            if token.type == 'operator' and token.value == ')':
                if last_argument is not None:
                    messages.append(last_argument)
                if len(messages) > 1:
                    messages = tuple(messages)
                elif messages:
                    messages = messages[0]
                else:
                    messages = None

                # Comments don't apply unless they immediately precede the
                # message
                if translator_comments and \
                   translator_comments[-1][0] < message_lineno - 1:
                    translator_comments = []

                if messages is not None:
                    yield (message_lineno, funcname, messages,
                           [comment[1] for comment in translator_comments])

                funcname = message_lineno = last_argument = None
                concatenate_next = False
                translator_comments = []
                messages = []
                call_stack = -1

            elif token.type == 'string':
                print token
                new_value = unquote_string(token.value)
                if concatenate_next:
                    last_argument = (last_argument or '') + new_value
                    concatenate_next = False
                else:
                    last_argument = new_value

            elif token.type == 'operator':
                if token.value == ',':
                    if last_argument is not None:
                        messages.append(last_argument)
                        last_argument = None
                    else:
                        messages.append(None)
                    concatenate_next = False
                elif token.value == '+':
                    concatenate_next = True

        elif call_stack > 0 and token.type == 'operator' \
             and token.value == ')':
            call_stack -= 1

        elif funcname and call_stack == -1:
            funcname = None

        elif call_stack == -1 and token.type == 'name' and \
             token.value in keywords and \
             (last_token is None or last_token.type != 'name' or
              last_token.value != 'function'):
            funcname = token.value

        last_token = token