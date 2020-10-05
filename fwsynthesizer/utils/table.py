#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

################################################################################
## GLOBALS

borders = {
    'unicode': ["─", "│", "╭", "╮", "╰", "╯", "├", "┤", "┬", "┴", "┼"],
    'ascii': ["-", "|", "+", "+", "+", "+", "+", "+", "+", "+", "+"]
}

dividers = {
    'unicode': ["╞", "═", "╪", "╡"],
    'ascii': ["+", "=", "+", "+"]
}

CENTER = lambda s, n: s.center(n)
LEFT = lambda s, n: s.ljust(n)
RIGHT = lambda s, n: s.rjust(n)

################################################################################
## TABLES

class Table(object):

    def __init__(self, fields, padding=1, style='unicode', align=LEFT):
        self.padding = padding
        self.style = style
        self.align = align

        if type(fields[0]) == tuple:
            self.fields = fields
        else:
            self.fields = [ (x,x) for x in fields ]

        self.row_groups = []
        self.projection = []

    @property
    def header(self):
        return [x[1] for x in self.fields]

    def project(self, field_list):
        self.projection = []
        field_names = [x[0] for x in self.fields]
        for field in field_list:
            self.projection.append(field_names.index(field))

    def apply_projection(self, row):
        if self.projection:
            return [ row[i] for i in self.projection ]
        return row

    def append_row(self, row):
        group = RowGroup([row])
        if self._columns() != group.columns():
            raise RuntimeError('Invalid number of columns')
        self.row_groups.append(group)

    def append_row_group(self, row_group):
        group = RowGroup(row_group)
        if self._columns() != group.columns():
            raise RuntimeError('Invalid number of columns')
        self.row_groups.append(group)

    def _columns(self):
        return len(self.fields)

    def columns(self):
        if self.projection:
            return len(self.projection)
        return self._columns()

    def column_widths(self):
        column_widths = [len(elm) for elm in self.header]
        for rg in self.row_groups:
            widths = rg.column_widths()
            for i,width in enumerate(widths):
                column_widths[i] = max(width, column_widths[i])
        if self.projection:
            return self.apply_projection(column_widths)
        return column_widths

    def width(self):
        cn = self.columns()
        cw = self.column_widths()
        return (cn - 1)*(1 + 2*self.padding) + (2*(1 + self.padding)) + sum(cw)

    def render(self):
        if self.style == 'latex':
            return self._render_latex()
        elif self.style == 'html':
            return self._render_html()
        elif self.style == 'json':
            return self._render_json()
        return self._render_ascii()

    def _render_latex(self):
        align = {LEFT: 'l', CENTER: 'c', RIGHT: 'r'}.get(self.align, 'l')

        out = ''
        out += '\\begin{tabular}{ |' + ''.join('{}|'.format(align)*self.columns()) + '}'
        out += '\\hline'
        out += ' & '.join('\\textbf{{{}}}'.format(title)
                          for title in self.apply_projection(self.header)) + '\\\\'
        out += '\\hline'
        for rg in self.row_groups:
            out += '\\\\'.join(' & '.join('\\verb|{}|'.format(s) for s in self.apply_projection(row))
                               for row in rg.rows())
            out += '\\\\ \\hline'
        out += '\\end{tabular}'
        return out

    def _render_html(self):
        out = ''
        out += '<table class="fws-table">'
        out += '<thead><tr>'+ ''.join('<td><b>{}</b></td>'.format(title) for title in self.apply_projection(self.header)) +'</tr></thead>'
        for i, rg in enumerate(self.row_groups):
            out += '<tbody class="fws-row-group rg-{}">'.format(i)
            for row in rg.rows():
                out += '<tr>' + ''.join('<td>{}</td>'.format(s) for s in self.apply_projection(row)) + '</tr>'
            out += '</tbody>'
        out += '</table>'
        return out

    def _render_json(self):
        fields,field_names = zip(*self.apply_projection(self.fields))
        table = []
        for i, rg in enumerate(self.row_groups):
            # Every row group is a single object
            outrow = {f: "" for f in fields}
            for row in rg.rows():
                for f,s in zip(fields, self.apply_projection(row)):
                    outrow[f] += '{}\n'.format(s)
                for f in fields:
                    outrow[f] = outrow[f].strip()
            table.append(outrow)

        out = {'fields': fields, 'field_names': field_names, 'table': table}
        return json.dumps(out)

    def _render_ascii(self):
        out = ''
        column_number = self.columns()
        widths = self.column_widths()

        ch = borders[self.style]
        dch = dividers[self.style]

        _line = lambda b, e, c, columns: (b + c.join(columns) + e + '\n')
        _sep = [ch[0]*w for w in widths]
        _hsep = [dch[1]*w for w in widths]
        _dpad = ch[0]*self.padding
        _hpad = dch[1]*self.padding
        _lpad = ' '*self.padding

        top = _line(ch[2] + _dpad, _dpad + ch[3], _dpad + ch[-3] + _dpad, _sep)
        bottom = _line(ch[4] + _dpad, _dpad + ch[5], _dpad + ch[-2] + _dpad, _sep)
        divider = _line(ch[-5] + _dpad, _dpad + ch[-4], _dpad + ch[-1] + _dpad, _sep)
        hdivider = _line(dch[0] + _hpad, _hpad + dch[3], _hpad + dch[2] + _hpad, _hsep)
        line = lambda cols: _line(ch[1] + _lpad , _lpad + ch[1], _lpad + ch[1] + _lpad,
                                  [self.align(c, widths[i]) for i,c in enumerate(cols) ])

        out += top
        out += line(self.apply_projection(self.header))
        out += hdivider
        for i, rg in enumerate(self.row_groups):
            for row in rg.rows():
                out += line(self.apply_projection(row))
            if i < len(self.row_groups) - 1:
                out += divider
        out += bottom

        return out

class RowGroup(object):
    def __init__(self, rows):
        self._rows = rows

    def columns(self):
        return len(self._rows[0])

    def column_widths(self):
        column_widths = self.columns() * [0]
        for row in self._rows:
            for i, elm in enumerate(row):
                column_widths[i] = max(column_widths[i], len(elm))
        return column_widths

    def rows(self):
        return self._rows

################################################################################
## TESTS

if __name__ == '__main__':
    header = ['A', 'BB', 'CCC']
    table = Table(header, align=LEFT, style='unicode')

    table.append_row_group([
        ['ciao', 'ciao1', 'ciao2'],
        ['ciao', 'ciao1', 'ciao2']
    ])

    table.append_row_group([
        ['ciao', 'ciao1', 'ciao2'],
        ['ciao', 'ciao1', 'ciao2']
    ])

    print()
    print(table.render())

    table.project(['A', 'CCC'])
    print(table.render())
    table.project([])

    table.style = 'ascii'
    print(table.render())
    table.style = 'latex'
    print(table.render())
