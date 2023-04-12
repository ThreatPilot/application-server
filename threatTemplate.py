import string

class SuperFormatter(string.Formatter):
    def format_field(self, value, format_spec):
        if format_spec.startswith('repeat'):
            template = format_spec.partition(':')[-1]
            if type(value) is dict:
                value = value.items()
            return ''.join([template.format(item=item) for item in value])
        elif format_spec == 'call':
            return value()
        elif format_spec.startswith('if'):
            return (value and format_spec.partition(':')[-1]) or ''
        else:
            return super(SuperFormatter, self).format_field(value, format_spec)
