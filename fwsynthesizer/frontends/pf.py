import fwsynthesizer
from fwsynthesizer.parsers import parse_pf

frontend = fwsynthesizer.Frontend(
    name="PF",
    diagram="diagrams/pf.diagram",
    language_converter=fwsynthesizer.converter(
        parser=parse_pf.conf_file.parse_strict,
        converter=parse_pf.convert_rules
    ),
    query_configuration=fwsynthesizer.query_configuration(
        get_lines=parse_pf.get_lines,
        delete_rule=parse_pf.delete_rule
    )
)
