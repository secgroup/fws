import fwsynthesizer
from fwsynthesizer.parsers import parse_ipfw

frontend = fwsynthesizer.Frontend(
    name="IPFW",
    diagram="diagrams/ipfw.diagram",
    language_converter=fwsynthesizer.converter(
        parser=parse_ipfw.ipfw_conf.parse_strict,
        converter=parse_ipfw.convert_rules
    ),
    query_configuration=fwsynthesizer.query_configuration(
        get_lines=parse_ipfw.get_lines,
        delete_rule=parse_ipfw.delete_rule
    )
)
