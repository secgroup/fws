import fwsynthesizer
from fwsynthesizer.parsers import parse_iptables

frontend = fwsynthesizer.Frontend(
    name = "IPTABLES",
    diagram = "diagrams/iptables.diagram",
    language_converter=fwsynthesizer.converter(
        parser=parse_iptables.iptables_save_file.parse_strict,
        converter=parse_iptables.tables_to_rules
    ),
    query_configuration=fwsynthesizer.query_configuration(
        get_lines=parse_iptables.get_lines,
        delete_rule=parse_iptables.delete_rule
    )
)
