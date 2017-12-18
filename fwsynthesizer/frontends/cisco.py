import fwsynthesizer
from fwsynthesizer.parsers import parse_cisco

frontend = fwsynthesizer.Frontend(
    name="CISCO",
    diagram="diagrams/cisco.diagram",
    language_converter=fwsynthesizer.converter(
        parser=parse_cisco.parse_file,
        converter=lambda x,_: parse_cisco.convert_file(*x)
    ),
    interfaces_enabled=False
)
